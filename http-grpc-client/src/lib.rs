#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use core::time::Duration;
use snafu::prelude::*;

// we CAN NOT just send the raw encoded protobuf(eg using GarbleIpfsRequest{}.encode())
// b/c that returns errors like
// "protocol error: received message with invalid compression flag: 8 (valid flags are 0 and 1), while sending request"
// "tonic-web: Invalid byte 45, offset 0"
// https://github.com/hyperium/tonic/blob/01e5be508051eebf19c233d48b57797a17331383/tonic-web/tests/integration/tests/grpc_web.rs#L93
// also: https://github.com/grpc/grpc-web/issues/152
// param: dyn prost::Message, eg interstellarpbapigarble::GarbleIpfsRequest etc
pub fn encode_body_grpc_web<T: prost::Message>(input: T) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::with_capacity(1024);
    buf.reserve(5);
    unsafe {
        buf.advance_mut(5);
    }

    input.encode(&mut buf).unwrap();

    let len = buf.len() - 5;
    {
        let mut buf = &mut buf[..5];
        buf.put_u8(0);
        buf.put_u32(len as u32);
    }

    buf.split_to(len + 5).freeze()
}

#[derive(PartialEq, Eq)]
pub enum ContentType {
    /// "application/grpc-web" or "application/grpc-web+proto"
    GrpcWeb,
    /// "application/grpc-web-text+proto"
    GrpcWebTextProto,
    /// "application/json"
    Json,
    MultipartFormData,
    TextPlain,
}

#[derive(PartialEq, Eq)]
pub enum RequestMethod {
    Post,
    Get,
    Put,
    Patch,
    Delete,
}

/// Decode either:
/// - a gRPC-web encoded body into a struct
/// - a json raw bytes into a struct
/// This is NOT integrated into "fetch_from_remote_grpc_web" b/c the response Struct is declared by the clients.
///
// pub fn decode_body<T: prost::Message + Default>(
//     body_bytes: bytes::Bytes,
//     grpc_content_type: ContentType,
// ) -> T {
//     let mut body = match grpc_content_type {
//         // only "application/grpc-web-text+proto" needs to be base64 decoded, the rest is handled as-is
//         ContentType::GrpcWebTextProto | ContentType::GrpcWeb => return decode_body_grpc_web(body_bytes, grpc_content_type),
//         ContentType::Json => return decode_body_json(body_bytes, grpc_content_type),
//         _ => panic!("decode_body: unsupported ContentType"),
//     };
// }

pub fn decode_body_grpc_web<T: prost::Message + Default>(
    body_bytes: bytes::Bytes,
    grpc_content_type: ContentType,
) -> T {
    assert!(
        grpc_content_type == ContentType::GrpcWebTextProto
            || grpc_content_type == ContentType::GrpcWeb,
        "decode_body_grpc_web MUST be grpc-web!"
    );

    let mut body = match grpc_content_type {
        // only "application/grpc-web-text+proto" needs to be base64 decoded, the rest is handled as-is
        ContentType::GrpcWebTextProto => base64::decode(body_bytes).unwrap().into(),
        _ => body_bytes,
    };

    body.advance(1);
    let len = body.get_u32();
    let reply = T::decode(&mut body.split_to(len as usize)).expect("decode");
    body.advance(5);

    // TODO? trailers?
    // let _trailers = body;
    // (reply, trailers)

    reply
}

/// Parse a node RPC response
/// It MUST be a JSON encoded hex string!
/// eg body_bytes = "Object({"id": String("1"), "jsonrpc": String("2.0"), "result": String("0xb8516d626945354373524d4a7565316b5455784d5a5162694e394a794e5075384842675a346138726a6d344353776602000000b8516d5a7870436964427066624c74675534796434574a314d7654436e5539316e7867394132446137735a7069636d0a000000")}"
pub fn decode_rpc_json<T: codec::Decode>(
    body_bytes: bytes::Bytes,
    grpc_content_type: ContentType,
) -> T {
    assert!(
        grpc_content_type == ContentType::Json,
        "decode_body_json MUST be json!"
    );

    // first: parse to untyped JSON
    // MUST match the schema: "id" + "jsonrpc" + etc; cf docstring
    let body_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("serde_json [1] failed");
    log::info!("[fetch_from_remote_grpc_web] body_json: {}", body_json,);

    // then we can deserialize the hex-encoded "result" field
    // NOTE: MUST remove the first 2 chars "0x" else:
    // "thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value: InvalidHexCharacter { c: 'x', index: 1 }'"
    let data_bytes = hex::decode(&body_json["result"].as_str().unwrap()[2..]).unwrap();
    let mut data_slice: &[u8] = &data_bytes;

    // finally can deserialize to the desired Struct
    T::decode(&mut data_slice).expect("decode failed")
}

#[derive(Debug, Snafu)]
pub enum InterstellarHttpClientError {
    HttpError { status_code: u16 },
    IoError,
    Timeout,
    UnknownResponseContentType { content_type: String },
}

/// This function uses the `offchain::http` API to query the remote endpoint information,
///   and returns the JSON response as vector of bytes.
///
/// return:
/// - the body, as raw bytes
/// - the Content-Type Header: needed to know how to deserialize(cf decode_body)
///
/// IMPORTANT: if in the future you need to use http_req(or http_req_sgx): CHECK GIT HISTORY
#[cfg(feature = "sp_offchain")]
pub fn sp_offchain_fetch_from_remote_grpc_web(
    body_bytes: Option<bytes::Bytes>,
    url: &str,
    request_method: RequestMethod,
    request_content_type: Option<ContentType>,
    timeout_duration: Duration,
) -> Result<(bytes::Bytes, ContentType), InterstellarHttpClientError> {
    log::info!(
        "fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
        url,
        if let Some(ref body_bytes) = body_bytes {
            base64::encode(body_bytes)
        } else {
            base64::encode(&[])
        }
    );

    // Initiate an external HTTP GET request.
    // This is using high-level wrappers from `sp_runtime`, for the low-level calls that
    // you can find in `sp_io`. The API is trying to be similar to `reqwest`, but
    // since we are running in a custom WASM execution environment we can't simply
    // import the library here.
    //
    // cf https://github.com/hyperium/tonic/blob/master/tonic-web/tests/integration/tests/grpc_web.rs
    // syntax = "proto3";
    // package test;
    // service Test {
    //		rpc SomeRpc(Input) returns (Output);
    // -> curl http://127.0.0.1:3000/test.Test/SomeRpc
    //
    // NOTE application/grpc-web == application/grpc-web+proto
    //      application/grpc-web-text = base64
    //
    // eg:
    // printf '\x00\x00\x00\x00\x05\x08\xe0\x01\x10\x60' | curl -skv -H "Content-Type: application/grpc-web+proto" -H "X-Grpc-Web: 1" -H "Accept: application/grpc-web-text+proto" -X POST --data-binary @- http://127.0.0.1:3000/interstellarpbapigarble.SkcdApi/GenerateSkcdDisplay
    let mut request = sp_runtime::offchain::http::Request::default();
    request = request.url(url);

    match request_method {
        RequestMethod::Post => {
            request = request.method(sp_runtime::offchain::http::Method::Post);
        }
        RequestMethod::Get => {
            request = request.method(sp_runtime::offchain::http::Method::Get);
        }
        RequestMethod::Put => {
            request = request.method(sp_runtime::offchain::http::Method::Put);
        }
        RequestMethod::Patch => {
            request = request.method(sp_runtime::offchain::http::Method::Patch);
        }
        RequestMethod::Delete => {
            request = request.method(sp_runtime::offchain::http::Method::Delete);
        }
    }

    match request_content_type {
        Some(ContentType::GrpcWeb) => {
            request = request.add_header("Content-Type", "application/grpc-web");
            request = request.add_header("X-Grpc-Web", "1");
        }
        Some(ContentType::Json) => {
            request = request.add_header("Content-Type", "application/json;charset=utf-8");
        }
        Some(ContentType::MultipartFormData) => {
            request =
                request.add_header("Content-Type", "multipart/form-data;boundary=\"boundary\"");
        }
        None | _ => {}
    }

    // NOTE: we CAN have a POST request without a body; eg IPFS CAT
    if let Some(body_bytes) = body_bytes {
        request = request.body(vec![body_bytes]);
    }

    // We set the deadline for sending of the request, note that awaiting response can
    // have a separate deadline. Next we send the request, before that it's also possible
    // to alter request headers or stream body content in case of non-GET requests.
    // NOTE: 'http_request_start can be called only in the offchain worker context'
    let pending = request
        // .deadline(timeout_duration)
        .send()
        .map_err(|_| InterstellarHttpClientError::IoError)?;

    // The request is already being processed by the host, we are free to do anything
    // else in the worker (we can send multiple concurrent requests too).
    // At some point however we probably want to check the response though,
    // so we can block current thread and wait for it to finish.
    // Note that since the request is being driven by the host, we don't have to wait
    // for the request to have it complete, we will just not read the response.
    let mut response = pending
        // .try_wait(timeout_duration)
        .try_wait(None)
        .map_err(|_| InterstellarHttpClientError::Timeout)?
        .map_err(|_| InterstellarHttpClientError::Timeout)?;

    let response_code = response.code;
    let response_content_type_str = response.headers().find("content-type").unwrap();
    log::info!(
        "[fetch_from_remote_grpc_web] status code: {}, content_type: {}",
        response_code,
        response_content_type_str
    );
    let response_content_type_type = match response_content_type_str {
        // yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
        "application/grpc-web" => ContentType::GrpcWeb,
        "application/grpc-web+proto" => ContentType::GrpcWeb,
        // BUT "application/grpc-web-text+proto" is base64 encoded
        "application/grpc-web-text+proto" => ContentType::GrpcWebTextProto,
        // classic JSON
        "application/json" => ContentType::Json,
        "application/json; charset=utf-8" => ContentType::Json,
        "text/plain" => ContentType::TextPlain,
        _ => {
            return Err(InterstellarHttpClientError::UnknownResponseContentType {
                content_type: response_content_type_str.to_owned(),
            })
        }
    };
    // DEBUG: list headers
    // let mut headers_it = response.headers().into_iter();
    // while headers_it.next() {
    //     let header = headers_it.current().unwrap();
    //     log::info!(
    //         "[fetch_from_remote_grpc_web] header: {} {}",
    //         header.0,
    //         header.1
    //     );
    // }

    // Let's check the status code before we proceed to reading the response.
    if response.code != 200 {
        log::warn!(
            "[fetch_from_remote_grpc_web] Unexpected status code: {}",
            response.code
        );
        return Err(InterstellarHttpClientError::HttpError {
            status_code: response.code,
        });
    }

    let response_bytes = response.body().collect::<bytes::Bytes>();
    Ok((response_bytes, response_content_type_type))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
