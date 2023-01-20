#![cfg_attr(not(feature = "std"), no_std)]
#![deny(elided_lifetimes_in_paths)]
#![warn(clippy::suspicious)]
#![warn(clippy::complexity)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::pedantic)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::unwrap_used)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, BufMut};
use core::time::Duration;
use snafu::prelude::*;

#[cfg(all(feature = "sgx", feature = "with_http_req_sgx"))]
use http_req_sgx as http_req;

// We CAN NOT just send the raw encoded protobuf(eg using GarbleIpfsRequest{}.encode())
/// b/c that returns errors like
/// "protocol error: received message with invalid compression flag: 8 (valid flags are 0 and 1), while sending request"
/// "tonic-web: Invalid byte 45, offset 0"
/// <https://github.com/hyperium/tonic/blob/01e5be508051eebf19c233d48b57797a17331383/tonic-web/tests/integration/tests/grpc_web.rs#L93/>
/// also: <https://github.com/grpc/grpc-web/issues/152/>
/// param: `dyn prost::Message`, eg `interstellarpbapigarble::GarbleIpfsRequest` etc
///
/// # Errors
/// - If the internal buffer is too small?
///
pub fn encode_body_grpc_web<T: prost::Message>(
    input: &T,
) -> Result<bytes::Bytes, InterstellarHttpClientError> {
    let mut buf = bytes::BytesMut::with_capacity(1024);
    buf.reserve(5);
    unsafe {
        buf.advance_mut(5);
    }

    input
        .encode(&mut buf)
        .map_err(|_| InterstellarHttpClientError::EncodeError)?;

    let len = buf.len() - 5;
    {
        let mut buf = &mut buf[..5];
        buf.put_u8(0);
        buf.put_u32(
            len.try_into()
                .map_err(|_| InterstellarHttpClientError::EncodeError)?,
        );
    }

    Ok(buf.split_to(len + 5).freeze())
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
    UnsupportedContentType {
        content_type: String,
    },
}

#[derive(PartialEq, Eq)]
pub enum RequestMethod {
    Post,
    Get,
    Put,
    Patch,
    Delete,
}
/// decode a `GrpcWeb` encoded response body
///
/// param: `grpc_content_type`: returned by `*fetch_from_remote_grpc_web`
///     SHOULD be `GrpcWeb` or `GrpcWebTextProto`
///
/// # Errors
///
/// - `ReponseDecodeWrongContentType` if `grpc_content_type` is not `GrpcWeb` or `GrpcWebTextProto`
/// - `ReponseDecodeError` if `prost::message::Message::decode` failed
pub fn decode_body_grpc_web<T: prost::Message + Default>(
    body_bytes: bytes::Bytes,
    grpc_content_type: &ContentType,
) -> Result<T, InterstellarHttpClientError> {
    // CHECK
    if grpc_content_type != &ContentType::GrpcWeb
        && grpc_content_type != &ContentType::GrpcWebTextProto
    {
        return Err(InterstellarHttpClientError::ReponseDecodeWrongContentType);
    }

    let mut body = match grpc_content_type {
        // only "application/grpc-web-text+proto" needs to be base64 decoded, the rest is handled as-is
        ContentType::GrpcWebTextProto => general_purpose::STANDARD_NO_PAD
            .decode(body_bytes)
            .map_err(|_| InterstellarHttpClientError::ReponseDecodeError)?
            .into(),
        _ => body_bytes,
    };

    body.advance(1);
    let len = body.get_u32();
    let reply = T::decode(&mut body.split_to(len as usize))
        .map_err(|_| InterstellarHttpClientError::ReponseDecodeError)?;
    body.advance(5);

    // TODO? trailers?
    // let _trailers = body;
    // (reply, trailers)

    Ok(reply)
}

/// Parse a node RPC response
/// It MUST be a JSON encoded hex string!
/// eg `body_bytes` = "Object({"id": String("1"), "jsonrpc": String("2.0"), "result": String("0xb8516d626945354373524d4a7565316b5455784d5a5162694e394a794e5075384842675a346138726a6d344353776602000000b8516d5a7870436964427066624c74675534796434574a314d7654436e5539316e7867394132446137735a7069636d0a000000")}"
///
/// param: `grpc_content_type`: returned by `*fetch_from_remote_grpc_web`
///     SHOULD be Json
///
/// # Errors
///
/// - `ReponseDecodeWrongContentType` if `grpc_content_type` is not Json
/// - `ReponseDecodeError` if `parity_scale_codec::codec::Decode` failed
pub fn decode_rpc_json<T: codec::Decode>(
    body_bytes: &bytes::Bytes,
    grpc_content_type: &ContentType,
) -> Result<T, InterstellarHttpClientError> {
    // CHECK
    if grpc_content_type != &ContentType::Json {
        return Err(InterstellarHttpClientError::ReponseDecodeWrongContentType);
    }

    // first: parse to untyped JSON
    // MUST match the schema: "id" + "jsonrpc" + etc; cf docstring
    let body_json: serde_json::Value = serde_json::from_slice(body_bytes)
        .map_err(|_| InterstellarHttpClientError::ReponseDecodeError)?;
    log::info!("[fetch_from_remote_grpc_web] body_json: {}", body_json,);

    // then we can deserialize the hex-encoded "result" field
    // NOTE: MUST remove the first 2 chars "0x" else:
    // "thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value: InvalidHexCharacter { c: 'x', index: 1 }'"
    let data_bytes = hex::decode(
        &body_json
            .get("result")
            .ok_or(InterstellarHttpClientError::ReponseDecodeError)?
            .as_str()
            .ok_or(InterstellarHttpClientError::ReponseDecodeError)?[2..],
    )
    .map_err(|_| InterstellarHttpClientError::ReponseDecodeError)?;
    let mut data_slice: &[u8] = &data_bytes;

    // finally can deserialize to the desired Struct
    T::decode(&mut data_slice).map_err(|_| InterstellarHttpClientError::ReponseDecodeError)
}

#[derive(Debug, Snafu)]
pub enum InterstellarHttpClientError {
    InvalidUrl,
    #[snafu(display("http error[{}]: {:?}", status_code, response))]
    HttpError {
        status_code: u16,
        response: Vec<u8>,
    },
    IoError,
    Timeout,
    ResponseMissingContentTypeHeader,
    ReponseDecodeWrongContentType,
    /// Could not decode the expected GRPC Response
    ReponseDecodeError,

    EncodeError,
}

/// This function uses the `offchain::http` API to query the remote endpoint information,
///   and returns the JSON response as vector of bytes.
///
/// WARNING: DO NOT USE in sgx env!
/// The code compiles, but it would FAIL at runtime; cf README.md
///
/// return:
/// - the body, as raw bytes
/// - the Content-Type Header: needed to know how to deserialize(cf `decode_body`)
///
/// # Errors
///
/// Various `InterstellarHttpClientError` eg:
/// - bad "url" param
/// - `IoError`
/// - `HttpError` if response is not an OK HTTP STATUS
/// - etc
///
#[cfg(feature = "with_sp_offchain")]
pub fn sp_offchain_fetch_from_remote_grpc_web(
    body_bytes: Option<bytes::Bytes>,
    url: &str,
    request_method: &RequestMethod,
    request_content_type: Option<&ContentType>,
    timeout_duration: Duration,
) -> Result<(bytes::Bytes, ContentType), InterstellarHttpClientError> {
    log::info!(
        "fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
        url,
        if let Some(ref body_bytes) = body_bytes {
            general_purpose::STANDARD_NO_PAD.encode(body_bytes)
        } else {
            String::new()
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
        _ => {}
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
        .deadline(
            sp_io::offchain::timestamp().add(sp_runtime::offchain::Duration::from_millis(
                timeout_duration
                    .as_millis()
                    .try_into()
                    .map_err(|_| InterstellarHttpClientError::EncodeError)?,
            )),
        )
        .send()
        .map_err(|err| {
            log::warn!(
                "fetch_from_remote_grpc_web: InterstellarHttpClientError::IoError at send = {:?}",
                err
            );
            InterstellarHttpClientError::IoError
        })?;

    // The request is already being processed by the host, we are free to do anything
    // else in the worker (we can send multiple concurrent requests too).
    // At some point however we probably want to check the response though,
    // so we can block current thread and wait for it to finish.
    // Note that since the request is being driven by the host, we don't have to wait
    // for the request to have it complete, we will just not read the response.
    let mut response = pending
        // .try_wait(timeout_duration)
        .try_wait(None)
        .map_err(|err| {
            log::warn!(
                "fetch_from_remote_grpc_web: InterstellarHttpClientError::IoError at try_wait[1] = {:?}",
                err
            );
            InterstellarHttpClientError::Timeout
        })?
        .map_err(|err| {
            log::warn!(
                "fetch_from_remote_grpc_web: InterstellarHttpClientError::IoError at try_wait[2] = {:?}",
                err
            );
            InterstellarHttpClientError::Timeout
        })?;

    let response_code = response.code;
    let response_content_type_str = response
        .headers()
        .find("content-type")
        .ok_or(InterstellarHttpClientError::ResponseMissingContentTypeHeader)?;
    let response_content_type_type = parse_response_content_type(response_content_type_str);
    let response_bytes = response.body().collect::<bytes::Bytes>();

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
    if response_code != 200 {
        log::warn!(
            "[fetch_from_remote_grpc_web] Unexpected status code: {}",
            response_code
        );
        return Err(InterstellarHttpClientError::HttpError {
            status_code: response_code,
            response: response_bytes.to_vec(),
        });
    }

    Ok((response_bytes, response_content_type_type))
}

/// This function uses the `offchain::http` API to query the remote endpoint information,
///   and returns the JSON response as vector of bytes.
///
/// return:
/// - the body, as raw bytes
/// - the Content-Type Header: needed to know how to deserialize(cf `decode_body`)
///
/// # Errors
///
/// Various `InterstellarHttpClientError` eg:
/// - bad "url" param
/// - `IoError`
/// - `HttpError` if response is not an OK HTTP STATUS
/// - etc
///
#[cfg(feature = "with_http_req")]
pub fn http_req_fetch_from_remote_grpc_web(
    body_bytes: Option<bytes::Bytes>,
    url: &str,
    request_method: &RequestMethod,
    request_content_type: Option<&ContentType>,
    timeout_duration: Duration,
) -> Result<(bytes::Bytes, ContentType), InterstellarHttpClientError> {
    log::info!(
        "fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
        url,
        if let Some(ref body_bytes) = body_bytes {
            general_purpose::STANDARD_NO_PAD.encode(body_bytes)
        } else {
            String::new()
        }
    );

    let http_req_uri =
        http_req::uri::Uri::try_from(url).map_err(|_| InterstellarHttpClientError::InvalidUrl)?;

    let mut request = http_req::request::Request::new(&http_req_uri);

    match request_method {
        RequestMethod::Post => {
            request.method(http_req::request::Method::POST);
        }
        RequestMethod::Get => {
            request.method(http_req::request::Method::GET);
        }
        RequestMethod::Put => {
            request.method(http_req::request::Method::PUT);
        }
        RequestMethod::Patch => {
            request.method(http_req::request::Method::PATCH);
        }
        RequestMethod::Delete => {
            request.method(http_req::request::Method::DELETE);
        }
    }

    match request_content_type {
        Some(ContentType::GrpcWeb) => {
            request.header("Content-Type", "application/grpc-web");
            request.header("X-Grpc-Web", "1");
        }
        Some(ContentType::Json) => {
            request.header("Content-Type", "application/json;charset=utf-8");
        }
        Some(ContentType::MultipartFormData) => {
            request.header("Content-Type", "multipart/form-data;boundary=\"boundary\"");
        }
        _ => {}
    }

    // NOTE: we CAN have a POST request without a body; eg IPFS CAT
    // NOTE: "send" and "body" MUST have a ref to the body, so we must copy it
    let body_bytes_copy: Vec<u8> = if let Some(body_bytes) = body_bytes {
        let body_bytes = body_bytes.to_vec();
        request.header("Content-Length", &body_bytes.len().to_string());
        body_bytes
    } else {
        vec![]
    };
    request.body(&body_bytes_copy);

    request.timeout(Some(timeout_duration));

    let mut response_bytes = Vec::new();
    let response = request.send(&mut response_bytes).map_err(|err| {
        log::warn!(
            "fetch_from_remote_grpc_web: InterstellarHttpClientError::IoError at send = {:?}",
            err
        );
        InterstellarHttpClientError::IoError
    })?;

    let response_content_type_str = response
        .headers()
        .get("content-type")
        .ok_or(InterstellarHttpClientError::ResponseMissingContentTypeHeader)?;
    let response_content_type_type =
        parse_response_content_type(response_content_type_str.as_str());

    // Let's check the status code before we proceed to reading the response.
    if !response.status_code().is_success() {
        log::warn!(
            "[fetch_from_remote_grpc_web] Unexpected status code: {}",
            response.status_code()
        );
        return Err(InterstellarHttpClientError::HttpError {
            status_code: u16::from(response.status_code()),
            response: response_bytes.clone(),
        });
    }

    Ok((
        bytes::Bytes::from(response_bytes),
        response_content_type_type,
    ))
}

fn parse_response_content_type(response_content_type_str: &str) -> ContentType {
    log::info!(
        "[fetch_from_remote_grpc_web] content_type: {}",
        response_content_type_str,
    );
    match response_content_type_str {
        // yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
        "application/grpc-web" | "application/grpc-web+proto" => ContentType::GrpcWeb,
        // BUT "application/grpc-web-text+proto" is base64 encoded
        "application/grpc-web-text+proto" => ContentType::GrpcWebTextProto,
        // classic JSON
        "application/json"
        | "application/json;charset=utf-8"
        | "application/json; charset=utf-8" => ContentType::Json,
        "text/plain" => ContentType::TextPlain,
        _ => ContentType::UnsupportedContentType {
            content_type: response_content_type_str.to_owned(),
        },
    }
}

// https://github.com/mikedilger/formdata/blob/master/src/lib.rs
// WARNING: DO NOT use "\n" as end of line: it MUST be escaped(hence '\' in this example)
// let body_bytes = b"--boundary\r\n\
//                 Content-Disposition: form-data; name=\"file\"; filename=\"TODO_path\"\r\n\
//                 Content-Type: application/octet-stream\r\n\
//                 \r\n\
//                 TODO_content1\r\n\
//                 TODO_content2\r\n\
//                 --boundary--";
pub const MULTIPART_NEW_LINE: &[u8] = b"\r\n";
pub const MULTIPART_BOUNDARY: &[u8] = b"--boundary";
pub const MULTIPART_CONTENT_DISPOSITION: &[u8] =
    b"Content-Disposition: form-data; name=\"file\"; filename=\"TODO_path\"";
pub const MULTIPART_CONTENT_TYPE: &[u8] = b"Content-Type: application/octet-stream";

/// Prepare a "Content-Disposition: form-data" body wrapping param `body_bytes`
/// That is used (at least) by API IPFS ADD.
#[must_use]
pub fn new_multipart_body_bytes(body_bytes: &[u8]) -> Vec<u8> {
    // TODO(interstellar) avoid copying
    let multipart_start = [
        MULTIPART_BOUNDARY,
        MULTIPART_NEW_LINE,
        MULTIPART_CONTENT_DISPOSITION,
        MULTIPART_NEW_LINE,
        MULTIPART_CONTENT_TYPE,
        MULTIPART_NEW_LINE,
        // Space b/w "headers" and "body"
        MULTIPART_NEW_LINE,
    ]
    .concat();
    // No need for a new line at the end
    [
        multipart_start.as_slice(),
        body_bytes,
        MULTIPART_NEW_LINE,
        MULTIPART_BOUNDARY,
        b"--",
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_multipart_body_bytes_ok() {
        let body_bytes = vec![42, 41];
        assert_eq!(
            new_multipart_body_bytes(&body_bytes),
            vec![
                45, 45, 98, 111, 117, 110, 100, 97, 114, 121, 13, 10, 67, 111, 110, 116, 101, 110,
                116, 45, 68, 105, 115, 112, 111, 115, 105, 116, 105, 111, 110, 58, 32, 102, 111,
                114, 109, 45, 100, 97, 116, 97, 59, 32, 110, 97, 109, 101, 61, 34, 102, 105, 108,
                101, 34, 59, 32, 102, 105, 108, 101, 110, 97, 109, 101, 61, 34, 84, 79, 68, 79, 95,
                112, 97, 116, 104, 34, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112,
                101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 111, 99, 116,
                101, 116, 45, 115, 116, 114, 101, 97, 109, 13, 10, 13, 10, //
                // BEGIN "body_bytes"
                42, 41, //
                // END "body_bytes"
                13, 10, 45, 45, 98, 111, 117, 110, 100, 97, 114, 121, 45, 45,
            ]
        );
    }
}
