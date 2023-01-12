#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// https://github.com/integritee-network/worker/blob/master/core/rest-client/src/lib.rs#L30
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_req_sgx as http_req;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use url_sgx as url;

#[cfg(not(feature = "sgx"))]
use http_req_std as http_req;

use alloc::string::ToString;
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use core::time::Duration;
use itc_rest_client::http_client::HttpClient;
use itc_rest_client::http_client::SendHttpRequest;

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
    Unknown,
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

pub fn fetch_from_remote_grpc_web(
    body_bytes: bytes::Bytes,
    url: &str,
    request_content_type: ContentType,
    deadline_duration: Duration,
) -> Result<(bytes::Bytes, ContentType), itc_rest_client::error::Error> {
    log::info!(
        "fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
        url,
        base64::encode(&body_bytes)
    );

    let http_client = HttpClient::new(
        itc_rest_client::http_client::DefaultSend {},
        false,
        Some(deadline_duration),
        None,
        None,
    );

    let url = url::Url::parse(url).unwrap();

    let uri = http_req::uri::Uri::try_from(url.as_str()).unwrap();

    let mut request = http_req::request::Request::new(&uri);
    request.method(http_req::request::Method::POST);

    let mut request_headers = http_req::response::Headers::default_http(&uri);
    match request_content_type {
        ContentType::GrpcWeb => {
            request_headers.insert("Content-Type", "application/grpc-web");
            request_headers.insert("X-Grpc-Web", "1");
        }
        ContentType::Json => {
            request_headers.insert("Content-Type", "application/json;charset=utf-8");
        }
        _ => panic!("request_content_type SHOULD be Json or GrpcWeb"),
    }

    request.body(&body_bytes);
    request_headers.insert("Content-Length", &body_bytes.len().to_string());

    let mut response_bytes = Vec::new();
    // let response = http_client.execute_send_request(&mut request, &mut write)?;
    let response = request.send(&mut response_bytes).unwrap(); // TODO .map_err(Error::HttpReqError)

    let content_type_header = response.headers().get("content-type").unwrap();
    log::info!(
        "[fetch_from_remote_grpc_web] status code: {}, content_type: {}",
        response.status_code(),
        content_type_header
    );
    let content_type = match content_type_header.as_str() {
        // yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
        "application/grpc-web" => ContentType::GrpcWeb,
        "application/grpc-web+proto" => ContentType::GrpcWeb,
        // BUT "application/grpc-web-text+proto" is base64 encoded
        "application/grpc-web-text+proto" => ContentType::GrpcWebTextProto,
        // classic JSON
        "application/json" => ContentType::Json,
        "application/json; charset=utf-8" => ContentType::Json,
        _ => ContentType::Unknown,
    };

    // Let's check the status code before we proceed to reading the response.
    if !response.status_code().is_success() {
        log::warn!(
            "[fetch_from_remote_grpc_web] Unexpected status code: {}",
            response.status_code()
        );
        return Err(itc_rest_client::error::Error::HttpError(
            u16::from(response.status_code()),
            "Unknown".to_string(),
        ));
    }

    return Ok((bytes::Bytes::from(response_bytes), content_type));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
