#![no_std]
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
use alloc::vec::Vec;
use snafu::prelude::*;

/// IMPORTANT we COULD expose only one public function, and make the various impl features mutually exclusive
/// BUT we CAN have this crate compiled with all features b/c of the dependency b/w pallet-ocw-circuits and pallet-ocw-garble
#[cfg(feature = "with_http_req")]
mod impl_http_req;
#[cfg(feature = "with_sp_offchain")]
mod impl_sp_offchain;
#[cfg(feature = "prost")]
pub mod prost_encode_decode;

pub trait SendRequest {
    ///
    /// # Errors
    ///
    /// Various `InterstellarHttpClientError` eg:
    /// - bad "url" param
    /// - `IoError`
    /// - `HttpError` if response is not an OK HTTP STATUS
    /// - etc
    ///
    fn send_request(
        body_bytes: Option<bytes::Bytes>,
        url: &str,
        request_method: &MyRequestMethod,
        request_content_type: Option<&MyContentType>,
        timeout_duration: core::time::Duration,
    ) -> Result<(bytes::Bytes, MyContentType), InterstellarHttpClientError>;
}

// TODO cfg-if, and make sure it works(no warning) if both are enabled
// NO! For testing purposes it is really important to:
// - be able to compile with both
// - "with_http_req" takes priority
// This is because of the dependency b/w pallet-ocw-circuits and pallet-ocw-garble
// Final: to simplify the features set b/c of the dependency above; we allow both
// to be used/exposed at the same time. That way the caller have full control at the call site.
//
// #[cfg(all(feature = "with_http_req", feature = "with_sp_offchain"))]
// compile_error!("feature \"with_http_req\" and feature \"with_sp_offchain\" cannot be enabled at the same time");

/// Send using `mod impl_http_req`
/// This SHOULD be called only in std/sgx context; ie from the `worker` and `pallet-ocw-garble`
///
/// # Errors
/// `InterstellarHttpClientError`: connection failed, parsing failed, etc
///
#[cfg(feature = "with_http_req")]
pub struct ClientHttpReq {}

#[cfg(feature = "with_http_req")]
impl SendRequest for ClientHttpReq {
    ///
    /// # Errors
    ///
    /// Various `InterstellarHttpClientError` eg:
    /// - bad "url" param
    /// - `IoError`
    /// - `HttpError` if response is not an OK HTTP STATUS
    /// - etc
    ///
    fn send_request(
        body_bytes: Option<bytes::Bytes>,
        url: &str,
        request_method: &MyRequestMethod,
        request_content_type: Option<&MyContentType>,
        timeout_duration: core::time::Duration,
    ) -> Result<(bytes::Bytes, MyContentType), InterstellarHttpClientError> {
        impl_http_req::send_request(
            body_bytes,
            url,
            request_method,
            request_content_type,
            timeout_duration,
        )
    }
}

/// Send using `mod impl_sp_offchain`
/// This SHOULD be called only from a `fn offchain_worker`; ie from `pallet-ocw-circuits`
///
/// # Errors
/// `InterstellarHttpClientError`: connection failed, parsing failed, etc
///
#[cfg(feature = "with_sp_offchain")]
pub struct ClientSpOffchain {}

#[cfg(feature = "with_sp_offchain")]
impl SendRequest for ClientSpOffchain {
    ///
    /// # Errors
    ///
    /// Various `InterstellarHttpClientError` eg:
    /// - bad "url" param
    /// - `IoError`
    /// - `HttpError` if response is not an OK HTTP STATUS
    /// - etc
    ///
    fn send_request(
        body_bytes: Option<bytes::Bytes>,
        url: &str,
        request_method: &MyRequestMethod,
        request_content_type: Option<&MyContentType>,
        timeout_duration: core::time::Duration,
    ) -> Result<(bytes::Bytes, MyContentType), InterstellarHttpClientError> {
        impl_sp_offchain::send_request(
            body_bytes,
            url,
            request_method,
            request_content_type,
            timeout_duration,
        )
    }
}

#[derive(PartialEq, Eq)]
pub enum MyContentType {
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
pub enum MyRequestMethod {
    Post,
    Get,
    Put,
    Patch,
    Delete,
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
    grpc_content_type: &MyContentType,
) -> Result<T, InterstellarHttpClientError> {
    // CHECK
    if grpc_content_type != &MyContentType::Json {
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

fn parse_response_content_type(response_content_type_str: &str) -> MyContentType {
    log::info!(
        "[fetch_from_remote_grpc_web] content_type: {}",
        response_content_type_str,
    );
    match response_content_type_str {
        // yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
        "application/grpc-web" | "application/grpc-web+proto" => MyContentType::GrpcWeb,
        // BUT "application/grpc-web-text+proto" is base64 encoded
        "application/grpc-web-text+proto" => MyContentType::GrpcWebTextProto,
        // classic JSON
        "application/json"
        | "application/json;charset=utf-8"
        | "application/json; charset=utf-8" => MyContentType::Json,
        "text/plain" => MyContentType::TextPlain,
        _ => MyContentType::UnsupportedContentType {
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
    use alloc::vec;

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
