use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use base64::engine::general_purpose;
use base64::Engine;

use crate::parse_response_content_type;
use crate::InterstellarHttpClientError;
use crate::MyContentType;
use crate::MyRequestMethod;

#[cfg(all(feature = "sgx", feature = "with_http_req_sgx"))]
use http_req_sgx as http_req;

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
pub(crate) fn send_request(
    body_bytes: Option<bytes::Bytes>,
    url: &str,
    request_method: &MyRequestMethod,
    request_content_type: Option<&MyContentType>,
    timeout_duration: core::time::Duration,
) -> Result<(bytes::Bytes, MyContentType), InterstellarHttpClientError> {
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
        MyRequestMethod::Post => {
            request.method(http_req::request::Method::POST);
        }
        MyRequestMethod::Get => {
            request.method(http_req::request::Method::GET);
        }
        MyRequestMethod::Put => {
            request.method(http_req::request::Method::PUT);
        }
        MyRequestMethod::Patch => {
            request.method(http_req::request::Method::PATCH);
        }
        MyRequestMethod::Delete => {
            request.method(http_req::request::Method::DELETE);
        }
    }

    match request_content_type {
        Some(MyContentType::GrpcWeb) => {
            request.header("Content-Type", "application/grpc-web");
            request.header("X-Grpc-Web", "1");
        }
        Some(MyContentType::Json) => {
            request.header("Content-Type", "application/json;charset=utf-8");
        }
        Some(MyContentType::MultipartFormData) => {
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
