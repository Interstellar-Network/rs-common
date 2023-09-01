use alloc::string::String;
use alloc::vec;

use base64::engine::general_purpose;
use base64::Engine;

use crate::parse_response_content_type;
use crate::InterstellarHttpClientError;
use crate::MyContentType;
use crate::MyRequestMethod;

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
        MyRequestMethod::Post => {
            request = request.method(sp_runtime::offchain::http::Method::Post);
        }
        MyRequestMethod::Get => {
            request = request.method(sp_runtime::offchain::http::Method::Get);
        }
        MyRequestMethod::Put => {
            request = request.method(sp_runtime::offchain::http::Method::Put);
        }
        MyRequestMethod::Patch => {
            request = request.method(sp_runtime::offchain::http::Method::Patch);
        }
        MyRequestMethod::Delete => {
            request = request.method(sp_runtime::offchain::http::Method::Delete);
        }
    }

    match request_content_type {
        Some(MyContentType::GrpcWeb) => {
            request = request.add_header("Content-Type", "application/grpc-web");
            request = request.add_header("X-Grpc-Web", "1");
        }
        Some(MyContentType::Json) => {
            request = request.add_header("Content-Type", "application/json;charset=utf-8");
        }
        Some(MyContentType::MultipartFormData) => {
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
