#![cfg_attr(not(feature = "std"), no_std)]

use bytes::{Buf, BufMut};

// #[cfg(all(not(feature = "std"), feature = "sgx"))]
// use http::{
// 	header::{HeaderName, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
// 	HeaderValue,
// };
// #[cfg(all(not(feature = "std"), feature = "sgx"))]
// use http_req::{
// 	request::{Method, Request},
// 	response::{Headers, Response},
// 	uri::Uri,
// };
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use itc_rest_client::http_client::HttpClient;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use itc_rest_client::http_client::SendHttpRequest;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use itc_rest_client::sgx_reexport_prelude::*;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
use sp_runtime::offchain::{http, Duration};

// we CAN NOT just send the raw encoded protobuf(eg using GarbleIpfsRequest{}.encode())
// b/c that returns errors like
// "protocol error: received message with invalid compression flag: 8 (valid flags are 0 and 1), while sending request"
// "tonic-web: Invalid byte 45, offset 0"
// https://github.com/hyperium/tonic/blob/01e5be508051eebf19c233d48b57797a17331383/tonic-web/tests/integration/tests/grpc_web.rs#L93
// also: https://github.com/grpc/grpc-web/issues/152
// param: dyn prost::Message, eg interstellarpbapigarble::GarbleIpfsRequest etc
pub fn encode_body<T: prost::Message>(input: T) -> bytes::Bytes {
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

pub enum GrpcWebContentType {
	/// "application/grpc-web" or "application/grpc-web+proto"
	GrpcWeb,
	/// "application/grpc-web-text+proto"
	GrpcWebTextProto,
	Unknown,
}

pub fn decode_body<T: prost::Message + Default>(
	body_bytes: bytes::Bytes,
	grpc_content_type: GrpcWebContentType,
) -> (T, bytes::Bytes) {
	let mut body = match grpc_content_type {
		// only "application/grpc-web-text+proto" needs to be base64 decoded, the rest is handled as-is
		GrpcWebContentType::GrpcWebTextProto => base64::decode(body_bytes).unwrap().into(),
		_ => body_bytes,
	};

	body.advance(1);
	let len = body.get_u32();
	let reply = T::decode(&mut body.split_to(len as usize)).expect("decode");
	body.advance(5);

	let trailers = body;

	(reply, trailers)
}

/// This function uses the `offchain::http` API to query the remote endpoint information,
///   and returns the JSON response as vector of bytes.
///
/// return:
/// - the body, as raw bytes
/// - the Content-Type Header: needed to know how to deserialize(cf decode_body)
#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub fn fetch_from_remote_grpc_web(
	body_bytes: bytes::Bytes,
	url: &str,
) -> Result<(bytes::Bytes, GrpcWebContentType), http::Error> {
	// We want to keep the offchain worker execution time reasonable, so we set a hard-coded
	// deadline to 5s to complete the external call.
	// You can also wait idefinitely for the response, however you may still get a timeout
	// coming from the host machine.
	let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(10_000));

	log::info!(
		"fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
		url,
		base64::encode(&body_bytes)
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
	let request = http::Request::post(url, vec![body_bytes])
		.add_header("Content-Type", "application/grpc-web")
		.add_header("X-Grpc-Web", "1");

	// We set the deadline for sending of the request, note that awaiting response can
	// have a separate deadline. Next we send the request, before that it's also possible
	// to alter request headers or stream body content in case of non-GET requests.
	// NOTE: 'http_request_start can be called only in the offchain worker context'
	let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;

	// The request is already being processed by the host, we are free to do anything
	// else in the worker (we can send multiple concurrent requests too).
	// At some point however we probably want to check the response though,
	// so we can block current thread and wait for it to finish.
	// Note that since the request is being driven by the host, we don't have to wait
	// for the request to have it complete, we will just not read the response.
	let mut response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

	log::info!("[fetch_from_remote_grpc_web] status code: {}", response.code);
	let content_type = response.headers().find("content-type").unwrap();
	let grpc_content_type = match content_type {
		// yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
		"application/grpc-web" => GrpcWebContentType::GrpcWeb,
		"application/grpc-web+proto" => GrpcWebContentType::GrpcWeb,
		// BUT "application/grpc-web-text+proto" is base64 encoded
		"application/grpc-web-text+proto" => GrpcWebContentType::GrpcWebTextProto,
		_ => GrpcWebContentType::Unknown,
	};
	// DEBUG: list headers
	let mut headers_it = response.headers().into_iter();
	while headers_it.next() {
		let header = headers_it.current().unwrap();
		log::info!("[fetch_from_remote_grpc_web] header: {} {}", header.0, header.1);
	}

	// Let's check the status code before we proceed to reading the response.
	if response.code != 200 {
		log::warn!("[fetch_from_remote_grpc_web] Unexpected status code: {}", response.code);
		return Err(http::Error::Unknown)
	}

	let response_bytes = response.body().collect::<bytes::Bytes>();
	return Ok((response_bytes, grpc_content_type))
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub fn fetch_from_remote_grpc_web(
	body_bytes: bytes::Bytes,
	url: &str,
) -> Result<(bytes::Bytes, GrpcWebContentType), itc_rest_client::error::Error> {
	use sgx_tstd::{collections::HashMap, string::ToString};

	// We want to keep the offchain worker execution time reasonable, so we set a hard-coded
	// deadline to 5s to complete the external call.
	// You can also wait idefinitely for the response, however you may still get a timeout
	// coming from the host machine.
	let deadline = 10u64; // in seconds(s)

	log::info!(
		"fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
		url,
		base64::encode(&body_bytes)
	);

	// fn add_to_headers(
	// 	headers: &mut http_req::response::Headers,
	// 	key: http::header::HeaderName,
	// 	value: http::HeaderValue,
	// ) {
	// 	let header_value_str = value.to_str();

	// 	match header_value_str {
	// 		Ok(v) => {
	// 			headers.insert(key.as_str(), v);
	// 		},
	// 		Err(e) => {
	// 			log::error!("Failed to add header to request: {:?}", e);
	// 		},
	// 	}
	// }

	// fn my_headers() -> http_req::response::Headers {
	// 	let mut headers = http_req::response::Headers::new();
	// 	// add_to_headers(
	// 	// 	&mut headers,
	// 	// 	"Content-Type",
	// 	// 	http::HeaderValue::from_str().unwrap(),
	// 	// );
	// 	// add_to_headers(&mut headers, "X-Grpc-Web", http::HeaderValue::from_str("1").unwrap());
	// 	headers.insert("Content-Type", "application/grpc-web");
	// 	headers.insert("X-Grpc-Web", "1");
	// 	headers
	// }

	let http_client = HttpClient::new(
		itc_rest_client::http_client::DefaultSend {},
		false,
		Some(sgx_tstd::time::Duration::from_secs(deadline)),
		None,
		None,
	);

	let url = url::Url::parse(url).unwrap();
	// let (response, encoded_body) = http_client
	// 	.send_request::<(), sgx_tstd::vec::Vec<u8>>(
	// 		url,
	// 		http_req::request::Method::POST,
	// 		(),
	// 		None,
	// 		Some(sgx_tstd::vec![body_bytes]),
	// 	)
	// 	.unwrap();

	// TODO .map_err(http::Error::HttpReqError)?
	let uri = http_req::uri::Uri::try_from(url.as_str()).unwrap();

	let mut request = http_req::request::Request::new(&uri);
	request.method(http_req::request::Method::POST);

	let mut request_headers = http_req::response::Headers::default_http(&uri);
	request_headers.insert("Content-Type", "application/grpc-web");
	request_headers.insert("X-Grpc-Web", "1");

	request.body(&body_bytes);
	request_headers.insert("Content-Length", &body_bytes.len().to_string());

	request.headers(HashMap::from(request_headers));

	let mut response_bytes = sgx_tstd::vec::Vec::new();
	// let response = http_client.execute_send_request(&mut request, &mut write)?;
	let response = request.send(&mut response_bytes).unwrap(); // TODO .map_err(Error::HttpReqError)

	log::info!("[fetch_from_remote_grpc_web] status code: {}", response.status_code());
	let content_type = response.headers().get("content-type").unwrap();
	let grpc_content_type = match content_type.as_str() {
		// yes, "application/grpc-web" and "application/grpc-web+proto" use the same encoding
		"application/grpc-web" => GrpcWebContentType::GrpcWeb,
		"application/grpc-web+proto" => GrpcWebContentType::GrpcWeb,
		// BUT "application/grpc-web-text+proto" is base64 encoded
		"application/grpc-web-text+proto" => GrpcWebContentType::GrpcWebTextProto,
		_ => GrpcWebContentType::Unknown,
	};
	// TODO DEBUG: list headers
	// let mut headers_it = response.headers().iter();
	// while headers_it.next() {
	// 	let header = headers_it.current().unwrap();
	// 	log::info!("[fetch_from_remote_grpc_web] header: {} {}", header.0, header.1);
	// }

	// Let's check the status code before we proceed to reading the response.
	if !response.status_code().is_success() {
		log::warn!(
			"[fetch_from_remote_grpc_web] Unexpected status code: {}",
			response.status_code()
		);
		return Err(itc_rest_client::error::Error::HttpError(
			u16::from(response.status_code()),
			"Unknown".to_string(),
		))
	}

	// let response_bytes = response.body().collect::<bytes::Bytes>();
	return Ok((bytes::Bytes::from(response_bytes), grpc_content_type))
}

#[cfg(test)]
mod tests {
	#[test]
	fn it_works() {
		let result = 2 + 2;
		assert_eq!(result, 4);
	}
}
