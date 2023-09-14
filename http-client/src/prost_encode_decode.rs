use base64::engine::general_purpose;
use base64::Engine;
use bytes::Buf;
use bytes::BufMut;

use crate::InterstellarHttpClientError;
use crate::MyContentType;

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
    grpc_content_type: &MyContentType,
) -> Result<T, InterstellarHttpClientError> {
    // CHECK
    if grpc_content_type != &MyContentType::GrpcWeb
        && grpc_content_type != &MyContentType::GrpcWebTextProto
    {
        return Err(InterstellarHttpClientError::ReponseDecodeWrongContentType);
    }

    let mut body = match grpc_content_type {
        // only "application/grpc-web-text+proto" needs to be base64 decoded, the rest is handled as-is
        MyContentType::GrpcWebTextProto => general_purpose::STANDARD_NO_PAD
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
