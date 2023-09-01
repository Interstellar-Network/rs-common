use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use base64::{engine::general_purpose, Engine as _};
use embedded_io::adapters::FromTokio;
use embedded_nal_async::{AddrType, IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;

use crate::parse_response_content_type;
use crate::InterstellarHttpClientError;
use crate::MyContentType;
use crate::RequestMethod;

// // https://github.com/drogue-iot/reqwless/blob/main/tests/client.rs#L31C1-L31C33
struct TokioTcp;
static TCP: TokioTcp = TokioTcp;
static LOOPBACK_DNS: LoopbackDns = LoopbackDns;

struct LoopbackDns;
impl embedded_nal_async::Dns for LoopbackDns {
    type Error = MyError;

    async fn get_host_by_name(&self, _: &str, _: AddrType) -> Result<IpAddr, Self::Error> {
        Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    async fn get_host_by_address(&self, _: IpAddr) -> Result<heapless::String<256>, Self::Error> {
        Err(MyError)
    }
}

#[derive(Debug)]
struct MyError;

impl embedded_io::Error for MyError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl embedded_nal_async::TcpConnect for TokioTcp {
    type Error = MyError;
    type Connection<'m> = FromTokio<TcpStream>;

    async fn connect<'m>(
        &self,
        remote: embedded_nal_async::SocketAddr,
    ) -> Result<Self::Connection<'m>, Self::Error> {
        let ip = match remote {
            embedded_nal_async::SocketAddr::V4(a) => a.ip().octets().into(),
            embedded_nal_async::SocketAddr::V6(a) => a.ip().octets().into(),
        };
        let remote = SocketAddr::new(ip, remote.port());
        let stream = TcpStream::connect(remote).await?;
        let stream = FromTokio::new(stream);
        Ok(stream)
    }
}

pub fn http_req_fetch_from_remote_grpc_web(
    body_bytes: Option<bytes::Bytes>,
    url: &str,
    request_method: &RequestMethod,
    request_content_type: Option<&MyContentType>,
    timeout_duration: core::time::Duration,
) -> Result<(bytes::Bytes, MyContentType), InterstellarHttpClientError> {
    use reqwless::client::HttpClient;
    use reqwless::client::{TlsConfig, TlsVerify};
    use reqwless::request::RequestBuilder;

    log::info!(
        "fetch_from_remote_grpc_web: url = {}, sending body b64 = {}",
        url,
        if let Some(ref body_bytes) = body_bytes {
            general_purpose::STANDARD_NO_PAD.encode(body_bytes)
        } else {
            String::new()
        }
    );

    // let mut tls_read_buf: [u8; 16384] = [0; 16384];
    // let mut tls_write_buf: [u8; 16384] = [0; 16384];
    // // let mut client = HttpClient::new_with_tls(
    // //     &TCP,
    // //     &LOOPBACK_DNS,
    // //     TlsConfig::new(
    // //         OsRng.next_u64(),
    // //         &mut tls_read_buf,
    // //         &mut tls_write_buf,
    // //         TlsVerify::None,
    // //     ),
    // // );
    // let mut client = HttpClient::new(&TCP, &LOOPBACK_DNS);
    // let mut rx_buf = [0; 4096];
    // // TODO? .await.unwrap()
    // let mut resource = client.resource(&url);
    // // TODO?
    // // for _ in 0..2 {
    // //     let response = resource
    // //         .post("/")
    // //         .body(b"PING".as_slice())
    // //         .content_type(ContentType::TextPlain)
    // //         .send(&mut rx_buf)
    // //         .await
    // //         .unwrap();
    // //     let body = response.body().read_to_end().await;
    // //     assert_eq!(body.unwrap(), b"PING");
    // // }

    // // match request_method {
    // //     RequestMethod::Post => {
    // //         request.method(http_req::request::Method::POST);
    // //     }
    // //     RequestMethod::Get => {
    // //         request.method(http_req::request::Method::GET);
    // //     }
    // //     RequestMethod::Put => {
    // //         request.method(http_req::request::Method::PUT);
    // //     }
    // //     RequestMethod::Patch => {
    // //         request.method(http_req::request::Method::PATCH);
    // //     }
    // //     RequestMethod::Delete => {
    // //         request.method(http_req::request::Method::DELETE);
    // //     }
    // // }

    // // match request_content_type {
    // //     Some(MyContentType::GrpcWeb) => {
    // //         request.header("Content-Type", "application/grpc-web");
    // //         request.header("X-Grpc-Web", "1");
    // //     }
    // //     Some(MyContentType::Json) => {
    // //         request.header("Content-Type", "application/json;charset=utf-8");
    // //     }
    // //     Some(MyContentType::MultipartFormData) => {
    // //         request.header("Content-Type", "multipart/form-data;boundary=\"boundary\"");
    // //     }
    // //     _ => {}
    // // }

    // // NOTE: we CAN have a POST request without a body; eg IPFS CAT
    // // NOTE: "send" and "body" MUST have a ref to the body, so we must copy it
    // let body_bytes_copy: Vec<u8> = if let Some(body_bytes) = body_bytes {
    //     let body_bytes = body_bytes.to_vec();
    //     resource.header("Content-Length", &body_bytes.len().to_string());
    //     body_bytes
    // } else {
    //     vec![]
    // };
    // resource.body(&body_bytes_copy);

    // resource.timeout(Some(timeout_duration));

    // let request = resource.build();

    // let mut response_bytes = Vec::new();
    // // TODO? (&mut response_bytes)
    // let response = futures::executor::block_on(async { resource.await });
    // response.unwrap().map_err(|err| {
    //     log::warn!(
    //         "fetch_from_remote_grpc_web: InterstellarHttpClientError::IoError at send = {:?}",
    //         err
    //     );
    //     InterstellarHttpClientError::IoError
    // })?;

    let mut client = HttpClient::new(&TCP, &LOOPBACK_DNS); // Types implementing embedded-nal-async
    let mut rx_buf = [0; 4096];
    let response = futures::executor::block_on(async {
        client
            .request(reqwless::request::Method::POST, &url)
            .await
            .unwrap()
            .body(b"PING")
            .content_type(reqwless::headers::ContentType::TextPlain)
            .send(&mut rx_buf)
            .await
            .unwrap()
    });

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
