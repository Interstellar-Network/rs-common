use futures::TryStreamExt;
use ipfs_client_http_req::IpfsClient;
use std::io::Cursor;
use test_log::test;
use tests_utils::foreign_ipfs;
use tests_utils::foreign_ipfs::IpfsApi;
use tests_utils::foreign_ipfs::IpfsClient as IpfsReferenceClient;

fn setup_ipfs() -> (IpfsClient, IpfsReferenceClient, foreign_ipfs::ForeignNode) {
    let (foreign_node, ipfs_reference_client) = foreign_ipfs::run_ipfs_in_background(None);
    // let ipfs_server_multiaddr = format!("/ip4/127.0.0.1/tcp/{}", foreign_node.api_port);
    let ipfs_server_multiaddr = format!("http://127.0.0.1:{}", foreign_node.api_port);
    let ipfs_internal_client = IpfsClient::new(&ipfs_server_multiaddr).unwrap();

    (ipfs_internal_client, ipfs_reference_client, foreign_node)
}

#[tokio::test]
async fn test_ipfs_add_ok() {
    let (ipfs_internal_client, ipfs_reference_client, foreign_node) = setup_ipfs();

    // MOCK ipfs_internal_client "ipfs_add"
    let content = &[65u8, 90, 97, 122]; // AZaz
    let add_response = ipfs_internal_client.ipfs_add(content).unwrap();

    let skcd_buf = ipfs_reference_client
        .cat(&add_response.hash)
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
        .unwrap();

    let res_str = String::from_utf8(skcd_buf).unwrap();
    assert_eq!(res_str, "AZaz");

    // Needed to keep the server alive?
    assert!(foreign_node.daemon.id() > 0);
}

#[tokio::test]
async fn test_ipfs_cat_ok() {
    let (ipfs_internal_client, ipfs_reference_client, foreign_node) = setup_ipfs();

    // ADD using the official client
    let content = &[65u8, 90, 97, 122]; // AZaz
    let cursor = Cursor::new(content);
    let ipfs_server_response = ipfs_reference_client.add(cursor).await.unwrap();

    let res = ipfs_internal_client
        .ipfs_cat(&ipfs_server_response.hash)
        .unwrap();

    let res_str = String::from_utf8(res).unwrap();
    assert_eq!(res_str, "AZaz");

    // Needed to keep the server alive?
    assert!(foreign_node.daemon.id() > 0);
}

/// https://rust-lang.github.io/api-guidelines/interoperability.html#types-are-send-and-sync-where-possible-c-send-sync
#[test]
fn require_send_sync() {
    fn assert_send<T: Send>() {}
    assert_send::<IpfsClient>();

    fn assert_sync<T: Sync>() {}
    assert_sync::<IpfsClient>();
}

// TODO re-add; but this fail with "called outside of an Externalities-provided environment."
// probably b/c crossbeam thread/scope?
// #[test]
// fn test_ipfs_thread_safe_adds() {
//     let (ipfs_internal_client, _ipfs_reference_client, foreign_node) = setup_ipfs();
//     let (mut t, state) = new_test_ext();

//     // IMPORTANT: MUST use https://docs.rs/crossbeam-utils/latest/crossbeam_utils/thread/index.html b/c
//     // std::thread CAN NOT borrow from the stack
//     t.execute_with(|| {
//         thread::scope(|s| {
//             for i in 1..10 {
//                 let ipfs_internal_client_ref = &ipfs_internal_client;
//                 let foreign_node_ref = &foreign_node;

//                 s.spawn(move |_| {
//                     ipfs_internal_client_ref.ipfs_add(&[0, i]);
//                 });
//             }
//         })
//         .unwrap();
//     });
// }
