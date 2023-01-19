#

TODO the http client is used both:
- from the pallets/ in this repo
- as a dependency of `lib-garble-rs`

Be **REALLY** to make sure this client is compatible with no_std/sgx.

NOTE: it MUST use Integritee's `itc_rest_client`(or directly `http-req`) else the pallets tests fail with
```
[2023-01-12T16:49:35Z ERROR pallet_ocw_garble::pallet] [ocw-garble] ipfs call ipfs_cat error: ResponseError { err: IO(Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }) }
thread 'tests::test_garble_and_strip_display_circuits_package_signed_ok' panicked at 'message_reply failed!: IpfsCallError', interstellar-pallets/pallets/ocw-garble/src/lib.rs:683:14
```
(even if the node/worker seem to be working fine)

Also it COULD compile when using `sp-io`(ie `offchain::http` API) but at runtime(in SGX) it WOULD fail
with `offchain::http_request_start unimplemented` cf https://github.com/integritee-network/worker/blob/f5674c4afb0d5499567b870b3d9d2b00bab05766/core-primitives/substrate-sgx/sp-io/src/lib.rs#L836