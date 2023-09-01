# http-grpc-client

TODO the http client is used both:
- from the pallets/ repo
- as a dependency of `lib-garble-rs`

Be **REALLY** sure this client is compatible with no_std/sgx.
There are multiple environment where it MUST work:
- in a SGX enclave; eg from `pallet-ocw-garble`: there the crate `http_req-sgx` is used
- standard std; there the crate `http_req` is used
- in WASM; eg `pallet-ocw-circuits`
- no_std; eg from `pallet-ocw-garble`
That is because:
- `integritee-node` is compiled twice both for std environment, and for WASM.
- `worker` CAN be compiled both for std environment, and for SGX(where `sgx_tstd` can be used as replacement for std).

NOTE: it MUST use Integritee's `itc_rest_client`(or directly `http-req`) else the pallets tests fail with
```
[2023-01-12T16:49:35Z ERROR pallet_ocw_garble::pallet] [ocw-garble] ipfs call ipfs_cat error: ResponseError { err: IO(Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }) }
thread 'tests::test_garble_and_strip_display_circuits_package_signed_ok' panicked at 'message_reply failed!: IpfsCallError', interstellar-pallets/pallets/ocw-garble/src/lib.rs:683:14
```
(even if the node/worker seem to be working fine)

Also it COULD compile when using `sp-io`(ie `offchain::http` API) but at runtime(in SGX) it WOULD fail
with `offchain::http_request_start unimplemented` cf https://github.com/integritee-network/worker/blob/f5674c4afb0d5499567b870b3d9d2b00bab05766/core-primitives/substrate-sgx/sp-io/src/lib.rs#L836