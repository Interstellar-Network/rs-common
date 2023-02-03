# rs-common

Those are the "common utils" meant to be used(directly or indirectly) by:
- https://github.com/Interstellar-Network/pallets
- https://github.com/Interstellar-Network/lib-garble-rs/
- https://github.com/Interstellar-Network/integritee-node
- https://github.com/Interstellar-Network/integritee-worker
- etc?

## Build and Test

NOTE: those are using Substrate testing framework, not Integritee(if it even exists).

`[RUST_BACKTRACE=1] cargo test [--no-fail-fast] -p pallet-ocw-garble -p pallet-ocw-circuits -p pallet-tx-validation -p pallet-mobile-registry`