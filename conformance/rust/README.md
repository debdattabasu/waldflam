# firestore-rs client conformance check

Runs the `firestore` crate (de-facto community Rust client), unchanged,
against waldflam:

```sh
cargo run --bin waldflam &          # in the repo root (needs docker compose up -d)
cd conformance/rust
FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 cargo run
```

Only the token source is injected (`TokenSourceType::ExternalSource`) because
firestore-rs unconditionally resolves Google credentials even in emulator
mode. Exercises ping, insert/get/update/delete (the unary CRUD RPCs), the
ALREADY_EXISTS precondition, filtered + ordered queries, transactions, and
the streaming batch writer (bidi Write stream).
