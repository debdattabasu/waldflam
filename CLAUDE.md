# waldflam

Open-source Firebase-compatible backend: the exact Firestore wire protocol
(gRPC + WebChannel + REST), implemented in Rust on MongoDB, so official
Firebase client SDKs (JS, Go, community Rust) connect **unchanged** in
emulator mode. Plus Cloud Functions triggers later. No Realtime Database.

**Read `docs/architecture.md` before any protocol, engine, or rules work.**
It is the source of truth: per-SDK wire contracts (§3), storage design (§6),
rules-engine spec (§7), roadmap (§9), and the behavior contracts (§11).

## Hard rules

- Wire behavior is contract-driven: for streams (Listen/Write) the *client*
  state machines documented in §3 are authoritative. For value ordering, index
  encoding, rules semantics, auth, and limits, §11's specs are authoritative.
- Server errors must use the exact gRPC codes clients act on (`ABORTED` for
  transaction contention, `NOT_FOUND` vs `INVALID_ARGUMENT`, etc. — §3).

## Build & test

```sh
cargo build --workspace
cargo test --workspace
docker compose up -d      # MongoDB 8 as single-node replica set (required for
                          # change streams + transactions; auto-initiates)
cargo run --bin waldflam  # serves gRPC h2c on 0.0.0.0:8080 (WALDFLAM_LISTEN)
```

Protoc and Rust stable are required; protos are vendored in
`crates/waldflam-proto/protos` (curated set from firebase-js-sdk).

## Layout

- `crates/waldflam-proto` — tonic/prost codegen for `google.firestore.v1`
- `crates/waldflam-engine` — Firestore semantics on MongoDB: resource paths
  (`path.rs`), the cross-type value total order (`order.rs`, must match the
  client comparators exactly — tests encode the ordering matrix), storage &
  query planning (to come)
- `crates/waldflam-rules` — Security Rules engine (from scratch; spec in §7)
- `crates/waldflam-server` — the `waldflam` binary: Firestore gRPC service
  (`service.rs`), emulator-semantics auth (`auth.rs`)

## Conventions

- Tests that encode wire/ordering contracts should cite where the behavior
  comes from (client SDK file or architecture-doc section) so a failure can be
  re-verified against the source.
- Conformance goal: official SDK integration suites run green against
  waldflam (`FIRESTORE_EMULATOR_HOST` / `connectFirestoreEmulator`).
