# waldflam

[![CI](https://github.com/debdattabasu/waldflam/actions/workflows/ci.yml/badge.svg)](https://github.com/debdattabasu/waldflam/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**An open-source, self-hostable Firebase backend — speaking Firestore's exact
wire protocol, so official Firebase client libraries connect unchanged.**

Rust server. MongoDB storage. No forked SDKs, no compat shims in your app:
point the stock JS / Go / Rust Firestore clients at waldflam the same way you
point them at the Firestore emulator, and they just work.

```js
// Your app code doesn't change. At all.
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore';
connectFirestoreEmulator(getFirestore(app), 'my-waldflam-host', 8080);
```

```sh
FIRESTORE_EMULATOR_HOST=my-waldflam-host:8080 go run ./...   # Go client
FIRESTORE_EMULATOR_HOST=my-waldflam-host:8080 cargo run      # firestore-rs
```

## Why

Firebase's developer experience is great; its lock-in is not. The existing
open-source alternatives (Supabase, Appwrite, PocketBase) all ship their own
SDKs and their own APIs — migrating means rewriting your data layer.

waldflam does for Firestore what FerretDB did for MongoDB: reimplement the
wire protocol on an open stack, so the client libraries you already use keep
working as they are.

## How

One port, four protocol surfaces:

1. **Native gRPC** (`google.firestore.v1`, plaintext h2c) — Go, Rust,
   Node/Admin, Android, iOS SDKs
2. **WebChannel** — the browser JS SDK's streaming transport for
   Listen/Write
3. **REST v1** (proto3-JSON) — the JS lite SDK and browser unary calls
4. **Admin API** — clear-data, rules hot-reload, the endpoints test harnesses
   expect

Storage is MongoDB: one flat collection per database, documents keyed by full
path, with an order-preserving index encoding that reproduces Firestore's
cross-type ordering, plus change streams backing realtime listeners and
multi-document transactions backing Firestore transactions.

Security rules (`firestore.rules`, `rules_version = '2'`) are evaluated by a
from-scratch Rust engine implementing the language's exact semantics — down to
the error-absorption behavior of `&&`/`||` and the per-request `get()` budget.

Full design, per-SDK wire contracts, and the implementation map: see
[docs/architecture.md](docs/architecture.md). Known gaps and planned work:
[backlog.md](backlog.md).

## Status

**The roadmap is complete: M0 through M6.** Every official client library
runs unchanged — the Go client, firestore-rs, and the JS SDK in all three
flavors (Node/gRPC, lite/REST, browser/WebChannel) — across CRUD, queries,
aggregations, transactions with contention retries, realtime listeners,
streaming writes, security rules, and Cloud Functions triggers. Seven
conformance suites in [conformance/](conformance/) prove it against a live
server on every run.

Still **pre-alpha for production**: query sorting and limits are applied in
the server rather than pushed into the database, and JWTs are decoded but not
verified (emulator semantics). Those and everything else known-missing are
catalogued honestly in [backlog.md](backlog.md) — read it before deploying
anything you care about.

- [x] **M0 — scaffold**: workspace, full 17-RPC `google.firestore.v1` gRPC
  surface served on h2c, value ordering + resource-name parsing + emulator
  auth semantics implemented and tested, Mongo replica-set compose file
- [x] **M1 — unary core**: CRUD, Commit with preconditions + transforms,
  queries (filters/orders/cursors), aggregations on Mongo
- [x] **M2 — transactions & write streams**: optimistic concurrency with
  ABORTED retries, bidi Write stream
- [x] **M3 — Listen**: realtime watch — official Go `Snapshots()` and JS
  `onSnapshot()` pass
- [x] **M4 — browser surface**: REST v1 (proto3-JSON — the lite SDK passes
  over pure `fetch()`) and WebChannel (the browser build passes, including
  live `onSnapshot`, over the reimplemented closure wire protocol)
- [x] **M5 — security rules + admin API**: hand-rolled rules engine
  enforced on every client path (reads, writes, queries, listeners), with
  the emulator admin endpoints for loading rules and clearing data
- [x] **M6 — Cloud Functions triggers**: document create/update/delete/write
  events delivered as CloudEvents to your HTTP endpoints, with path-pattern
  params and before/after payloads

Next up is depth rather than breadth — pushing sort and limit into the
database, then production auth. Three pieces already landed: commits are
**atomic** (each runs in a MongoDB transaction, so a batch never half-lands
and concurrent writers can't lose an update), waldflam runs **multi-instance**
(every commit is announced through a change stream, so a listener on one
instance sees writes applied on any of them), and query filters are
**index-backed** (translated into MongoDB predicates over the stored
order-preserving index keys, served by an index scan instead of reading the
collection). See [backlog.md](backlog.md).

## Cloud Functions triggers

Register handlers, then any write through any surface fires them:

```sh
curl -X PUT localhost:8080/emulator/v1/projects/my-project/triggers \
  -H 'content-type: application/json' \
  -d '{"triggers":[{"id":"onUserWritten","pattern":"users/{userId}",
       "event":"written","endpoint":"http://localhost:3000/onUserWritten"}]}'
```

Your endpoint receives a CloudEvent 1.0 with Firestore's proto3-JSON
document payloads (`data.oldValue` / `data.value`) and the captured path
params. `event` is one of `created`, `updated`, `deleted`, `written`.

## Development

```sh
docker compose up -d      # MongoDB 8, single-node replica set
cargo test --workspace    # unit layer: ordering, encodings, rules, auth
cargo run --bin waldflam  # all surfaces on 0.0.0.0:8080
```

Requires Rust stable and protoc.

With a server running, the conformance suites drive real SDKs against it:

```sh
cd conformance/go   && FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 go run .
cd conformance/rust && FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 cargo run
cd conformance/js   && npm install && node main.mjs   # Node / gRPC
                                      node lite.mjs   # lite / REST
      node --conditions=browser browser.mjs           # browser / WebChannel
                                      node rules.mjs  # security rules
                                   node triggers.mjs  # functions triggers
```

All of the above — rustfmt, clippy, the workspace tests, and every one of the
seven conformance suites — runs on each push via
[GitHub Actions](.github/workflows/ci.yml).

Design, wire contracts, and the implementation map:
[docs/architecture.md](docs/architecture.md).

## License

Apache-2.0
