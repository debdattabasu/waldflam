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
streaming writes, security rules, and Cloud Functions triggers. Eight
conformance suites in [conformance/](conformance/) prove it against a live
server on every run — the eighth against a server that verifies signatures,
with credentials waldflam issued itself.

Still **pre-alpha for production**: queries whose filters can't be expressed
exactly — `!=`, `not-in`, `OR` — still page in the server rather than the
database, and multi-filter queries get single-field selectivity because there
are no composite indexes yet. Those and everything else known-missing are
catalogued honestly in [backlog.md](backlog.md) — read it before deploying
anything you care about.

## Authentication

By default waldflam runs **emulator semantics**: tokens are decoded but not
verified and `Bearer owner` is admin. That is what the SDKs' emulator mode
expects, and it is correct for local development — but it trusts anything it
is handed, so don't expose it.

For a deployment anyone can reach:

```sh
WALDFLAM_AUTH=verify
WALDFLAM_PUBLIC_URL=https://waldflam.example.com   # how clients reach you
```

That's the whole configuration. Every token now needs a real RS256 signature,
the `owner` backdoor is gone, and the `/emulator/v1` endpoints — which load
rules and erase databases — require admin.

### Credentials

waldflam issues its own, so verified mode needs no identity provider behind
it. **Service accounts** are the machine credential:

```sh
waldflam credentials create backend --project my-project > key.json
waldflam credentials list
waldflam credentials revoke backend@my-project.iam.waldflam.local
```

`key.json` has the same shape as a Google service-account key file, and
waldflam keeps only the public half — the private key is printed once and
never stored, so a database dump can't be replayed into working credentials.
Holding it proves the identity two ways, because Google's auth libraries
disagree about which to use and a server can't dictate the choice: exchange a
signed assertion at `/oauth2/v4/token` for a short-lived access token (the
OAuth2 JWT-bearer grant), or send the assertion straight through as the bearer.

That gets you a *named*, expiring, revocable, project-scoped admin — where a
shared secret names nobody, never expires, and needs a restart to rotate.
Revoking one stops the assertions **and** the access tokens already handed
out, everywhere, within 30 seconds.

**User identities** work the way Firebase's do. A service account mints a
custom token for a `uid`; the client trades it in and gets back an ID token
that waldflam signed:

```sh
POST /v1/accounts:signInWithCustomToken   {"token": "<custom token>"}
POST /v1/token                            grant_type=refresh_token&refresh_token=…
```

Custom claims ride along into `request.auth.token`, so rules see them. The
signing keys are published at `/.well-known/jwks.json` with OIDC discovery at
`/.well-known/openid-configuration`, which is what lets waldflam verify what
it issued — and lets anything else verify it too.

`WALDFLAM_ADMIN_TOKEN` still works as a shared-secret admin if you want one;
it's documented as the weaker option because it is. To keep using an existing
identity provider instead — Firebase Auth, say, while you migrate off it —
point waldflam at its JWKS and its tokens are accepted alongside waldflam's
own:

```sh
WALDFLAM_AUTH_ISSUER=https://securetoken.google.com/my-project
WALDFLAM_AUTH_AUDIENCE=my-project
WALDFLAM_AUTH_JWKS_URL=https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
```

All three or none: waldflam refuses to start half-configured, because a
verifier that can't verify would reject every token from an issuer the
operator believed was working.

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

Next up is depth rather than breadth — composite indexes. Four pieces already
landed: commits are **atomic** (each runs in a MongoDB transaction, so a batch
never half-lands and concurrent writers can't lose an update), waldflam runs
**multi-instance** (every commit is announced through a change stream, so a
listener on one instance sees writes applied on any of them), queries are
**index-backed end to end** (filters, ordering, cursors, and `limit` all
become MongoDB predicates over stored order-preserving keys, so a paged query
reads its page rather than the whole match set), and **credentials are real** —
signed service accounts and waldflam-issued user identities, so a verified
deployment depends on no identity provider but itself. See
[backlog.md](backlog.md).

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

The credentials suite needs a server that actually verifies signatures, so it
gets its own:

```sh
waldflam credentials create ci-runner --project cred-ci --out key.json
WALDFLAM_AUTH=verify WALDFLAM_LISTEN=127.0.0.1:8099 \
  WALDFLAM_PUBLIC_URL=http://127.0.0.1:8099 waldflam &
cd conformance/js && WALDFLAM_PORT=8099 WALDFLAM_KEY_FILE=../../key.json \
  node credentials.mjs
```

All of the above — rustfmt, clippy, the workspace tests, and every one of the
eight conformance suites — runs on each push via
[GitHub Actions](.github/workflows/ci.yml).

Design, wire contracts, and the implementation map:
[docs/architecture.md](docs/architecture.md).

## License

Apache-2.0
