# Backlog

Milestones M0–M6 are done (see [readme](readme.md) and
[docs/architecture.md](docs/architecture.md)). What follows is everything
known to be missing, wrong, or deliberately deferred — ordered by whether it
would bite a real user.

## Correctness gaps that can bite today

These are the ones to fix before calling waldflam production-ready.

- **Remote events are state-at-read, not state-at-commit.** Cross-instance
  commit notices carry only the paths a commit touched, so
  `waldflam-engine/src/fanout.rs` reads each document back to build the
  event. A listener can therefore observe a *later* state than the commit
  that notified it — self-correcting (the next event re-reads), but it means
  a rapid write sequence on another instance may collapse into fewer
  observed states than it produced.
- **Triggers fire only on the instance that applied the commit.** This is
  deliberate — every instance sees every commit, so dispatching everywhere
  would deliver each CloudEvent once per instance — but combined with
  at-most-once delivery it means a commit whose instance dies mid-dispatch
  drops its events, with no other instance to pick them up.
- **Nothing enforces one waldflam per `WALDFLAM_MONGO`+listen pair.** Running
  two instances is now correct, but there's no cluster membership, health, or
  leader concept, so operational mistakes (e.g. two instances with wildly
  skewed clocks) show up as odd `read_time`s rather than a clear error.
- **Transaction isolation is weaker than Firestore's.** This is about
  *Firestore* transactions (`BeginTransaction` → `Commit`), which span
  multiple RPCs and are validated by read-set comparison — not about a single
  `Commit`, which is now atomic. Reads inside one see latest state rather
  than a fixed snapshot, and the read-set records only documents actually
  returned, so a document *appearing* in a queried range after the read goes
  undetected (a phantom). Contention on documents that were read is detected
  correctly and answers `ABORTED`. Fix: Mongo snapshot sessions for reads,
  plus range-based read-set tracking for queries.
- **A document only read inside a commit isn't conflict-checked.** MongoDB
  detects write-write conflicts, so any document the commit writes is
  protected. A `Verify`-only write reads without writing, so a concurrent
  change to it won't restart the transaction. Narrow, but real.
- **`read_time` consistency selectors are ignored.** Requests asking for a
  point-in-time read silently get latest state. Firestore keeps history; we
  overwrite in place. Fix needs a versioned storage design — non-trivial, and
  worth deciding whether to support at all.
- **Inexact predicates can't be paged server-side.** `!=`, `not-in`,
  `is-not-null`, `is-not-nan` and anything untranslatable leave the predicate
  wider than the query, so `limit` has to stay in memory or it would count
  documents the exact pass is about to reject. Those queries still read all
  candidates.
- **Index-ordered pages need a bound on the sort field.** The wildcard index
  serves the order only because the predicate always carries the order-by
  field's existence clause (`$gte: ""`). If that clause is ever dropped as an
  optimization, ordering silently reverts to a blocking sort — correct
  results, much more work. `sorted_pages_avoid_a_blocking_sort` guards it.
- **Some filters can't be planned and still scan.** `!=` and `not-in` narrow
  only to "field exists"; `OR` isn't supported at all; backtick-escaped field
  paths are skipped deliberately, since a dotted path is ambiguous between a
  nested map and a field whose name contains a dot. Each of these falls back
  to a collection scan plus in-memory filtering, which is correct but slow.
- **Multi-filter queries only get single-field selectivity, and deep sorts
  fall back to a blocking sort — there are no composite indexes.** A wildcard
  index scan binds one field path, so a query with two filters seeks on one
  and applies the rest during FETCH. Likewise, a normalized order-by of three
  or more columns (an explicit multi-field sort, or an inequality on a field
  other than the sort field, which `normalize_orders` appends) exceeds the
  one-wildcard-plus-`name_key` shape and gets top-K sorted instead.

  This is the design's ceiling, not a bug to patch. A composite index needs
  one key per *query shape*, holding the fields' encodings concatenated in
  order; a per-field index structurally cannot provide that. Firestore
  resolves it by making composite indexes user-declared
  (`firestore.indexes.json`) while single-field indexing stays automatic —
  and waldflam already has the automatic half.

  Whether to follow suit is an open product decision, and worth taking
  deliberately: honouring `firestore.indexes.json` would match Firestore
  exactly and let users tune, at the cost of the "no indexes to declare"
  property that motivated this storage design. Deriving indexes from observed
  query shapes instead would keep that property but adds a whole adaptive
  indexing subsystem. Until one is chosen, selective multi-filter queries
  over large collections are the weak spot.
- **No document-size, depth, or path-length limits.** Firestore rejects
  documents over 1 MiB, nesting past 20/50 levels, path segments over 1500
  bytes, and paths over 100 segments. Constants are recorded in
  architecture.md §11; nothing enforces them.
- **Index-value truncation is unimplemented.** Production truncates index
  values at 1500 bytes with a `truncated` tiebreaker flag. Large values will
  produce oversized index keys instead.

## Missing API surface

- `PartitionQuery` — stubbed `UNIMPLEMENTED`. The Go client short-circuits
  `partitionCount == 1`, so it only matters for parallel-scan workloads.
- `ExecutePipeline` (the beta pipeline API) — stubbed.
- `ListDocuments` ignores `page_size`/`page_token`/`order_by`/`show_missing`;
  it returns everything in one page sorted by `__name__`.
- `ListCollectionIds` ignores paging.
- `BatchWrite` (the non-atomic bulk RPC) is unimplemented; `BulkWriter` in the
  Go client is the main user.
- Collection-group queries are rejected below the database root.
- `OR` composite filters are rejected (`Unimplemented`); only `AND` is
  supported. Modern SDKs can emit `OR`.
- Vector/`find_nearest` queries: values sort correctly, but there's no KNN
  search.
- No `firestore.indexes.json` handling. Matching the emulator, any valid query
  runs without an index — but we also don't *use* the file to build Mongo
  indexes, which we should once index-backed queries land.

## Rules engine

- **`request.resource.data` on updates is the incoming document only**, not
  merged with existing state. Rules like `request.resource.data.owner ==
  resource.data.owner` behave correctly for full sets but can differ from
  production for masked updates.
- `getAfter()` / `existsAfter()` parse and dispatch but see pre-commit state.
- No `duration`/`timestamp` arithmetic beyond the basics; no `hashing.*`, no
  `bytes` literals, no `math.random`.
- The per-entity lookup budget (10) isn't separately tracked — only the
  per-request budget (20).
- Query authorization is path-based (`list` on the collection). Production also
  evaluates query *constraints* (the `constraint` value type) so that a rule
  like `allow list: if request.query.limit <= 10` works. Not supported.
- No rules coverage report (`:ruleCoverage`), which the emulator exposes and
  test tooling can consume.
- Compile-time validators are partial: expression depth, match depth, and
  runtime recursion are bounded, but there's no static cycle detection or
  type-check pass.

## Cloud Functions

- Triggers deliver at-most-once with 3 attempts and no dead-letter queue; a
  handler that's down past the retries drops the event.
- No trigger persistence — registrations live in memory and vanish on restart.
- No auth on the delivery request (no OIDC token), and no per-trigger
  filtering beyond the path pattern.
- Only Firestore document triggers; no scheduled, auth, or storage triggers,
  and no callable/HTTPS function hosting.

## Operations & ecosystem

- **Signing-key rotation is manual.** `waldflam credentials
  rotate-signing-key` works and doesn't break tokens in flight, but nothing
  schedules it, so a deployment that never runs it keeps one key forever.
  Google rotates on the order of days. Fix: an interval-driven rotation, with
  the same overlap the manual path already implements.
- **A key rotated away is still readable until it's purged.** Retired keys sit
  in MongoDB for about 75 minutes so their tokens keep verifying. That's the
  correct tradeoff for availability, but it does mean "rotate because the key
  leaked" doesn't take effect immediately. There's no way to say *this key is
  compromised, drop it now and accept the failed requests* — worth adding.
- **ID-token revocation checks are off by default.** With
  `WALDFLAM_AUTH_CHECK_REVOKED` unset, signing a user out leaves their
  existing ID token working for up to an hour. This matches Firebase, and the
  cost of turning it on is a lookup per request (cached, and invalidated by
  broadcast) — but the default is the permissive one, which is worth knowing.
- **Sessions can't be listed or attributed.** A refresh token record has a
  uid, a project and a timestamp — no device, IP, or user agent — so there's
  no "your active sessions" view, and revoking one session means already
  holding that token. Only "sign out everywhere" is reachable by uid.
- **Replay protection can't cover bearer assertions.** A `jti` is spent at the
  two exchange endpoints, but the self-signed-JWT flow reuses one assertion
  for its whole lifetime, so a captured one stays usable there until it
  expires. Bounded by the one-hour cap and by TLS, and unavoidable without
  changing what that flow is; the mitigation is to prefer the token exchange.
- **Service accounts are project-scoped but not permission-scoped.** A service
  account is admin of its project, full stop; there is no notion of a
  read-only or collection-scoped credential, and OAuth2 `scope` on the
  assertion is ignored.
- **The signing key is stored in the clear unless you say otherwise.** Sealing
  (`WALDFLAM_KEK`) and remote signing (`WALDFLAM_SIGNER_URL`) are both opt-in,
  so the default still puts the key in reach of anyone who can read the
  database. Defaulting to sealed would mean generating and storing a KEK
  somewhere, which is the operator's decision to make; but the default is the
  weaker one and that is worth knowing. See the threat model in
  architecture.md §3.
- **No vendor signer clients.** `RemoteSigner` speaks a small HTTP contract
  that a shim can put in front of Cloud KMS, Vault transit or PKCS#11, but
  waldflam ships no client for any of them, so using one means running that
  shim.
- **A remote signer is on the hot path with no caching or retry.** Every token
  minted is an outbound call; if the signer is slow, sign-in is slow, and a
  blip becomes a failed request rather than a retried one.
- **KEK rotation is unimplemented.** `seal-signing-key` adopts a KEK, but
  there's no way to re-seal under a new one — that currently means rotating
  the signing key instead, which is a different and larger operation.
- **`WALDFLAM_PUBLIC_URL` is load-bearing and silent about it.** It becomes
  the `iss` of every minted token and is compared on the way back in, so
  changing it invalidates outstanding tokens, and getting it wrong emits key
  files pointing somewhere clients can't reach. Nothing validates it or warns
  when it stays at the loopback default.
- **Google auth libraries disagree about `token_uri`.** Go's
  `google.JWTConfigFromJSON` honours it, so the Go Admin SDK can authenticate
  against a waldflam key file end to end; the Node libraries hardcode
  Google's token URL, so `firebase-admin`'s `credential.cert()` path will not
  reach us. Both flows are implemented (exchange *and* assertion-as-bearer),
  but only the raw wire contract is covered by conformance — no suite drives
  an actual Admin SDK in non-emulator mode.
- **No custom claims → rules integration beyond the token payload.** waldflam
  can now mint ID tokens with arbitrary custom claims, so this is solved for
  identities it issues; there is still no way to attach server-side roles to a
  uid that an *external* issuer minted.
- **TLS has no hot reload.** Certificates are read once at startup, so renewal
  needs a restart. Fine behind a terminator or with a process manager that
  restarts on renewal; a watcher on the cert path would be better.
- **No mutual TLS and no client-certificate auth**, so TLS authenticates the
  server to clients and not the reverse. Service accounts cover the reverse
  direction, but mTLS is what some deployments expect.
- No rate limiting and no quotas — including on the token endpoint, which is
  the one that does public-key verification on unauthenticated input and is
  therefore the cheapest thing to point load at.
- No metrics/tracing export; logging is minimal. Authentication failures in
  particular are not counted or sampled, so a credential-stuffing attempt
  looks like nothing at all.
- No data import/export, and no `firebase emulators:start` integration
  (emulator hub discovery endpoints).
- Multi-database support is structurally present (`{project}~{database}`
  collections) but untested beyond `(default)`.
- No published container image or release binaries.

## Deliberate divergences

Documented choices, not bugs:

- Rules `map.keys()`/`values()` return sorted keys; upstream order is
  unspecified upstream.
- Listen resume is implemented as `RESET` + full re-send rather than replaying
  deltas from a token. Correct, but re-sends more than necessary.
- Existence filters are never sent. The Go client ignores their bloom filter
  entirely, and an inaccurate count forces a re-sync, so sending nothing is
  safer than sending something approximate.
- Auto-generated document ids use a hash-based generator, not a CSPRNG.

## Nice-to-have

- grpc-webnext transports (§5) and a first-party browser SDK that speaks real
  gRPC instead of WebChannel.
- Differential testing against test vectors derived from the official emulator,
  to catch undocumented contract details.
- Running the SDKs' own upstream integration suites against waldflam.
- Benchmarks; nothing has been profiled.
