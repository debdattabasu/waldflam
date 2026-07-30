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
- **Sorting, cursors, and limits still happen in memory.** Filters are pushed
  into MongoDB (`waldflam-engine/src/plan.rs`), so a query no longer reads the
  whole collection — but every candidate that survives the predicate is still
  fetched, sorted, and truncated in the server. A query whose *filters* are
  broad but whose `limit` is small therefore reads far more than it returns.
  Fix: push `sort` + `limit` down too, which needs an index key per
  normalized order-by rather than the unordered `indexed` array.
- **Some filters can't be planned and still scan.** `!=` and `not-in` narrow
  only to "field exists"; `OR` isn't supported at all; backtick-escaped field
  paths are skipped deliberately, since a dotted path is ambiguous between a
  nested map and a field whose name contains a dot. Each of these falls back
  to a collection scan plus in-memory filtering, which is correct but slow.
- **Multi-filter queries only get single-field selectivity — there are no
  composite indexes.** All index entries live in one array per document, and
  MongoDB derives bounds from a single `$elemMatch` per index scan. A query
  with two filters therefore seeks on one of them and filters the rest during
  FETCH. Measured on `even == true AND n > 30` over 40 documents: 20 keys
  examined, 20 documents fetched, 16 returned — the `n > 30` clause
  contributed nothing.

  This is the design's ceiling, not a bug to patch. A composite index needs
  one key per *query shape*, holding the fields' encodings concatenated in
  order; the single attribute-pattern array structurally cannot provide that.
  Firestore resolves it by making composite indexes user-declared
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

- **Production auth mode.** Today every JWT is decoded but never verified
  (emulator semantics). A real deployment needs signature verification against
  Firebase Auth JWKS or a configured issuer, behind a flag.
- No TLS termination (plaintext h2c only), no rate limiting, no quotas.
- No metrics/tracing export; logging is minimal.
- No CI. The conformance matrix should run on every push — it's the main
  regression net and it currently only runs when invoked by hand.
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
