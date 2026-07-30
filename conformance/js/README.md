# JS client conformance check

Runs the official `firebase` npm package (Node build = gRPC transport),
unchanged, against waldflam:

```sh
cargo run --bin waldflam &          # needs docker compose up -d
cd conformance/js
npm install
WALDFLAM_PORT=8080 npm test
```

Three flavors, all unchanged:

- `npm test` / `node main.mjs` — the Node build (gRPC transport)
- `node lite.mjs` — firebase/firestore/lite (pure fetch() REST)
- `node --conditions=browser browser.mjs` — the browser build (WebChannel
  streaming transport for Listen/Write, REST for unary)

Each exercises set/get, transforms, queries, count aggregation, optimistic
transactions, the full onSnapshot realtime lifecycle, and deletes.

`node triggers.mjs` covers Cloud Functions triggers: registering handlers
over the admin API, then asserting create/update/delete CloudEvents arrive
at a local HTTP server with the right types, before/after payloads, and path
params.

`node rules.mjs` covers security rules end to end: loading a ruleset over
the emulator admin API, admin bypass (`Bearer owner`), anonymous vs
authenticated access, `exists()` lookups inside rules, query (`list`)
enforcement, and the clear-data endpoint.
