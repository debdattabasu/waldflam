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
