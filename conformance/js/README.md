# JS client conformance check

Runs the official `firebase` npm package (Node build = gRPC transport),
unchanged, against waldflam:

```sh
cargo run --bin waldflam &          # needs docker compose up -d
cd conformance/js
npm install
WALDFLAM_PORT=8080 npm test
```

Exercises set/get, increment + serverTimestamp transforms, filtered +
ordered queries, count aggregation, optimistic transactions, the full
onSnapshot realtime lifecycle (initial / live add / live delete), and
deletes. Browser builds (WebChannel transport) and the lite SDK (REST) are
the remaining M4 surface.
