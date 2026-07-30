# Go client conformance check

Runs the official `cloud.google.com/go/firestore` client, unchanged, against
a waldflam server:

```sh
cargo run --bin waldflam &          # serves on :8080 (needs docker compose up -d)
cd conformance/go
FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 go run .
```

Exercises Set/Get, Update with increment + serverTimestamp transforms,
Create preconditions, filtered + ordered queries, GetAll (found/missing),
and Delete.
