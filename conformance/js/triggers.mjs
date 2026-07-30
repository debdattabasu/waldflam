// Cloud Functions triggers: register handlers over the admin API, write
// documents with a normal client, and assert the CloudEvents arrive with
// correct types, payloads, and path params.
import { createServer } from 'node:http';
import { initializeApp } from 'firebase/app';
import {
  getFirestore, connectFirestoreEmulator, doc, setDoc, updateDoc, deleteDoc,
} from 'firebase/firestore';

const host = process.env.WALDFLAM_HOST || '127.0.0.1';
const port = parseInt(process.env.WALDFLAM_PORT || '8080', 10);
const projectId = `js-fn-${Date.now()}`;

const assert = (cond, msg) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } };

// A local "functions runtime": collects CloudEvents.
const received = [];
const waiters = [];
const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const event = JSON.parse(body);
    received.push(event);
    while (waiters.length) waiters.shift()();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const fnPort = server.address().port;
const endpoint = (path) => `http://127.0.0.1:${fnPort}/${path}`;

const waitFor = async (predicate, what) => {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const hit = received.find(predicate);
    if (hit) return hit;
    await new Promise((r) => { waiters.push(r); setTimeout(r, 100); });
  }
  console.error(`FAIL: timed out waiting for ${what}. Got: ${JSON.stringify(received.map(e => e.type + ' ' + e.subject))}`);
  process.exit(1);
};

// 1. Register triggers.
const res = await fetch(`http://${host}:${port}/emulator/v1/projects/${projectId}/triggers`, {
  method: 'PUT',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    triggers: [
      { id: 'onUserWritten', pattern: 'users/{userId}', event: 'written', endpoint: endpoint('written') },
      { id: 'onPostCreated', pattern: 'users/{userId}/posts/{postId}', event: 'created', endpoint: endpoint('created') },
      { id: 'onUserDeleted', pattern: 'users/{userId}', event: 'deleted', endpoint: endpoint('deleted') },
    ],
  }),
});
assert(res.ok, `trigger registration failed: ${res.status}`);
const body = await res.json();
assert(body.registered === 3, `expected 3 triggers, got ${body.registered}`);
console.log('TRIGGERS ok: registered via admin API');

const app = initializeApp({ projectId }, 'fn');
const db = getFirestore(app);
connectFirestoreEmulator(db, host, port);

// 2. Create fires `created` (via the `written` trigger).
await setDoc(doc(db, 'users/alice'), { name: 'Alice', score: 1 });
const created = await waitFor(
  (e) => e.type.endsWith('.created') && e.subject === 'documents/users/alice',
  'create event',
);
assert(created.specversion === '1.0', 'specversion');
assert(created.params.userId === 'alice', `params.userId, got ${JSON.stringify(created.params)}`);
assert(created.data.value.fields.name.stringValue === 'Alice', 'new value payload');
assert(Object.keys(created.data.oldValue).length === 0, 'oldValue empty on create');
assert(created.source.includes(projectId), 'source names the database');
console.log('TRIGGERS ok: create event with params and payload');

// 3. Update fires `updated` carrying before AND after.
await updateDoc(doc(db, 'users/alice'), { score: 2 });
const updated = await waitFor(
  (e) => e.type.endsWith('.updated') && e.subject === 'documents/users/alice',
  'update event',
);
assert(updated.data.oldValue.fields.score.integerValue === '1', `oldValue score, got ${JSON.stringify(updated.data.oldValue.fields?.score)}`);
assert(updated.data.value.fields.score.integerValue === '2', 'new value score');
console.log('TRIGGERS ok: update event carries before and after');

// 4. Nested pattern with two params, `created` only.
await setDoc(doc(db, 'users/alice/posts/p1'), { title: 'Hello' });
const nested = await waitFor(
  (e) => e.subject === 'documents/users/alice/posts/p1',
  'nested create event',
);
assert(nested.type.endsWith('.created'), 'nested event type');
assert(nested.params.userId === 'alice' && nested.params.postId === 'p1',
  `nested params: ${JSON.stringify(nested.params)}`);
console.log('TRIGGERS ok: nested pattern captures multiple params');

// 5. Delete fires `deleted` with the final state in oldValue.
await deleteDoc(doc(db, 'users/alice'));
const deleted = await waitFor(
  (e) => e.type.endsWith('.deleted') && e.subject === 'documents/users/alice',
  'delete event',
);
assert(deleted.data.oldValue.fields.score.integerValue === '2', 'deleted oldValue');
assert(Object.keys(deleted.data.value).length === 0, 'value empty on delete');
console.log('TRIGGERS ok: delete event carries the final state');

// 6. Non-matching paths must not fire.
await setDoc(doc(db, 'other/thing'), { x: 1 });
await new Promise((r) => setTimeout(r, 500));
assert(!received.some((e) => e.subject === 'documents/other/thing'),
  'non-matching path should not trigger');
console.log('TRIGGERS ok: non-matching paths ignored');

server.close();
console.log('ALL TRIGGER CHECKS PASSED');
process.exit(0);
