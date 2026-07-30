// The official firebase JS SDK (Node build = gRPC transport) running
// unchanged against waldflam via connectFirestoreEmulator.
import { initializeApp } from 'firebase/app';
import {
  getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, updateDoc,
  deleteDoc, collection, query, where, orderBy, getDocs, runTransaction,
  onSnapshot, increment, serverTimestamp, getCountFromServer,
} from 'firebase/firestore';

const host = process.env.WALDFLAM_HOST || '127.0.0.1';
const port = parseInt(process.env.WALDFLAM_PORT || '8080', 10);
const app = initializeApp({ projectId: `js-conf-${Date.now()}` });
const db = getFirestore(app);
connectFirestoreEmulator(db, host, port);

const assert = (cond, msg) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } };

// Set / get.
await setDoc(doc(db, 'cities/tokyo'), { name: 'Tokyo', population: 37400000 });
await setDoc(doc(db, 'cities/delhi'), { name: 'Delhi', population: 31200000 });
await setDoc(doc(db, 'cities/lyon'), { name: 'Lyon', population: 1700000 });
let snap = await getDoc(doc(db, 'cities/tokyo'));
assert(snap.exists() && snap.data().population === 37400000, 'get');
console.log('GET ok:', snap.data().name);

// Update with transforms.
await updateDoc(doc(db, 'cities/tokyo'), {
  population: increment(100),
  updated: serverTimestamp(),
});
snap = await getDoc(doc(db, 'cities/tokyo'));
assert(snap.data().population === 37400100, 'increment');
assert(snap.data().updated !== undefined, 'serverTimestamp');
console.log('UPDATE ok:', snap.data().population);

// Query.
const big = await getDocs(query(
  collection(db, 'cities'),
  where('population', '>', 2000000),
  orderBy('population', 'desc'),
));
assert(big.docs.length === 2, `query size ${big.docs.length}`);
assert(big.docs[0].data().name === 'Tokyo' && big.docs[1].data().name === 'Delhi', 'query order');
console.log('QUERY ok:', big.docs.map(d => d.data().name));

// Aggregation.
const count = await getCountFromServer(collection(db, 'cities'));
assert(count.data().count === 3, `count ${count.data().count}`);
console.log('COUNT ok:', count.data().count);

// Transaction (JS does optimistic: BatchGet + preconditioned Commit).
await runTransaction(db, async (tx) => {
  const s = await tx.get(doc(db, 'cities/lyon'));
  tx.update(doc(db, 'cities/lyon'), { population: s.data().population + 1 });
});
snap = await getDoc(doc(db, 'cities/lyon'));
assert(snap.data().population === 1700001, 'txn');
console.log('TXN ok:', snap.data().population);

// Realtime: onSnapshot lifecycle.
const results = [];
let resolveNext;
const nextSnapshot = () => new Promise(r => { resolveNext = r; });
const unsub = onSnapshot(
  query(collection(db, 'cities'), where('population', '>', 2000000)),
  (qs) => { results.push(qs); if (resolveNext) { const r = resolveNext; resolveNext = null; r(qs); } },
  (err) => { console.error('FAIL: onSnapshot error', err); process.exit(1); },
);
let p = nextSnapshot();
let qs = results.length ? results[results.length - 1] : await p;
assert(qs.docs.length === 2, 'initial snapshot');
console.log('LISTEN ok: initial snapshot', qs.docs.map(d => d.id));

p = nextSnapshot();
await setDoc(doc(db, 'cities/osaka'), { name: 'Osaka', population: 19000000 });
qs = await p;
assert(qs.docs.length === 3, 'live add');
const added = qs.docChanges().find(c => c.type === 'added');
assert(added && added.doc.id === 'osaka', 'live add change');
console.log('LISTEN ok: live add delivered');

p = nextSnapshot();
await deleteDoc(doc(db, 'cities/osaka'));
qs = await p;
assert(qs.docs.length === 2, 'live delete');
const removed = qs.docChanges().find(c => c.type === 'removed');
assert(removed && removed.doc.id === 'osaka', 'live delete change');
console.log('LISTEN ok: live delete delivered');
unsub();

// Delete.
await deleteDoc(doc(db, 'cities/tokyo'));
snap = await getDoc(doc(db, 'cities/tokyo'));
assert(!snap.exists(), 'delete');
console.log('DELETE ok');

console.log('ALL JS CLIENT CHECKS PASSED');
process.exit(0);
