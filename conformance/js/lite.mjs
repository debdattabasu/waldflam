// The firebase/firestore/lite SDK — pure fetch() REST, proto3-JSON.
import { initializeApp } from 'firebase/app';
import {
  getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, updateDoc,
  deleteDoc, collection, query, where, orderBy, getDocs, getCount,
  increment, serverTimestamp,
} from 'firebase/firestore/lite';

const host = process.env.WALDFLAM_HOST || '127.0.0.1';
const port = parseInt(process.env.WALDFLAM_PORT || '8080', 10);
const app = initializeApp({ projectId: `js-lite-${Date.now()}` });
const db = getFirestore(app);
connectFirestoreEmulator(db, host, port);

const assert = (cond, msg) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } };

await setDoc(doc(db, 'cities/tokyo'), { name: 'Tokyo', population: 37400000, tags: ['big', 'capital'] });
await setDoc(doc(db, 'cities/lyon'), { name: 'Lyon', population: 1700000 });
let snap = await getDoc(doc(db, 'cities/tokyo'));
assert(snap.exists() && snap.data().population === 37400000, 'get');
assert(snap.data().tags.length === 2, 'array round-trip');
console.log('LITE GET ok:', snap.data().name);

await updateDoc(doc(db, 'cities/tokyo'), { population: increment(100), updated: serverTimestamp() });
snap = await getDoc(doc(db, 'cities/tokyo'));
assert(snap.data().population === 37400100, 'increment');
console.log('LITE UPDATE ok:', snap.data().population);

const big = await getDocs(query(
  collection(db, 'cities'), where('population', '>', 2000000), orderBy('population', 'desc'),
));
assert(big.docs.length === 1 && big.docs[0].data().name === 'Tokyo', 'query');
console.log('LITE QUERY ok:', big.docs.map(d => d.data().name));

const count = await getCount(collection(db, 'cities'));
assert(count.data().count === 2, `count ${count.data().count}`);
console.log('LITE COUNT ok:', count.data().count);

await deleteDoc(doc(db, 'cities/tokyo'));
snap = await getDoc(doc(db, 'cities/tokyo'));
assert(!snap.exists(), 'delete');
console.log('LITE DELETE ok');

// Rules over REST. The lite SDK sends credentials as an Authorization header
// on plain fetch() calls; the server has to carry them into the request it
// authorizes, or every REST call silently evaluates as `request.auth == null`
// no matter who is signed in.
const rulesProject = `js-lite-rules-${Date.now()}`;
const res = await fetch(`http://${host}:${port}/emulator/v1/projects/${rulesProject}:securityRules`, {
  method: 'PUT',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ rules: { files: [{ name: 'f.rules', content: `
    rules_version = '2';
    service cloud.firestore {
      match /databases/{db}/documents {
        match /{document=**} { allow read, write: if request.auth != null; }
      }
    }` }] } }),
});
assert(res.ok, `load rules: ${res.status}`);

const signedIn = getFirestore(initializeApp({ projectId: rulesProject }, 'lite-user'));
connectFirestoreEmulator(signedIn, host, port, { mockUserToken: { sub: 'alice', user_id: 'alice' } });
await setDoc(doc(signedIn, 'private/a'), { ok: true });
snap = await getDoc(doc(signedIn, 'private/a'));
assert(snap.exists() && snap.data().ok === true, 'signed-in REST write/read should be allowed');
console.log('LITE RULES ok: signed-in request is authorized');

const anonymous = getFirestore(initializeApp({ projectId: rulesProject }, 'lite-anon'));
connectFirestoreEmulator(anonymous, host, port);
let denied = false;
try {
  await getDoc(doc(anonymous, 'private/a'));
} catch (e) {
  denied = String(e).includes('permission') || String(e).includes('PERMISSION_DENIED');
}
assert(denied, 'anonymous REST read should be denied');
console.log('LITE RULES ok: anonymous request is denied');

console.log('ALL JS LITE CHECKS PASSED');
process.exit(0);
