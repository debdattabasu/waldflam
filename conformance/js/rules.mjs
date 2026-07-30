// Security-rules enforcement, driven the way @firebase/rules-unit-testing
// drives it: load rules over the emulator admin API, then exercise allow
// and deny paths with an unauthenticated client, a user client, and an
// admin (Bearer owner) client.
import { initializeApp } from 'firebase/app';
import {
  getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, deleteDoc,
  collection, getDocs,
} from 'firebase/firestore';

const host = process.env.WALDFLAM_HOST || '127.0.0.1';
const port = parseInt(process.env.WALDFLAM_PORT || '8080', 10);
const projectId = `js-rules-${Date.now()}`;

const RULES = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Anyone may read public docs; nobody may write them.
    match /public/{doc} {
      allow read: if true;
    }
    // Owner-only documents — the canonical idiom.
    match /users/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    // Requires a role document to exist (exercises get()).
    match /admin/{doc} {
      allow read: if exists(/databases/$(database)/documents/roles/$(request.auth.uid));
    }
  }
}`;

const assert = (cond, msg) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } };
const denied = async (p, what) => {
  try { await p; console.error(`FAIL: ${what} should have been denied`); process.exit(1); }
  catch (e) {
    assert(e.code === 'permission-denied', `${what}: expected permission-denied, got ${e.code}`);
  }
};
const allowed = async (p, what) => {
  try { return await p; } catch (e) { console.error(`FAIL: ${what} should have been allowed: ${e}`); process.exit(1); }
};

// 1. Load rules through the admin API.
const res = await fetch(`http://${host}:${port}/emulator/v1/projects/${projectId}:securityRules`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ rules: { files: [{ name: 'firestore.rules', content: RULES }] } }),
});
assert(res.ok, `securityRules PUT failed: ${res.status} ${await res.text()}`);
console.log('RULES ok: loaded via admin API');

// A malformed ruleset must be rejected.
const bad = await fetch(`http://${host}:${port}/emulator/v1/projects/${projectId}:securityRules`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ rules: { files: [{ name: 'f', content: 'service cloud.firestore {' }] } }),
});
assert(!bad.ok, 'malformed rules should be rejected');
console.log('RULES ok: malformed ruleset rejected');

// 2. Admin client (Bearer owner) bypasses rules — seed data with it.
const adminApp = initializeApp({ projectId }, 'admin');
const adminDb = getFirestore(adminApp);
connectFirestoreEmulator(adminDb, host, port, { mockUserToken: 'owner' });
await allowed(setDoc(doc(adminDb, 'public/hello'), { msg: 'hi' }), 'admin seed public');
await allowed(setDoc(doc(adminDb, 'users/alice'), { name: 'Alice' }), 'admin seed alice');
await allowed(setDoc(doc(adminDb, 'users/bob'), { name: 'Bob' }), 'admin seed bob');
await allowed(setDoc(doc(adminDb, 'roles/alice'), { admin: true }), 'admin seed role');
await allowed(setDoc(doc(adminDb, 'admin/secret'), { s: 1 }), 'admin seed secret');
console.log('RULES ok: admin (Bearer owner) bypasses rules');

// 3. Unauthenticated client.
const anonApp = initializeApp({ projectId }, 'anon');
const anonDb = getFirestore(anonApp);
connectFirestoreEmulator(anonDb, host, port);
const pub = await allowed(getDoc(doc(anonDb, 'public/hello')), 'anon read public');
assert(pub.data().msg === 'hi', 'public payload');
console.log('RULES ok: anonymous read of public doc allowed');

await denied(getDoc(doc(anonDb, 'users/alice')), 'anon read of user doc');
await denied(setDoc(doc(anonDb, 'public/hello'), { msg: 'nope' }), 'anon write to public');
console.log('RULES ok: anonymous denied on protected paths');

// 4. Authenticated user (unsigned JWT via mockUserToken).
const aliceApp = initializeApp({ projectId }, 'alice');
const aliceDb = getFirestore(aliceApp);
connectFirestoreEmulator(aliceDb, host, port, { mockUserToken: { sub: 'alice', user_id: 'alice' } });

const mine = await allowed(getDoc(doc(aliceDb, 'users/alice')), 'alice reads own doc');
assert(mine.data().name === 'Alice', 'own doc payload');
await allowed(setDoc(doc(aliceDb, 'users/alice'), { name: 'Alice2' }), 'alice writes own doc');
console.log('RULES ok: owner allowed on own document');

await denied(getDoc(doc(aliceDb, 'users/bob')), "alice reads bob's doc");
await denied(setDoc(doc(aliceDb, 'users/bob'), { name: 'hacked' }), "alice writes bob's doc");
console.log("RULES ok: owner denied on another user's document");

// 5. get()/exists() against the datastore inside a rule.
await allowed(getDoc(doc(aliceDb, 'admin/secret')), 'alice reads admin (has role)');
console.log('RULES ok: exists() lookup granted access');

const bobApp = initializeApp({ projectId }, 'bob');
const bobDb = getFirestore(bobApp);
connectFirestoreEmulator(bobDb, host, port, { mockUserToken: { sub: 'bob', user_id: 'bob' } });
await denied(getDoc(doc(bobDb, 'admin/secret')), 'bob reads admin (no role)');
console.log('RULES ok: exists() lookup denied access');

// 6. Query (list) enforcement.
await allowed(getDocs(collection(anonDb, 'public')), 'anon lists public');
await denied(getDocs(collection(anonDb, 'users')), 'anon lists users');
console.log('RULES ok: list enforcement on queries');

// 7. Clear data admin endpoint.
const clear = await fetch(
  `http://${host}:${port}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
  { method: 'DELETE' },
);
assert(clear.ok, `clearData failed: ${clear.status}`);
const gone = await getDoc(doc(adminDb, 'public/hello'));
assert(!gone.exists(), 'data should be cleared');
console.log('RULES ok: clearData admin endpoint');

console.log('ALL RULES CHECKS PASSED');
process.exit(0);
