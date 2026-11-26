/**
 * collection.test.js — Tests for PIR collection setup at the uploader.
 *
 * Run with:  node src/pir/collection.test.js
 *
 * Tests:
 *   1. setupCollection produces m equal-length records and n shares
 *   2. Index signature verifies with the uploader key, fails with a wrong key
 *   3. lookupSlot finds the right slot from H₃(O_j), -1 for an unknown tag
 *   4. decryptRecord round-trips every object (K known)
 *   5. decryptRecord rejects a record served from the wrong slot (G,j binding)
 *   6. Reconstructed K (from k shares) decrypts records — ties shamir to setup
 *   7. Variable-length objects all padded to a common record size
 */

import { randomBytes } from 'crypto';
import { generateKeyPair, aesDecrypt } from '../libp2p/crypto.js';
import { reconstruct } from './shamir.js';
import {
  setupCollection, verifyIndex, lookupSlot, decryptRecord, H3,
} from './collection.js';

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (e) { console.log(`  ✗  ${name}`); console.log(`     ${e.message}`); failed++; }
}
function assert(c, m) { if (!c) throw new Error(m || 'Assertion failed'); }

const G = 'test-collection-G';
const uploaderKey = generateKeyPair();
const uploaderPub = uploaderKey.publicKey;

function makeObjects() {
  return [
    Buffer.from('alpha object'),
    Buffer.from('a somewhat longer beta object with more bytes'),
    Buffer.from('gamma'),
    randomBytes(64),
    Buffer.from('epsilon'),
  ];
}

console.log('\n── PIR Collection Setup Tests ────────────────────────────────\n');

// 1. Shape
test('setupCollection produces m records and n shares', () => {
  const objects = makeObjects();
  const c = setupCollection(objects, { collectionId: G, k: 3, n: 5, uploaderKey });
  assert(c.records.length === objects.length, 'wrong record count');
  assert(c.shares.length === 5, 'wrong share count');
  const size = c.records[0].length;
  assert(c.records.every(r => r.length === size), 'records not equal length');
  assert(c.recordSize === size, 'recordSize mismatch');
});

// 2. Index signature
test('index signature verifies with uploader key, fails with wrong key', () => {
  const c = setupCollection(makeObjects(), { collectionId: G, k: 3, n: 5, uploaderKey });
  assert(verifyIndex(c.index, uploaderPub) === true, 'valid signature rejected');
  const other = generateKeyPair();
  assert(verifyIndex(c.index, other.publicKey) === false, 'wrong key accepted');
});

// 3. lookupSlot
test('lookupSlot maps H₃(O_j) → slot, -1 for unknown', () => {
  const objects = makeObjects();
  const c = setupCollection(objects, { collectionId: G, k: 3, n: 5, uploaderKey });
  for (let j = 0; j < objects.length; j++) {
    assert(lookupSlot(c.index, H3(objects[j])) === j, `slot mismatch at j=${j}`);
  }
  assert(lookupSlot(c.index, H3(Buffer.from('not in set'))) === -1, 'unknown tag not -1');
});

// 4. decryptRecord round-trip
test('decryptRecord recovers every object with known K', () => {
  const objects = makeObjects();
  const c = setupCollection(objects, { collectionId: G, k: 3, n: 5, uploaderKey });
  for (let j = 0; j < objects.length; j++) {
    const got = decryptRecord(c.records[j], c.key, { collectionId: G, slot: j });
    assert(got.equals(objects[j]), `object ${j} did not round-trip`);
  }
});

// 5. (G,j) binding — wrong slot rejected
test('decryptRecord rejects a record decrypted at the wrong slot', () => {
  const objects = makeObjects();
  const c = setupCollection(objects, { collectionId: G, k: 3, n: 5, uploaderKey });
  let threw = false;
  try { decryptRecord(c.records[0], c.key, { collectionId: G, slot: 1 }); }
  catch { threw = true; }
  assert(threw, 'wrong-slot decryption should fail the (G,j) binding');
});

// 6. Shamir-reconstructed K decrypts
test('K reconstructed from k shares decrypts the records', () => {
  const objects = makeObjects();
  const c = setupCollection(objects, { collectionId: G, k: 3, n: 6, uploaderKey });
  const K = reconstruct([c.shares[0], c.shares[2], c.shares[4]]); // any 3
  assert(K.equals(c.key), 'reconstructed K ≠ setup K');
  const got = decryptRecord(c.records[2], K, { collectionId: G, slot: 2 });
  assert(got.equals(objects[2]), 'decrypt with reconstructed K failed');
});

// 7. Variable length padding
test('variable-length objects pad to a single common record size', () => {
  const objects = [Buffer.alloc(1), Buffer.alloc(200), Buffer.alloc(50)];
  const c = setupCollection(objects, { collectionId: G, k: 2, n: 3, uploaderKey });
  const size = c.records[0].length;
  assert(c.records.every(r => r.length === size), 'padding did not equalize lengths');
});

console.log(`\n  ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
