/**
 * cid.test.js — Manual tests for the CID module
 *
 * Run with:  node src/cid/cid.test.js
 *
 * Tests:
 *   1. Same input always produces the same CID¹ (determinism)
 *   2. Different inputs produce different CIDs
 *   3. CID¹, CID², CID³ are all distinct for the same input
 *   4. CID string round-trips through cidFromString()
 *   5. CID¹ matches what IPFS Desktop would produce (manual verification step)
 */

import { tripleHash, cidFromString } from './cid.js';
import { hash, hmac } from './crypto.js';

// Fixed 32-byte HMAC key used throughout these tests. In production the owner
// generates a random k and shares it out-of-band alongside CID³.
const K = Buffer.alloc(32, 0xab);

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗  ${name}`);
    console.log(`     ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(a, b, message) {
  if (a !== b) throw new Error(message || `Expected ${a} === ${b}`);
}

function assertNotEqual(a, b, message) {
  if (a === b) throw new Error(message || `Expected ${a} !== ${b}`);
}

// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── CID Module Tests ──────────────────────────────────────────\n');

// 1. Determinism
test('Same content produces identical CID¹ every time', () => {
  const r1 = tripleHash('hello world', K);
  const r2 = tripleHash('hello world', K);
  assertEqual(r1.cid1.string, r2.cid1.string, 'CID¹ is not deterministic');
  assertEqual(r1.cid2.string, r2.cid2.string, 'CID² is not deterministic');
  assertEqual(r1.cid3.string, r2.cid3.string, 'CID³ is not deterministic');
});

// 2. Different inputs → different CIDs
test('Different content produces different CIDs', () => {
  const r1 = tripleHash('hello world', K);
  const r2 = tripleHash('goodbye world', K);
  assertNotEqual(r1.cid1.string, r2.cid1.string, 'CID¹ collision!');
  assertNotEqual(r1.cid3.string, r2.cid3.string, 'CID³ collision!');
});

// 3. CID¹, CID², CID³ are all distinct
test('CID¹, CID², CID³ are all distinct for the same input', () => {
  const { cid1, cid2, cid3 } = tripleHash('test object', K);
  assertNotEqual(cid1.string, cid2.string, 'CID¹ and CID² are the same!');
  assertNotEqual(cid2.string, cid3.string, 'CID² and CID³ are the same!');
  assertNotEqual(cid1.string, cid3.string, 'CID¹ and CID³ are the same!');
});

// 4. CID string round-trips
test('CID string can be parsed back into a CID', () => {
  const { cid1 } = tripleHash('round trip test', K);
  const reparsed  = cidFromString(cid1.string);
  assertEqual(
    cid1.digest.toString('hex'),
    reparsed.digest.toString('hex'),
    'Digest changed after round-trip'
  );
  assertEqual(cid1.string, reparsed.string, 'String changed after round-trip');
});

// 5. CID chain integrity — h3 = HMAC_k(H(H(data)))
test('Triple hash chain: HMAC_k(H(H(data))) matches CID³ digest', () => {
  const data = Buffer.from('chain integrity');
  const { h1, h2, h3, cid3 } = tripleHash(data, K);

  // Verify the digest lengths and that h3 matches the digest stored in CID³
  assert(h1.length === 32, 'h1 length is wrong');
  assert(h2.length === 32, 'h2 length is wrong');
  assert(h3.length === 32, 'h3 length is wrong');
  assert(h3.equals(cid3.digest), 'h3 does not match cid3 digest');

  // Verify the chain manually: h1 = H(data), h2 = H(h1), h3 = HMAC_k(h2)
  const h1check = hash(data);
  const h2check = hash(h1check);
  const h3check = hmac(K, h2check);
  assert(h1.equals(h1check), 'h1 does not match H(data)');
  assert(h2.equals(h2check), 'h2 does not match H(H(data))');
  assert(h3.equals(h3check), 'h3 does not match HMAC_k(H(H(data)))');
});

// 5b. CID³ depends on the key — a different k yields a different CID³
test('Different HMAC keys produce different CID³ for identical content', () => {
  const data = Buffer.from('key sensitivity');
  const withK1 = tripleHash(data, Buffer.alloc(32, 0x01));
  const withK2 = tripleHash(data, Buffer.alloc(32, 0x02));
  assertEqual(withK1.cid1.string, withK2.cid1.string, 'CID¹ must not depend on k');
  assertEqual(withK1.cid2.string, withK2.cid2.string, 'CID² must not depend on k');
  assertNotEqual(withK1.cid3.string, withK2.cid3.string, 'CID³ must depend on k');
});

// 6. CID starts with 'b' (base32 multibase prefix)
test('All CIDs start with multibase prefix "b" (base32)', () => {
  const { cid1, cid2, cid3 } = tripleHash('prefix test', K);
  assert(cid1.string.startsWith('b'), 'CID¹ missing base32 prefix');
  assert(cid2.string.startsWith('b'), 'CID² missing base32 prefix');
  assert(cid3.string.startsWith('b'), 'CID³ missing base32 prefix');
});

// 7. Buffer and string inputs produce the same CID
test('Buffer and string inputs produce identical CIDs', () => {
  const r1 = tripleHash('same content', K);
  const r2 = tripleHash(Buffer.from('same content'), K);
  assertEqual(r1.cid1.string, r2.cid1.string, 'Buffer vs string CID¹ mismatch');
});

// ─────────────────────────────────────────────────────────────────────────────

console.log(`\n── Results: ${passed} passed, ${failed} failed ─────────────────────────────────\n`);

// Print sample output so you can compare with IPFS Desktop
console.log('── Sample CIDs for "hello world" ─────────────────────────────\n');
const sample = tripleHash('hello world', K);
console.log('  CID¹ (published)  :', sample.cid1.string);
console.log('  CID² (SECRET)     :', sample.cid2.string);
console.log('  CID³ (published)  :', sample.cid3.string);
console.log('  h1 (raw, hex)     :', sample.h1.toString('hex'));
console.log('  h2 (raw, hex)     :', sample.h2.toString('hex'));
console.log('  h3 (raw, hex)     :', sample.h3.toString('hex'));
console.log();
console.log('  To verify CID¹ against IPFS Desktop:');
console.log('    echo -n "hello world" | ipfs add --only-hash --cid-version 1 -');
console.log('  The multihash portion of CID¹ above should match.\n');
