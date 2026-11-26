/**
 * shamir.test.js — Tests for Shamir (k, n) secret sharing.
 *
 * Run with:  node src/pir/shamir.test.js
 *
 * Tests:
 *   1. Round-trip: split then reconstruct returns the exact secret
 *   2. Any k-subset of shares reconstructs; different subsets agree
 *   3. k-1 shares reveal nothing (reconstruct ≠ secret, effectively random)
 *   4. Reconstruction with more than k shares still works
 *   5. Share wire encoding round-trips (shareToBuffer / shareFromBuffer)
 *   6. split() rejects bad parameters (k<2, k>n, oversized secret)
 *   7. reconstruct() rejects duplicate / x=0 coordinates
 *   8. Works for a maximal 256-bit secret (all-0xFF)
 */

import { randomBytes } from 'crypto';
import {
  split, reconstruct, shareToBuffer, shareFromBuffer, PRIME,
} from './shamir.js';

let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (e) { console.log(`  ✗  ${name}`); console.log(`     ${e.message}`); failed++; }
}
function assert(c, m) { if (!c) throw new Error(m || 'Assertion failed'); }

/** Pick a specific k-subset of shares by index. */
const pick = (shares, idxs) => idxs.map(i => shares[i]);

console.log('\n── Shamir Secret Sharing Tests ───────────────────────────────\n');

// 1. Round-trip
test('split → reconstruct returns the exact secret', () => {
  const secret = randomBytes(32);
  const shares = split(secret, 3, 5);
  assert(shares.length === 5, 'expected 5 shares');
  const back = reconstruct(pick(shares, [0, 1, 2]));
  assert(back.equals(secret), 'reconstructed secret differs');
});

// 2. Any k-subset reconstructs and all subsets agree
test('any k-subset reconstructs to the same secret', () => {
  const secret = randomBytes(32);
  const shares = split(secret, 3, 6);
  const a = reconstruct(pick(shares, [0, 1, 2]));
  const b = reconstruct(pick(shares, [3, 4, 5]));
  const c = reconstruct(pick(shares, [0, 2, 4]));
  assert(a.equals(secret) && b.equals(secret) && c.equals(secret), 'subsets disagree');
});

// 3. k-1 shares reveal nothing
test('k-1 shares do not reconstruct the secret', () => {
  const secret = randomBytes(32);
  const shares = split(secret, 3, 5);
  // Only 2 shares available (k=3). Interpolating at x=0 over 2 points gives
  // some field element unrelated to the true secret.
  const guess = reconstruct(pick(shares, [0, 1]));
  assert(!guess.equals(secret), 'k-1 shares should NOT reveal the secret');
});

// 4. More than k shares still works
test('reconstruction with more than k shares works', () => {
  const secret = randomBytes(32);
  const shares = split(secret, 3, 7);
  const back = reconstruct(pick(shares, [0, 1, 2, 3, 4])); // 5 > k=3
  assert(back.equals(secret), 'over-provisioned reconstruct failed');
});

// 5. Share wire encoding round-trips
test('share encodes/decodes through a 65-byte buffer', () => {
  const shares = split(randomBytes(32), 2, 3);
  const buf = shareToBuffer(shares[0]);
  assert(buf.length === 65, 'share buffer must be 65 bytes (y needs 33 bytes: p = 2^256+297)');
  const back = shareFromBuffer(buf);
  assert(back.x === shares[0].x && back.y === shares[0].y, 'share round-trip mismatch');
});

test('share wire format preserves y ≥ 2^256 (no top-nibble truncation)', () => {
  // y = f(x) mod p can exceed 2^256 (p = 2^256 + 297). A 64-byte wire format
  // would silently drop the leading nibble and round-trip to a WRONG y.
  const bigY = (1n << 256n) + 100n;   // in [2^256, p)
  const back = shareFromBuffer(shareToBuffer({ x: 1n, y: bigY }));
  assert(back.y === bigY, 'y ≥ 2^256 must survive the wire round-trip exactly');
});

// 6. Parameter validation
test('split rejects invalid parameters', () => {
  let threw = 0;
  try { split(randomBytes(32), 1, 5); } catch { threw++; }  // k<2
  try { split(randomBytes(32), 6, 5); } catch { threw++; }  // k>n
  try { split(randomBytes(33), 2, 3); } catch { threw++; }  // secret too big
  assert(threw === 3, `expected 3 rejections, got ${threw}`);
});

// 7. reconstruct validation
test('reconstruct rejects duplicate and x=0 coordinates', () => {
  const shares = split(randomBytes(32), 2, 3);
  let threw = 0;
  try { reconstruct([shares[0], shares[0]]); } catch { threw++; }     // duplicate
  try { reconstruct([{ x: 0n, y: 5n }, shares[1]]); } catch { threw++; } // x=0
  assert(threw === 2, `expected 2 rejections, got ${threw}`);
});

// 8. Maximal 256-bit secret
test('handles a maximal 256-bit secret (0xFF…FF < p)', () => {
  const secret = Buffer.alloc(32, 0xff);
  assert((1n << 256n) - 1n < PRIME, 'prime must exceed 2²⁵⁶-1');
  const shares = split(secret, 4, 8);
  const back = reconstruct(pick(shares, [1, 3, 5, 7]));
  assert(back.equals(secret), 'max secret round-trip failed');
});

console.log(`\n  ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
