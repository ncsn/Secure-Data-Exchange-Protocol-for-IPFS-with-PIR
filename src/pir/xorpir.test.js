/**
 * xorpir.test.js — Tests for XOR-PIR query splitting and answering.
 *
 * Run with:  node src/pir/xorpir.test.js
 *
 * Tests:
 *   1. k query shares XOR back to the unit vector e_j
 *   2. End-to-end: splitQuery → answerQuery (per server) → combineAnswers = C_j
 *   3. Privacy: each individual share is NOT the unit vector (looks random)
 *   4. Works across a range of (m, j, k) including j at the boundaries
 *   5. answerQuery rejects unequal-length records
 *   6. splitQuery rejects out-of-range j and k < 2
 *   7. Padding bits beyond m are always zero (no phantom record selection)
 *   8. answerQuery rejects a wrong-length query share
 *   9. splitQuery supports k > 256 (randomIndex no longer capped at 256)
 */

import { randomBytes } from 'crypto';
import {
  splitQuery, answerQuery, combineAnswers, unitVector, vectorBytes, getBit, xorBuf,
} from './xorpir.js';

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (e) { console.log(`  ✗  ${name}`); console.log(`     ${e.message}`); failed++; }
}
function assert(c, m) { if (!c) throw new Error(m || 'Assertion failed'); }

/** XOR a list of equal-length buffers. */
function xorAll(bufs) {
  let acc = Buffer.alloc(bufs[0].length);
  for (const b of bufs) acc = xorBuf(acc, b);
  return acc;
}

console.log('\n── XOR-PIR Tests ─────────────────────────────────────────────\n');

// 1. Shares XOR back to e_j
test('k query shares XOR back to the unit vector', () => {
  const m = 20, j = 7, k = 3;
  const shares = splitQuery(m, j, k);
  assert(shares.length === k, 'wrong number of shares');
  const combined = xorAll(shares);
  assert(combined.equals(unitVector(m, j)), 'shares do not XOR to e_j');
});

// 2. Full retrieval round-trip
test('end-to-end retrieval returns the correct record', () => {
  const m = 16, k = 4, recordSize = 48;
  const records = Array.from({ length: m }, () => randomBytes(recordSize));
  const j = 11;
  const shares = splitQuery(m, j, k);
  const answers = shares.map(q => answerQuery(records, q)); // each "server"
  const recovered = combineAnswers(answers);
  assert(recovered.equals(records[j]), 'recovered record ≠ target record');
});

// 3. Privacy — no individual share equals the plaintext choice
test('individual shares do not reveal the target (not the unit vector)', () => {
  const m = 24, j = 5, k = 3;
  const e = unitVector(m, j);
  const shares = splitQuery(m, j, k);
  const anyEqualsUnit = shares.some(s => s.equals(e));
  assert(!anyEqualsUnit, 'a share leaked the unit vector');
  // A share should, with overwhelming probability, have many bits set.
  const popcount = shares.map(s => s.reduce((n, byte) => {
    let c = 0; for (let b = 0; b < 8; b++) c += (byte >> b) & 1; return n + c;
  }, 0));
  assert(popcount.some(p => p > 1), 'shares look suspiciously sparse');
});

// 4. Range of parameters incl. boundary j
test('works for boundary indices and varying k', () => {
  for (const [m, k] of [[8, 2], [33, 5], [100, 3]]) {
    for (const j of [0, m - 1, Math.floor(m / 2)]) {
      const records = Array.from({ length: m }, (_, t) => {
        const r = Buffer.alloc(16); r.writeUInt32BE(t + 1, 0); return r;
      });
      const answers = splitQuery(m, j, k).map(q => answerQuery(records, q));
      assert(combineAnswers(answers).equals(records[j]), `failed m=${m} j=${j} k=${k}`);
    }
  }
});

// 5. Unequal record lengths rejected
test('answerQuery rejects unequal-length records', () => {
  let threw = false;
  try { answerQuery([Buffer.alloc(8), Buffer.alloc(9)], Buffer.alloc(vectorBytes(2))); }
  catch { threw = true; }
  assert(threw, 'expected rejection for ragged records');
});

// 6. Parameter validation
test('splitQuery rejects out-of-range j and k < 2', () => {
  let threw = 0;
  try { splitQuery(10, 10, 3); } catch { threw++; }  // j == m
  try { splitQuery(10, -1, 3); } catch { threw++; }  // j < 0
  try { splitQuery(10, 3, 1); } catch { threw++; }   // k < 2
  assert(threw === 3, `expected 3 rejections, got ${threw}`);
});

// 7. Tail padding bits are zero
test('padding bits beyond m are zero in every share', () => {
  const m = 17, k = 4;                 // 17 bits → 3 bytes, 7 padding bits
  const shares = splitQuery(m, 9, k);
  const len = vectorBytes(m);
  for (const s of shares) {
    assert(s.length === len, 'share has wrong byte length');
    for (let t = m; t < len * 8; t++) assert(getBit(s, t) === 0, `padding bit ${t} set`);
  }
});

// 8. Wrong-length query share rejected
test('answerQuery rejects a wrong-length query share', () => {
  const records = Array.from({ length: 10 }, () => randomBytes(8)); // needs ⌈10/8⌉=2 bytes
  let threw = 0;
  try { answerQuery(records, Buffer.alloc(vectorBytes(10) + 1)); } catch { threw++; } // too long
  try { answerQuery(records, Buffer.alloc(vectorBytes(10) - 1)); } catch { threw++; } // too short
  assert(threw === 2, `expected 2 rejections for bad q length, got ${threw}`);
});

// 9. k > 256 works end-to-end (randomIndex rejection sampling over >1 byte)
test('splitQuery supports k > 256', () => {
  const m = 12, k = 300, j = 5;
  const records = Array.from({ length: m }, (_, t) => {
    const r = Buffer.alloc(8); r.writeUInt32BE(t + 1, 0); return r;
  });
  const shares = splitQuery(m, j, k);
  assert(shares.length === k, 'wrong number of shares for k=300');
  const answers = shares.map(q => answerQuery(records, q));
  assert(combineAnswers(answers).equals(records[j]), 'k>256 retrieval failed');
});

console.log(`\n  ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
