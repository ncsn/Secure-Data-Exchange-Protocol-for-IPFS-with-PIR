/**
 * xorpir.js — XOR-based Private Information Retrieval query splitting (paper §III,
 * "PIR-kérésrészek" and "A privát lekérés üzenetváltása").
 *
 * The client U wants object j out of m without any single server learning j.
 * It expresses the choice as a unit vector e_j ∈ {0,1}^m (only bit j is 1) and
 * splits it into k query shares q_i:
 *
 *   - k-1 of the shares are independent, uniform random m-bit vectors
 *   - the last share is q_{i*} = e_j ⊕ (⊕ of the other k-1 shares)
 *
 * so that  ⊕_{i∈S} q_i = e_j. Each server N_i sees only its own uniform-looking
 * q_i and answers with the XOR of the records its share selects:
 *
 *   R_i = ⊕_{t : q_i[t]=1} C_t
 *
 * The client XORs the k answers to recover the single target record:
 *
 *   ⊕_{i∈S} R_i = ⊕_t (⊕_i q_i[t]) · C_t = C_j
 *
 * Any coalition of ≤ k-1 servers sees only uniform random query vectors, so the
 * joint distribution of their shares is identical for every j — they learn
 * nothing about which object was requested.
 *
 * Query vectors are stored as packed bit buffers (ceil(m/8) bytes). Records are
 * equal-length buffers (the padded AES-GCM records C_t from collection setup).
 */

import { randomBytes } from 'crypto';

/** Bytes needed to pack an m-bit vector. */
export function vectorBytes(m) {
  return Math.ceil(m / 8);
}

/** Read bit t (0-indexed) from a packed bit buffer. MSB-first within each byte. */
function getBit(buf, t) {
  return (buf[t >> 3] >> (7 - (t & 7))) & 1;
}

/** Set bit t (0-indexed) in a packed bit buffer. */
function setBit(buf, t) {
  buf[t >> 3] |= 1 << (7 - (t & 7));
}

/** XOR two equal-length buffers into a fresh buffer. */
function xorBuf(a, b) {
  if (a.length !== b.length) throw new Error('xorpir: buffer length mismatch');
  const out = Buffer.allocUnsafe(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * randomIndex(k) → integer in [0, k)
 * Uniform, bias-free selection via rejection sampling. A plain `randomByte % k`
 * is biased whenever k does not divide the sample space, which would make some
 * balancing positions i* slightly more likely and weaken the info-theoretic
 * uniformity of the query shares. We draw enough bytes to cover k, then reject
 * any draw in the non-uniform tail. Supports arbitrarily large k (k servers is
 * small in practice, but the bound must not silently cap the protocol).
 */
function randomIndex(k) {
  if (!Number.isInteger(k) || k <= 0) throw new Error('xorpir: randomIndex requires k ≥ 1');
  if (k === 1) return 0;
  // Bytes needed so the sample space ≥ k (so a uniform sub-range of size k exists).
  const nbytes = Math.ceil(Math.log2(k) / 8);
  const space = 2 ** (8 * nbytes);
  const limit = space - (space % k);   // largest multiple of k ≤ sample space
  for (;;) {
    let v = 0;
    const bytes = randomBytes(nbytes);
    for (let i = 0; i < nbytes; i++) v = v * 256 + bytes[i];
    if (v < limit) return v % k;
  }
}

/**
 * unitVector(m, j) → Buffer
 * Packed m-bit vector e_j with only bit j set (the local, plaintext choice).
 */
export function unitVector(m, j) {
  if (!Number.isInteger(m) || m <= 0) throw new Error('xorpir: m must be a positive integer');
  if (!Number.isInteger(j) || j < 0 || j >= m) throw new Error('xorpir: j out of range [0, m)');
  const v = Buffer.alloc(vectorBytes(m));
  setBit(v, j);
  return v;
}

/**
 * splitQuery(m, j, k) → Array<Buffer>
 *
 * Produces k query shares whose XOR is the unit vector e_j. The index i* of the
 * "balancing" share is chosen at random among the k so that no fixed position
 * is special on the wire.
 *
 * @param {number} m — number of objects in the collection
 * @param {number} j — target object index (0-based)
 * @param {number} k — number of servers / query shares (≥ 2)
 * @returns {Array<Buffer>} k packed m-bit query vectors
 */
export function splitQuery(m, j, k) {
  if (!Number.isInteger(k) || k < 2) throw new Error('xorpir: k must be ≥ 2');
  const e = unitVector(m, j);
  const len = vectorBytes(m);

  // k-1 uniform random shares; the k-th balances them to e_j.
  const shares = [];
  for (let i = 0; i < k; i++) shares.push(randomBytes(len));

  const iStar = randomIndex(k);                  // random balancing position (unbiased)
  let acc = Buffer.from(e);                      // start from e_j
  for (let i = 0; i < k; i++) {
    if (i === iStar) continue;
    acc = xorBuf(acc, shares[i]);                // fold in the random shares
  }
  shares[iStar] = acc;                           // q_{i*} = e_j ⊕ (⊕ others)

  // Mask off any padding bits beyond m in every share so trailing bits stay 0
  // and the XOR identity holds exactly at the record level.
  maskTail(shares, m);
  return shares;
}

/** Zero out bits [m, 8·len) in each share so padding never selects a record. */
function maskTail(shares, m) {
  const len = vectorBytes(m);
  const totalBits = len * 8;
  for (let t = m; t < totalBits; t++) {
    for (const s of shares) s[t >> 3] &= ~(1 << (7 - (t & 7)));
  }
}

/**
 * answerQuery(records, q) → Buffer
 *
 * Server-side: R_i = XOR of every record C_t where q[t] = 1. Returns an
 * all-zero buffer of recordSize if the query selects nothing.
 *
 * @param {Array<Buffer>} records — m equal-length records C_0..C_{m-1}
 * @param {Buffer}        q       — this server's packed m-bit query share
 * @returns {Buffer} the masked partial answer R_i (recordSize bytes)
 */
export function answerQuery(records, q) {
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error('xorpir: records must be a non-empty array');
  }
  // The query share must be exactly the packed bit-vector for this replica's m
  // records (⌈m/8⌉ bytes). A short q would under-read records (getBit returns 0
  // past its end, silently answering a different query); a long q is malformed.
  const need = vectorBytes(records.length);
  if (!Buffer.isBuffer(q) || q.length !== need) {
    throw new Error(`xorpir: query length mismatch (expected ${need} bytes for ${records.length} records)`);
  }
  const recordSize = records[0].length;
  for (const r of records) {
    if (r.length !== recordSize) throw new Error('xorpir: records must be equal length');
  }
  let acc = Buffer.alloc(recordSize);
  for (let t = 0; t < records.length; t++) {
    if (getBit(q, t)) acc = xorBuf(acc, records[t]);
  }
  return acc;
}

/**
 * combineAnswers(answers) → Buffer
 *
 * Client-side: XOR the k partial answers to recover the target record C_j.
 *
 * @param {Array<Buffer>} answers — k partial answers R_i (equal length)
 * @returns {Buffer} the recovered record C_j
 */
export function combineAnswers(answers) {
  if (!Array.isArray(answers) || answers.length < 2) {
    throw new Error('xorpir: need at least 2 answers to combine');
  }
  let acc = Buffer.from(answers[0]);
  for (let i = 1; i < answers.length; i++) acc = xorBuf(acc, answers[i]);
  return acc;
}

export { getBit, xorBuf };
