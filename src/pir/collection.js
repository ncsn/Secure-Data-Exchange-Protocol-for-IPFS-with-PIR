/**
 * collection.js — PIR collection setup at the uploader P (paper §III,
 * "Előkészítés a feltöltőnél (setup)").
 *
 * The uploader turns a set of plaintext objects O_1..O_m into a privacy-preserving
 * collection that k-of-n servers can serve without any single server learning
 * which object a client fetched:
 *
 *   1. Encrypted records.  Fresh random 256-bit AES key K. Each object is padded
 *      to a common length and AES-256-GCM encrypted with a per-record nonce ν_j
 *      and associated data (G, j):
 *          C_j = ν_j ‖ enc_K(ν_j, pad(O_j); G, j)
 *      Every C_j has the identical length (required for XOR-PIR).
 *
 *   2. Secret sharing.  K is split with Shamir (k, n); server N_i receives share s_i.
 *
 *   3. Index & publication.  Every server gets the same replica D = (C_1..C_m) and a
 *      signed index I_G mapping the triple-hash tag h_j = H₃(O_j) = H(H(H(O_j)))
 *      to slot j. The signed metadata also carries G, k, n, m and the record size.
 *
 * H₃ here is the *unkeyed* triple SHA-256 tag from the paper's index step — distinct
 * from the keyed CID³ = HMAC_k(CID²) used for DHT discovery elsewhere in the project.
 */

import { randomBytes } from 'crypto';
import { hash } from '../cid/crypto.js';
import { aesEncrypt, aesDecrypt, sign, verify, randomAesKey, GCM_IV_BYTES } from '../libp2p/crypto.js';
import { split as shamirSplit } from './shamir.js';

/** H₃(O) = H(H(H(O))) — unkeyed triple SHA-256 tag used in the signed index. */
export function tripleTag(obj) {
  return hash(hash(hash(obj)));
}

/**
 * packetCid(records) → string (hex)
 * The paper's "packet CID": a content address pinning the exact replica
 * D = (C_1‖…‖C_m) the servers must store. Derived as H over the concatenation
 * of every record, so any server whose stored replica differs from the signed
 * one is detectable. Length-prefixing each record keeps the hash unambiguous.
 */
export function packetCid(records) {
  const parts = [];
  for (const r of records) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(r.length, 0);
    parts.push(len, r);
  }
  return hash(Buffer.concat(parts)).toString('hex');
}

// ── Padding (length-prefixed, to a common record length) ─────────────────────────
//
// pad(O) = UInt32BE(len(O)) ‖ O ‖ zero-fill, so the original length survives inside
// the encrypted field and every padded object reaches the same size.

const LEN_PREFIX_BYTES = 4;

function padObject(obj, paddedLen) {
  if (obj.length + LEN_PREFIX_BYTES > paddedLen) {
    throw new Error('collection: object longer than padded record length');
  }
  const out = Buffer.alloc(paddedLen);
  out.writeUInt32BE(obj.length, 0);
  obj.copy(out, LEN_PREFIX_BYTES);
  return out;
}

function unpadObject(padded) {
  const len = padded.readUInt32BE(0);
  if (LEN_PREFIX_BYTES + len > padded.length) {
    throw new Error('collection: corrupt padding length');
  }
  return padded.slice(LEN_PREFIX_BYTES, LEN_PREFIX_BYTES + len);
}

/** Associated data binding each record to its collection, slot and nonce: (G, j, ν_j). */
function aad(collectionId, j, nonce) {
  return Buffer.concat([
    Buffer.from(collectionId, 'utf8'),
    Buffer.from(`:${j}:`, 'utf8'),
    nonce,
  ]);
}

/**
 * Per-record nonce length (ν_j). ν_j IS the AES-GCM nonce (not merely AAD), so it
 * is exactly GCM_IV_BYTES long. It is bound into the (G,j,ν_j) AAD and prepended
 * to the record; aesEncrypt stores the same bytes as the GCM IV, so decryptRecord
 * slices ν_j off the front as AAD while aesDecrypt reads the matching IV from enc.
 */
const NONCE_BYTES = GCM_IV_BYTES;

// ── Setup ────────────────────────────────────────────────────────────────────

/**
 * setupCollection(objects, { collectionId, k, n, uploaderKey, nodes }) → collection
 *
 * @param {Array<Buffer>} objects    — plaintext objects O_1..O_m
 * @param {object}        opts
 * @param {string}        opts.collectionId  — G, the collection identifier
 * @param {number}        opts.k      — Shamir threshold / number of serving nodes
 * @param {number}        opts.n      — total number of server nodes
 * @param {{privateKey, publicKey}} opts.uploaderKey — P's signing key pair
 * @param {Array<{address, publicKey}>} [opts.nodes] — optional n serving nodes, in
 *        server-index order (nodes[i-1] → N_i). When supplied, the signed index
 *        binds each node's address and SPKI verification key plus the packet CID,
 *        so a client can reject a server that presents a key P never signed for.
 *        Omit for a key-agnostic index (backward compatible).
 * @returns {{
 *   records: Buffer[],               // D = (C_1..C_m), replicated to every server
 *   recordSize: number,
 *   index: object,                   // signed I_G (metadata + signature)
 *   shares: Array<{x,y}>,            // one Shamir share per server (index i → N_i)
 *   key: Buffer                      // K — kept by P only (returned for testing)
 * }}
 */
export function setupCollection(objects, { collectionId, k, n, uploaderKey, nodes }) {
  if (!Array.isArray(objects) || objects.length === 0) {
    throw new Error('collection: objects must be a non-empty array');
  }
  if (!collectionId) throw new Error('collection: collectionId (G) is required');
  if (!uploaderKey?.privateKey || !uploaderKey?.publicKey) {
    throw new Error('collection: uploaderKey with { privateKey, publicKey } is required');
  }
  if (nodes !== undefined) {
    if (!Array.isArray(nodes) || nodes.length !== n) {
      throw new Error('collection: nodes, when supplied, must be an array of length n');
    }
    for (const nd of nodes) {
      if (!nd?.publicKey) throw new Error('collection: each node needs a publicKey');
    }
  }
  const m = objects.length;

  // 1. Fresh AES key and common record length.
  const K = randomAesKey();
  const maxObj = Math.max(...objects.map(o => o.length));
  const paddedLen = maxObj + LEN_PREFIX_BYTES;

  // 2. Encrypt each object: C_j = ν_j ‖ enc_K(ν_j, pad(O_j); G,j).
  //    ν_j is the actual AES-GCM nonce (passed explicitly to aesEncrypt), and is
  //    also bound as part of the (G, j, ν_j) associated data. The record prepends
  //    ν_j in the clear; because aesEncrypt stores that same ν_j as enc's IV, the
  //    record literally is ν_j ‖ enc_K(ν_j, ...). The GCM tag then fails if a
  //    record is moved to a different slot/collection or its nonce is altered.
  const records = [];
  const tags = [];
  for (let j = 0; j < m; j++) {
    const padded = padObject(objects[j], paddedLen);
    const nonce  = randomBytes(NONCE_BYTES);                     // ν_j (= GCM nonce)
    const enc    = aesEncrypt(padded, K, aad(collectionId, j, nonce), nonce);
    records.push(Buffer.concat([nonce, enc]));                   // ν_j ‖ enc_K(...)
    tags.push(tripleTag(objects[j]));
  }

  // Every record must be identical length for XOR-PIR; aesEncrypt is deterministic
  // in length for equal-length plaintext, so this holds, but assert it.
  const recordSize = records[0].length;
  for (const r of records) {
    if (r.length !== recordSize) throw new Error('collection: record length mismatch');
  }

  // 3. Shamir-split K into n shares (one per server).
  const shares = shamirSplit(K, k, n);

  // 4. Build and sign the index I_G.
  const entries = tags.map((tag, j) => ({ tag: tag.toString('hex'), slot: j }));
  const meta = {
    collectionId,
    k, n, m,
    recordSize,
    uploaderPublicKey: uploaderKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    entries,
  };
  // Optional node-key binding (paper §III signed metadata: "the packet CID, record
  // size, threshold, and node addresses and signature verification keys"). Present
  // only when the caller supplies `nodes`, keeping the index backward compatible.
  if (nodes !== undefined) {
    meta.packetCid = packetCid(records);
    meta.nodes = nodes.map(nd => ({
      address: nd.address ?? null,
      verifyKey: nd.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    }));
  }
  const metaBytes = Buffer.from(JSON.stringify(meta), 'utf8');
  const signature = sign(metaBytes, uploaderKey.privateKey).toString('base64');
  // Store the exact signed bytes alongside the parsed meta so verifyIndex checks
  // the signature against what was actually signed — not a re-serialization whose
  // key order could differ across engines and spuriously fail verification.
  const index = { meta, metaBytes: metaBytes.toString('base64'), signature };

  return { records, recordSize, index, shares, key: K };
}

/**
 * verifyIndex(index, uploaderPublicKey) → boolean
 * Clients and servers verify I_G's signature with P's known verification key.
 *
 * Besides the signature, this binds the live `index.meta` object to the exact
 * bytes that were signed: an attacker who keeps a valid (metaBytes, signature)
 * pair but swaps in a different `index.meta` (e.g. altered node keys or entries)
 * is rejected, because downstream code reads `index.meta`, not `index.metaBytes`.
 */
export function verifyIndex(index, uploaderPublicKey) {
  // Prefer the exact signed bytes stored at setup; fall back to re-serializing
  // meta for indexes produced before metaBytes was stored.
  const metaBytes = index.metaBytes
    ? Buffer.from(index.metaBytes, 'base64')
    : Buffer.from(JSON.stringify(index.meta), 'utf8');
  const sig = Buffer.from(index.signature, 'base64');
  if (!verify(metaBytes, sig, uploaderPublicKey)) return false;

  // When the signed bytes are available, ensure the parsed meta that callers
  // actually use is byte-identical to what was signed. Both are produced by the
  // same JSON.stringify path (setup serialized `meta` to `metaBytes`), so a
  // faithful index round-trips exactly; a tampered `index.meta` does not.
  if (index.metaBytes) {
    const liveBytes = Buffer.from(JSON.stringify(index.meta), 'utf8');
    if (!liveBytes.equals(metaBytes)) return false;
  }
  return true;
}

/**
 * lookupSlot(index, tag) → number | -1
 * Finds slot j for a triple-hash tag h = H₃(O_j). The client computes the tag
 * locally from the object it wants and looks up its index — the tag never leaves.
 */
export function lookupSlot(index, tag) {
  const hex = Buffer.isBuffer(tag) ? tag.toString('hex') : tag;
  const entry = index.meta.entries.find(e => e.tag === hex);
  return entry ? entry.slot : -1;
}

/**
 * decryptRecord(record, K, { collectionId, slot }) → Buffer
 *
 * Reverses record construction: split off the ν_j nonce prefix, AES-GCM decrypt
 * with (G, j, ν_j) supplied as associated data, then remove padding. The GCM tag
 * fails if the record was moved to the wrong slot/collection or its nonce altered.
 */
export function decryptRecord(record, K, { collectionId, slot }) {
  const nonce = record.slice(0, NONCE_BYTES);                   // ν_j
  const enc   = record.slice(NONCE_BYTES);
  const plain = aesDecrypt(enc, K, aad(collectionId, slot, nonce));
  return unpadObject(plain);
}

export { padObject, unpadObject, tripleTag as H3 };
