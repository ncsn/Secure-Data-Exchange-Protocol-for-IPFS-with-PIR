/**
 * shamir.js — Shamir (k, n) threshold secret sharing over a prime field F_p.
 *
 * This is the key-protection half of the PIR retrieval layer (paper §III,
 * "Titokmegosztás"). The uploader P splits the 256-bit AES collection key K
 * into n shares s_i = (x_i, y_i), one per server node. Any k shares reconstruct
 * K via Lagrange interpolation at x = 0; any k-1 shares reveal nothing about K
 * (the distribution of f(0) remains uniform over F_p).
 *
 *   f(x) = K + b_1·x + b_2·x² + … + b_{k-1}·x^{k-1}   (mod p)
 *   s_i  = (x_i, f(x_i)),   x_i = i   (fixed, non-zero, pairwise distinct)
 *   K    = f(0) = Σ_{i∈S} y_i · Π_{ℓ∈S, ℓ≠i} (-x_ℓ)/(x_i - x_ℓ)   (mod p)
 *
 * All arithmetic uses native BigInt. The field prime p is the smallest prime
 * greater than 2²⁵⁶, so every 256-bit key and every server coordinate x_i = i
 * (for realistic n ≪ 2²⁵⁶) fits strictly inside F_p.
 *
 * No network, no Node crypto beyond randomBytes for the polynomial coefficients.
 */

import { randomBytes } from 'crypto';

// ── Field configuration ────────────────────────────────────────────────────────

/**
 * PRIME — smallest prime strictly greater than 2²⁵⁶ (2²⁵⁶ + 297).
 * A 256-bit secret is always < 2²⁵⁶ < p, so f(0) = K is representable, and
 * reconstruction is exact. Verified prime; see Shamir's scheme requirements.
 */
export const PRIME = (1n << 256n) + 297n;

/** Byte length of a reconstructed secret (256-bit AES key). */
const SECRET_BYTES = 32;

// ── Field arithmetic (BigInt mod p) ─────────────────────────────────────────────

/** Reduce n into the canonical range [0, p) — handles negative inputs. */
function mod(n, p = PRIME) {
  const r = n % p;
  return r < 0n ? r + p : r;
}

/**
 * modInverse(a, p) → BigInt
 * Modular multiplicative inverse via the extended Euclidean algorithm.
 * p is prime, so every non-zero a has an inverse.
 */
function modInverse(a, p = PRIME) {
  let [oldR, r] = [mod(a, p), p];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('shamir: value is not invertible (not coprime with prime)');
  return mod(oldS, p);
}

// ── Buffer ↔ BigInt helpers ─────────────────────────────────────────────────────

/** Big-endian Buffer → BigInt. */
function bufToBig(buf) {
  return buf.length === 0 ? 0n : BigInt('0x' + buf.toString('hex'));
}

/** BigInt → fixed-length big-endian Buffer (SECRET_BYTES). */
function bigToSecretBuf(n) {
  let hex = mod(n).toString(16);
  if (hex.length > SECRET_BYTES * 2) {
    throw new Error('shamir: reconstructed value exceeds 256 bits');
  }
  hex = hex.padStart(SECRET_BYTES * 2, '0');
  return Buffer.from(hex, 'hex');
}

/** Uniform random BigInt in [0, p). Rejection-samples to avoid modulo bias. */
function randomFieldElement() {
  // 33 bytes = 264 bits > 256-bit prime; reject until strictly below p.
  for (;;) {
    const candidate = bufToBig(randomBytes(SECRET_BYTES + 1));
    if (candidate < PRIME) return candidate;
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * split(secret, k, n) → Array<{ x: bigint, y: bigint }>
 *
 * Splits a secret into n shares with threshold k (any k reconstruct, any k-1
 * reveal nothing). Coordinates x_i = 1..n.
 *
 * @param {Buffer} secret — the 256-bit key K (≤ 32 bytes, big-endian)
 * @param {number} k      — reconstruction threshold (2 ≤ k ≤ n)
 * @param {number} n      — number of shares to produce
 * @returns {Array<{x: bigint, y: bigint}>}
 */
export function split(secret, k, n) {
  if (!Buffer.isBuffer(secret)) throw new Error('shamir.split: secret must be a Buffer');
  if (secret.length > SECRET_BYTES) throw new Error('shamir.split: secret exceeds 256 bits');
  if (!Number.isInteger(k) || !Number.isInteger(n)) throw new Error('shamir.split: k and n must be integers');
  if (k < 2) throw new Error('shamir.split: threshold k must be ≥ 2');
  if (k > n) throw new Error('shamir.split: threshold k must be ≤ n');
  if (BigInt(n) >= PRIME) throw new Error('shamir.split: n must be < field prime');

  const K = bufToBig(secret);
  if (K >= PRIME) throw new Error('shamir.split: secret value ≥ field prime');

  // Random coefficients b_1..b_{k-1}; constant term is the secret itself.
  const coeffs = [K];
  for (let d = 1; d < k; d++) coeffs.push(randomFieldElement());

  // Evaluate f(x_i) for x_i = 1..n using Horner's method.
  const shares = [];
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i);
    let y = 0n;
    for (let d = coeffs.length - 1; d >= 0; d--) {
      y = mod(y * x + coeffs[d]);
    }
    shares.push({ x, y });
  }
  return shares;
}

/**
 * reconstruct(shares) → Buffer
 *
 * Reconstructs the secret from any k (or more) shares via Lagrange
 * interpolation evaluated at x = 0. Duplicate x-coordinates are rejected.
 *
 * @param {Array<{x: bigint, y: bigint}>} shares — at least k distinct shares
 * @returns {Buffer} the 32-byte secret
 */
export function reconstruct(shares) {
  if (!Array.isArray(shares) || shares.length < 2) {
    throw new Error('shamir.reconstruct: need at least 2 shares');
  }
  const xs = shares.map(s => BigInt(s.x));
  if (new Set(xs.map(String)).size !== xs.length) {
    throw new Error('shamir.reconstruct: duplicate share coordinates');
  }
  if (xs.some(x => x === 0n)) {
    throw new Error('shamir.reconstruct: x = 0 is reserved for the secret');
  }

  // K = Σ y_i · Π_{ℓ≠i} (-x_ℓ) / (x_i - x_ℓ)   (mod p)
  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    const xi = xs[i];
    const yi = mod(BigInt(shares[i].y));
    let num = 1n;
    let den = 1n;
    for (let l = 0; l < shares.length; l++) {
      if (l === i) continue;
      const xl = xs[l];
      num = mod(num * mod(-xl));
      den = mod(den * mod(xi - xl));
    }
    const lagrange = mod(num * modInverse(den));
    secret = mod(secret + yi * lagrange);
  }
  return bigToSecretBuf(secret);
}

/**
 * shareToBuffer(share) / shareFromBuffer(buf) — wire encoding for a single
 * share so it can travel inside a MAC_KEY/BLOCK payload. Layout:
 *   [ x: 32 bytes big-endian | y: 33 bytes big-endian ]
 * x_i = i is small, so 32 bytes always suffices. BUT y = f(x_i) mod p can land
 * anywhere in [0, p) and p = 2²⁵⁶ + 297, so y may need 257 bits (33 bytes). A
 * 32-byte y field would silently drop the top nibble for the rare y ≥ 2²⁵⁶,
 * reconstructing a WRONG secret with no error. The y field is therefore 33 bytes.
 */
const SHARE_X_BYTES = 32;
const SHARE_Y_BYTES = 33;  // y ∈ [0, 2²⁵⁶+297) needs 257 bits → 33 bytes
const SHARE_WIRE_BYTES = SHARE_X_BYTES + SHARE_Y_BYTES;

export function shareToBuffer(share) {
  const xBig = BigInt(share.x);
  const yBig = BigInt(share.y);
  // Guard the wire bounds explicitly. The fixed-width fields can only hold a
  // canonical field element; a coordinate outside [0, p) would be silently
  // reduced by mod() and encode a different value than the caller passed,
  // reconstructing a wrong secret with no error. Fail loudly instead.
  if (xBig < 0n || xBig >= PRIME) throw new Error('shamir.shareToBuffer: x out of field range [0, p)');
  if (yBig < 0n || yBig >= PRIME) throw new Error('shamir.shareToBuffer: y out of field range [0, p)');
  const x = Buffer.from(xBig.toString(16).padStart(SHARE_X_BYTES * 2, '0'), 'hex');
  const y = Buffer.from(yBig.toString(16).padStart(SHARE_Y_BYTES * 2, '0'), 'hex');
  return Buffer.concat([x, y]);
}

export function shareFromBuffer(buf) {
  if (buf.length !== SHARE_WIRE_BYTES) {
    throw new Error(`shamir.shareFromBuffer: expected ${SHARE_WIRE_BYTES} bytes`);
  }
  return {
    x: bufToBig(buf.slice(0, SHARE_X_BYTES)),
    y: bufToBig(buf.slice(SHARE_X_BYTES, SHARE_WIRE_BYTES)),
  };
}
