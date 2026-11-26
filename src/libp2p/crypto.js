/**
 * crypto.js — Asymmetric cryptography for libp2p and the privacy protocol
 *
 * This module provides all asymmetric crypto operations used by:
 *   - Peer ID generation (hash of public key)
 *   - Digital signatures (sign/verify CID² in the privacy handshake)
 *   - Asymmetric encryption (encrypt CID¹ + AES key K for the owner)
 *   - ECDH key agreement (derive a shared secret between two peers)
 *
 * ── Algorithm choices ────────────────────────────────────────────────────────
 *
 *   Signing   : ECDSA with curve P-256 and SHA-256
 *   Encryption: ECIES (ECDH key agreement → AES-256-GCM symmetric encryption)
 *               Pure ECDSA/ECDH has no built-in encryption — ECIES is the
 *               standard pattern for "encrypt to a public key" using ECC.
 *   Key format: raw SPKI (public) and PKCS8 (private) via Node.js crypto
 *
 * SWAP POINT — curve:
 *   Change CURVE below to switch the elliptic curve.
 *   Supported by Node.js built-in crypto:
 *     'P-256'   (secp256r1) — good default, widely supported
 *     'P-384'   (secp384r1) — stronger, slightly slower
 *     'P-521'   (secp521r1) — strongest standard curve
 *   For secp256k1 (Bitcoin/Ethereum curve) you would need the 'noble-curves'
 *   npm package as Node.js does not support it natively for ECDH.
 *
 * SWAP POINT — signing hash:
 *   Change SIGN_HASH below. Must be compatible with the chosen curve:
 *     P-256 → SHA-256 (standard) or SHA-384
 *     P-384 → SHA-384 (standard)
 *     P-521 → SHA-512 (standard)
 *
 * SWAP POINT — symmetric cipher for ECIES:
 *   Change ECIES_CIPHER and ECIES_KEY_BYTES below.
 *   AES-256-GCM is recommended (authenticated encryption — detects tampering).
 *   Alternatives: 'aes-128-gcm' (16-byte key), 'chacha20-poly1305' (32-byte key).
 */

import { createECDH, createSign, createVerify, createCipheriv,
         createDecipheriv, randomBytes, createHash, hkdfSync } from 'crypto';
import { generateKeyPairSync, createPublicKey }                from 'crypto';

// ── Algorithm configuration ───────────────────────────────────────────────────

/** Elliptic curve for all key operations. SWAP THIS to change the curve. */
const CURVE = 'P-256';

/** Hash algorithm used by ECDSA signing. SWAP THIS with the curve. */
const SIGN_HASH = 'SHA256';

/** Symmetric cipher used inside ECIES encrypt/decrypt. SWAP THIS freely. */
const ECIES_CIPHER = 'aes-256-gcm';

/** Key length in bytes for ECIES_CIPHER. Must match the cipher. SWAP THIS. */
const ECIES_KEY_BYTES = 32; // 32 bytes = 256-bit key for AES-256

/** GCM authentication tag length in bytes (fixed at 16 for AES-GCM). */
const GCM_TAG_BYTES = 16;

/** IV (nonce) length in bytes for AES-GCM. */
const GCM_IV_BYTES = 12;

export { CURVE, SIGN_HASH, ECIES_CIPHER, ECIES_KEY_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES };

// ── Diffie-Hellman (ECDH) helpers ────────────────────────────────────────────
//
// Used by the enhanced privacy protocol (Figure 2 of the paper):
//   Step 2: B generates (gb, Gb) and sends Gb
//   Step 3: A generates (ga, Ga) and sends Ga
//   Both derive K_AB = ECDH(ga, Gb) = ECDH(gb, Ga)
//   The session key provides forward secrecy: compromising long-term keys
//   does not reveal K_AB.

/**
 * generateDHKeyPair() → { privateKey: Buffer, publicKey: Buffer }
 *
 * Generates an ephemeral ECDH key pair for Diffie-Hellman key exchange.
 * publicKey is the 65-byte uncompressed point (Ga or Gb in the paper).
 * privateKey is the raw scalar (32 bytes for P-256).
 */
export function generateDHKeyPair() {
  const ecdh = createECDH(ecCurveName(CURVE));
  ecdh.generateKeys();
  return {
    privateKey: ecdh.getPrivateKey(),
    publicKey: ecdh.getPublicKey(), // 65-byte uncompressed
  };
}

/**
 * computeDHSecret(myPrivateKey, theirPublicKey) → Buffer (32-byte AES key)
 *
 * Computes the shared secret from ECDH and derives an AES-256 session key
 * using HKDF-SHA256. This is K_AB = KDF(ECDH(a, Gb)) = KDF(ECDH(b, Ga)).
 *
 * @param {Buffer} myPrivateKey    — raw ECDH private scalar
 * @param {Buffer} theirPublicKey  — 65-byte uncompressed ECDH public key
 * @returns {Buffer} 32-byte AES-256 session key
 */
export function computeDHSecret(myPrivateKey, theirPublicKey) {
  const ecdh = createECDH(ecCurveName(CURVE));
  ecdh.setPrivateKey(myPrivateKey);
  const sharedSecret = ecdh.computeSecret(theirPublicKey);
  // Derive a 32-byte AES key using HKDF with a fixed salt
  // The raw ECDH shared secret is already unique per session (ephemeral keys),
  // so a constant salt is safe and ensures both parties derive the same key.
  const salt = Buffer.from('ipfs-triple-hash-dh-salt');
  const info = Buffer.from('ipfs-privacy-session-key');
  return Buffer.from(hkdfSync('sha256', sharedSecret, salt, info, ECIES_KEY_BYTES));
}

// ── Key pair ──────────────────────────────────────────────────────────────────

/**
 * generateKeyPair() → { privateKey, publicKey, publicKeyRaw }
 *
 * Generates a new ECDSA key pair.
 *
 * @returns {{
 *   privateKey    : KeyObject  — Node.js private key object
 *   publicKey     : KeyObject  — Node.js public key object
 *   publicKeyRaw  : Buffer     — SPKI DER-encoded public key (~91 bytes for P-256).
 *                               Used for Peer ID derivation and wire encoding.
 *                               NOTE: this is the full SPKI DER structure, not the
 *                               bare 65-byte uncompressed point. exportRawPublicKey()
 *                               extracts the 65-byte point (slice(-65)) for ECDH.
 * }}
 */
export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: CURVE,
  });

  // Export the SPKI DER public key. Peer IDs and the wire format are both derived
  // from these exact bytes, so this must stay stable across the codebase.
  const publicKeyRaw = Buffer.from(
    publicKey.export({ type: 'spki', format: 'der' })
  );

  return { privateKey, publicKey, publicKeyRaw };
}

// ── Sign / Verify ─────────────────────────────────────────────────────────────

/**
 * sign(data, privateKey) → Buffer
 *
 * Signs arbitrary data with a private key.
 * Used in the privacy protocol: owner B signs CID² to prove ownership.
 *
 * @param {Buffer|string} data
 * @param {KeyObject}     privateKey
 * @returns {Buffer} DER-encoded ECDSA signature
 */
export function sign(data, privateKey) {
  const signer = createSign(SIGN_HASH);
  signer.update(data);
  return signer.sign(privateKey); // returns DER-encoded Buffer
}

/**
 * verify(data, signature, publicKey) → boolean
 *
 * Verifies an ECDSA signature.
 * Used by node A to confirm that B really knows CID².
 *
 * @param {Buffer|string} data
 * @param {Buffer}        signature — DER-encoded signature from sign()
 * @param {KeyObject}     publicKey
 * @returns {boolean}
 */
export function verify(data, signature, publicKey) {
  try {
    const verifier = createVerify(SIGN_HASH);
    verifier.update(data);
    return verifier.verify(publicKey, signature);
  } catch {
    return false; // malformed signature or wrong key
  }
}

// ── ECIES Encrypt / Decrypt ───────────────────────────────────────────────────
//
// ECIES (Elliptic Curve Integrated Encryption Scheme):
//   Encrypt to a public key without a pre-shared secret.
//
// Protocol (encrypt):
//   1. Generate a fresh ephemeral ECDH key pair (ephem_priv, ephem_pub)
//   2. Derive shared secret: ECDH(ephem_priv, recipient_pub)
//   3. Derive AES key: HKDF-like SHA-256 of the shared secret
//   4. Encrypt plaintext with AES-GCM using the derived key
//   5. Output: [ ephem_pub (65 bytes) | iv (12) | tag (16) | ciphertext ]
//
// Protocol (decrypt):
//   1. Parse ephem_pub from the message
//   2. Derive shared secret: ECDH(recipient_priv, ephem_pub)
//   3. Derive the same AES key
//   4. Decrypt with AES-GCM, verify the auth tag
//
// Security: only the holder of recipient_priv can decrypt.
// Used in privacy protocol: A encrypts (CID¹ + K) with B's public key.

/**
 * eciesEncrypt(plaintext, recipientPublicKey) → Buffer
 *
 * Encrypts plaintext so only the holder of recipientPublicKey's private key
 * can decrypt it.
 *
 * @param {Buffer}    plaintext
 * @param {KeyObject} recipientPublicKey
 * @returns {Buffer} [ ephem_pub(65) | iv(12) | tag(16) | ciphertext ]
 */
export function eciesEncrypt(plaintext, recipientPublicKey) {
  // Step 1: ephemeral ECDH key pair
  const ecdh    = createECDH(ecCurveName(CURVE));
  ecdh.generateKeys();
  const ephemPub = ecdh.getPublicKey(); // 65-byte uncompressed

  // Step 2: derive shared secret using recipient's raw public key
  const recipientRaw   = exportRawPublicKey(recipientPublicKey);
  const sharedSecret   = ecdh.computeSecret(recipientRaw);

  // Step 3: derive AES key from shared secret, using ephemPub as salt
  const aesKey = deriveKey(sharedSecret, ephemPub);

  // Step 4: AES-GCM encrypt
  const iv         = randomBytes(GCM_IV_BYTES);
  const cipher     = createCipheriv(ECIES_CIPHER, aesKey, iv);
  const encrypted  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag        = cipher.getAuthTag();

  // Step 5: assemble output
  return Buffer.concat([ephemPub, iv, tag, encrypted]);
}

/**
 * eciesDecrypt(ciphertext, privateKey) → Buffer
 *
 * Decrypts a message produced by eciesEncrypt().
 *
 * @param {Buffer}    ciphertext — full output from eciesEncrypt()
 * @param {KeyObject} privateKey
 * @returns {Buffer} original plaintext
 */
export function eciesDecrypt(ciphertext, privateKey) {
  // Parse the wire format
  let offset = 0;
  const ephemPub = ciphertext.slice(offset, offset + 65); offset += 65;
  const iv       = ciphertext.slice(offset, offset + GCM_IV_BYTES); offset += GCM_IV_BYTES;
  const tag      = ciphertext.slice(offset, offset + GCM_TAG_BYTES); offset += GCM_TAG_BYTES;
  const encrypted = ciphertext.slice(offset);

  // Derive shared secret using our private key and the ephemeral public key
  const ecdh       = createECDH(ecCurveName(CURVE));
  const privRaw    = exportRawPrivateKey(privateKey);
  ecdh.setPrivateKey(privRaw);
  const sharedSecret = ecdh.computeSecret(ephemPub);

  // Derive AES key — use ephemPub as salt (same as encrypt side)
  const aesKey = deriveKey(sharedSecret, ephemPub);

  // AES-GCM decrypt
  const decipher = createDecipheriv(ECIES_CIPHER, aesKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ── AES-GCM (symmetric, session key) ─────────────────────────────────────────
//
// Used in the privacy protocol for the final object transfer:
// Owner B encrypts OBJ with the AES session key K supplied by node A.

/**
 * aesEncrypt(plaintext, key, aad?, nonce?) → Buffer
 *
 * Encrypts with AES-256-GCM using a caller-supplied key. When `aad` is given,
 * it is bound as GCM associated data: the auth tag then covers both the
 * ciphertext and the associated data, but the AAD itself is NOT stored in the
 * output (the caller must supply the identical AAD to decrypt).
 *
 * When `nonce` is given it is used verbatim as the GCM IV (it must be exactly
 * GCM_IV_BYTES long); otherwise a fresh random IV is generated. Supplying the
 * nonce lets a caller realize the paper's record form C_j = ν_j ‖ enc_K(ν_j,
 * pad(O_j); G,j), where ν_j is the actual GCM nonce (not merely associated
 * data). The IV is always stored in the output, so decrypt needs only the key
 * (and the matching AAD); it does not need the nonce passed back separately.
 * Output: [ iv(12) | tag(16) | ciphertext ]
 *
 * CAUTION: a caller-supplied nonce MUST be unique per key — GCM nonce reuse is
 * catastrophic. Pass a fresh random ν_j per record (as collection setup does).
 *
 * @param {Buffer} plaintext
 * @param {Buffer} key — 32-byte AES key
 * @param {Buffer} [aad] — optional associated data bound into the auth tag
 * @param {Buffer} [nonce] — optional explicit GCM IV (exactly GCM_IV_BYTES)
 * @returns {Buffer}
 */
export function aesEncrypt(plaintext, key, aad, nonce) {
  let iv;
  if (nonce === undefined) {
    iv = randomBytes(GCM_IV_BYTES);
  } else {
    if (!Buffer.isBuffer(nonce) || nonce.length !== GCM_IV_BYTES) {
      throw new Error(`aesEncrypt: nonce must be a ${GCM_IV_BYTES}-byte Buffer`);
    }
    iv = nonce;
  }
  const cipher  = createCipheriv(ECIES_CIPHER, key, iv);
  if (aad) cipher.setAAD(aad);
  const enc     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag     = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

/**
 * aesDecrypt(ciphertext, key, aad?) → Buffer
 *
 * Decrypts output from aesEncrypt(). If the ciphertext was produced with AAD,
 * the identical `aad` must be supplied here or the GCM tag check fails. The IV
 * is read from the ciphertext prefix, so an explicit nonce is never needed here
 * regardless of whether encrypt used a random or caller-supplied IV.
 *
 * @param {Buffer} ciphertext
 * @param {Buffer} key — 32-byte AES key
 * @param {Buffer} [aad] — optional associated data that was bound at encrypt time
 * @returns {Buffer}
 */
export function aesDecrypt(ciphertext, key, aad) {
  let offset     = 0;
  const iv       = ciphertext.slice(offset, offset + GCM_IV_BYTES); offset += GCM_IV_BYTES;
  const tag      = ciphertext.slice(offset, offset + GCM_TAG_BYTES); offset += GCM_TAG_BYTES;
  const enc      = ciphertext.slice(offset);
  const decipher = createDecipheriv(ECIES_CIPHER, key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

/**
 * randomAesKey() → Buffer
 *
 * Generates a cryptographically random AES session key (K).
 * This is what node A generates and sends encrypted to node B.
 *
 * @returns {Buffer} 32-byte random key
 */
export function randomAesKey() {
  return randomBytes(ECIES_KEY_BYTES);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * deriveKey(sharedSecret, salt) → Buffer
 *
 * Derives a fixed-length AES key from a raw ECDH shared secret using HKDF-SHA256.
 * The salt is the ephemeral public key, making every derived key unique per message.
 *
 * @param {Buffer} sharedSecret — ECDH output
 * @param {Buffer} salt         — ephemeral public key bytes (65 bytes, uncompressed)
 * @returns {Buffer} ECIES_KEY_BYTES-length key
 */
function deriveKey(sharedSecret, salt) {
  const info = Buffer.from('ecies-aes-key');
  return Buffer.from(hkdfSync('sha256', sharedSecret, salt, info, ECIES_KEY_BYTES));
}

/**
 * ecCurveName(webCryptoCurve) → string
 * Maps Web Crypto curve names to Node.js ECDH curve names.
 * SWAP THIS if you change CURVE to a non-standard name.
 */
function ecCurveName(curve) {
  const map = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };
  return map[curve] || curve;
}

/** Export the raw 65-byte uncompressed public key from a KeyObject. */
function exportRawPublicKey(keyObject) {
  // SPKI DER for P-256 = 27-byte header + 65-byte raw key
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return Buffer.from(der).slice(-65);
}

/** Export the raw private key scalar from a KeyObject for use with ECDH. */
function exportRawPrivateKey(keyObject) {
  // Export as JWK and decode the base64url-encoded 'd' field (the raw scalar).
  const jwk = keyObject.export({ format: 'jwk' });
  return Buffer.from(jwk.d, 'base64url');
}
