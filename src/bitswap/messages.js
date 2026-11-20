/**
 * messages.js — Bitswap message types and wire serialisation
 *
 * Every message exchanged between two Bitswap peers is one of these types.
 * The standard types mirror real IPFS Bitswap 1.2.0.
 * The PRIVACY_* types are our extensions for the triple-hash protocol.
 *
 * ── Standard Bitswap message flow ────────────────────────────────────────────
 *
 *   Requester A                        Owner B
 *       │                                  │
 *       │── WANT_HAVE(cid) ───────────────►│  "Do you have this block?"
 *       │◄─ HAVE(cid) ────────────────────│  "Yes"
 *       │   or DONT_HAVE(cid)             │  "No"
 *       │                                  │
 *       │── WANT_BLOCK(cid) ─────────────►│  "Send me the block"
 *       │◄─ BLOCK(cid, data) ─────────────│  "Here it is"
 *       │                                  │
 *       │── CANCEL(cid) ─────────────────►│  "Never mind" (got it elsewhere)
 *
 * ── Privacy protocol message flow (paper Fig. 2) ─────────────────────────────
 *
 *   The session key K_AB is derived via ephemeral Diffie–Hellman during the
 *   handshake, providing forward secrecy: compromising the owner's long-term
 *   ECDSA/ECIES key does not reveal past session keys.
 *
 *   Requester A                                        Owner B
 *       │                                                  │
 *       │── WANT_HAVE(CID³) ─────────────────────────────►│  Step 1
 *       │                                                  │
 *       │◄─ PRIVACY_CHALLENGE(                            │  Step 2
 *       │     Sign_SSK_B(CID² ‖ PKB ‖ G^b), PKB, G^b) ───│  B generates
 *       │      A verifies signature against PKB           │  ephemeral (b, G^b)
 *       │                                                  │
 *       │── PRIVACY_RESPONSE(                             │  Step 3
 *       │     ECIES_PKB(CID¹ ‖ H(K_AB) ‖ G^a)) ─────────►│  K_AB = KDF(G^ab)
 *       │      A generates ephemeral (a, G^a)              │  B verifies H(K_AB)
 *       │◄─ PRIVACY_BLOCK(AES_K_AB(OBJ)) ────────────────│  Step 4
 *       │      A decrypts, verifies H(OBJ) = CID¹.digest  │
 *
 * ── Wire format ───────────────────────────────────────────────────────────────
 *
 *   All messages are sent over a Connection using the '/bitswap/1.0' protocol.
 *
 *   Binary layout:
 *     [ 1 byte  : message type ]
 *     [ 2 bytes : CID string length (uint16-BE) ]
 *     [ N bytes : CID string (UTF-8) ]
 *     [ 4 bytes : payload length (uint32-BE) ]
 *     [ M bytes : payload (type-dependent) ]
 *
 * SWAP POINT — message format:
 *   Real Bitswap uses protobuf. Replace encode/decode below with
 *   protobuf serialisation for wire compatibility with go-ipfs/kubo.
 */

// ── Message type constants ────────────────────────────────────────────────────

export const MessageType = Object.freeze({
  // Standard Bitswap
  WANT_HAVE    : 0x01,  // "Do you have CID X?"
  HAVE         : 0x02,  // "Yes, I have CID X"
  DONT_HAVE    : 0x03,  // "No, I don't have CID X"
  WANT_BLOCK   : 0x04,  // "Send me the block for CID X"
  BLOCK        : 0x05,  // "Here is the block for CID X"
  CANCEL       : 0x06,  // "Cancel my request for CID X"

  // Privacy protocol extensions
  PRIVACY_CHALLENGE : 0x10,  // B → A: sign(CID²)  [Step 2]
  PRIVACY_RESPONSE  : 0x11,  // A → B: ecies(CID¹ + K, B_pub)  [Step 3]
  PRIVACY_BLOCK     : 0x12,  // B → A: aes_K(OBJ)  [Step 4]
});

// Human-readable names for logging
export const MessageTypeName = Object.freeze(
  Object.fromEntries(Object.entries(MessageType).map(([k, v]) => [v, k]))
);

// ── Encode ────────────────────────────────────────────────────────────────────

/**
 * encode(type, cid, payload) → Buffer
 *
 * Serialises a Bitswap message into bytes for transmission.
 *
 * @param {number} type    — one of MessageType.*
 * @param {string} cid     — CID string this message refers to
 * @param {Buffer} [payload] — type-dependent data (empty for WANT_HAVE etc.)
 * @returns {Buffer}
 */
export function encode(type, cid, payload = Buffer.alloc(0)) {
  const cidBytes     = Buffer.from(cid, 'utf8');
  const buf          = Buffer.alloc(1 + 2 + cidBytes.length + 4 + payload.length);
  let offset         = 0;

  buf.writeUInt8(type, offset);                 offset += 1;
  buf.writeUInt16BE(cidBytes.length, offset);   offset += 2;
  cidBytes.copy(buf, offset);                   offset += cidBytes.length;
  buf.writeUInt32BE(payload.length, offset);    offset += 4;
  payload.copy(buf, offset);

  return buf;
}

/**
 * decode(buf) → { type, cid, payload }
 *
 * Deserialises a Bitswap message from bytes.
 *
 * @param {Buffer} buf
 * @returns {{ type: number, cid: string, payload: Buffer }}
 */
export function decode(buf) {
  // Minimum: 1 (type) + 2 (cidLen) + 0 (cid) + 4 (payLen) = 7 bytes
  if (!Buffer.isBuffer(buf) || buf.length < 7) {
    throw new Error('Bitswap decode: buffer too short');
  }

  let offset     = 0;
  const type     = buf.readUInt8(offset);                                 offset += 1;
  const cidLen   = buf.readUInt16BE(offset);                              offset += 2;

  if (offset + cidLen + 4 > buf.length) {
    throw new Error('Bitswap decode: CID length exceeds buffer');
  }
  const cid      = buf.slice(offset, offset + cidLen).toString('utf8');  offset += cidLen;
  const payLen   = buf.readUInt32BE(offset);                              offset += 4;

  if (offset + payLen > buf.length) {
    throw new Error('Bitswap decode: payload length exceeds buffer');
  }
  const payload  = buf.slice(offset, offset + payLen);

  return { type, cid, payload };
}
