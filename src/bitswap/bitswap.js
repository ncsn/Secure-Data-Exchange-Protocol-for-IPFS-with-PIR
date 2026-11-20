/**
 * bitswap.js — Bitswap engine
 *
 * The Bitswap engine sits between the block store and the network.
 * It handles:
 *   1. Standard block exchange (want-list, HAVE/BLOCK responses)
 *   2. Per-peer ledgers (bytes sent vs received — incentive layer)
 *   3. Privacy protocol handshake (Steps 1–4 from the research paper)
 *
 * ── Architecture ──────────────────────────────────────────────────────────────
 *
 *   BitswapEngine
 *     ├── BlockStore            — local block storage (read + write)
 *     ├── PeerId                — local peer identity (for signing)
 *     ├── Map<peerId, Ledger>   — per-peer accounting
 *     ├── Map<cid, callbacks>   — pending requests waiting for blocks
 *     └── Connection registry   — connections handed to us by TCPTransport
 *
 * ── Ledger ────────────────────────────────────────────────────────────────────
 *
 *   For each peer we track:
 *     bytesSent     — how many bytes we sent them
 *     bytesReceived — how many bytes they sent us
 *     debt ratio    — bytesSent / (bytesReceived + 1)
 *
 *   Peers with high debt (they receive much more than they send) get
 *   lower priority. This is the incentive mechanism that prevents leeching.
 *
 *   SWAP POINT — incentive strategy:
 *     Real Bitswap uses a more sophisticated strategy (Bitswap 1.2 uses
 *     a sigmoid function over the debt ratio). Replace _shouldServe()
 *     to implement a different strategy.
 *
 * ── Privacy protocol ──────────────────────────────────────────────────────────
 *
 *   When a node calls requestPrivate(cid3, cid1, ownerConn):
 *     Step 1: send WANT_HAVE(cid3)
 *     Step 2: receive PRIVACY_CHALLENGE(Sign(CID₂ ‖ PKB ‖ Gb), PKB, Gb)
 *             verify sig against owner's public key
 *     Step 3: generate DH keypair (ga, Ga), compute K_AB = DH(ga, Gb)
 *             send PRIVACY_RESPONSE(ecies(CID₁ ‖ H(K_AB) ‖ Ga, PKB))
 *     Step 4: receive PRIVACY_BLOCK(aes_K_AB(OBJ))
 *             decrypt with K_AB, verify hash = CID₁ digest
 *
 *   When a node is the owner and receives WANT_HAVE(cid3):
 *     - looks up cid3 → cid2 mapping (owner's private table)
 *     - generates ephemeral DH keypair (gb, Gb)
 *     - sends PRIVACY_CHALLENGE(Sign(CID₂ ‖ PKB ‖ Gb), PKB, Gb)
 *     - waits for PRIVACY_RESPONSE, decrypts to get CID₁ + H(K_AB) + Ga
 *     - computes K_AB = DH(gb, Ga), verifies H(K_AB)
 *     - fetches OBJ, encrypts with K_AB, sends PRIVACY_BLOCK
 */

import EventEmitter from 'events';
import { randomBytes, timingSafeEqual } from 'crypto';

import { MessageType, MessageTypeName, encode, decode } from './messages.js';
import { sign, verify, eciesDecrypt, eciesEncrypt,
         aesEncrypt, aesDecrypt,
         generateDHKeyPair, computeDHSecret }           from '../libp2p/crypto.js';
import { tripleHash }                                   from '../cid/cid.js';
import { hash }                                         from '../cid/crypto.js';
import { createHash }                                    from 'crypto';

const BITSWAP_PROTO = '/bitswap/1.0';

/** Maximum concurrent pending requests to prevent memory exhaustion */
const MAX_PENDING = 1024;

/** ── Flood forwarding (opt-in) ─────────────────────────────────────────────────
 *
 * When BITSWAP_FLOOD_FORWARD=1, an intermediate node that receives a WANT_HAVE
 * for a CID it does not own / does not have in its store will:
 *   1. Broadcast WANT_HAVE to every OTHER connected peer (excluding origin)
 *   2. Record the origin connection in _forwardTable so replies can be routed back
 *   3. Forward all subsequent protocol messages for that CID in both directions
 *
 * The flag is OFF by default so existing tests observe unchanged single-hop
 * behavior. Enable per-container via env var in docker-compose for benchmarks.
 */
const FLOOD_FORWARD_ENABLED = process.env.BITSWAP_FLOOD_FORWARD === '1';
/** How long a forward-table entry stays valid before cleanup (ms). */
const FORWARD_TTL_MS      = 15_000;
/** How long a CID stays in _forwardSeen to prevent broadcast loops (ms). */
const FORWARD_SEEN_TTL_MS = 30_000;

// ── Ledger ────────────────────────────────────────────────────────────────────

class Ledger {
  constructor(peerId) {
    this.peerId        = peerId;
    this.bytesSent     = 0;
    this.bytesReceived = 0;
  }

  /** debt ratio — higher means we've sent more than we received */
  debtRatio() {
    return this.bytesSent / (this.bytesReceived + 1);
  }
}

// ── BitswapEngine ─────────────────────────────────────────────────────────────

export class BitswapEngine extends EventEmitter {
  /**
   * @param {import('../blockstore/blockstore.js').BlockStore} store
   * @param {import('../libp2p/peer.js').PeerId}               localPeer
   */
  constructor(store, localPeer) {
    super();
    this.store      = store;
    this.localPeer  = localPeer;

    // per-peer ledgers
    this.ledgers    = new Map(); // peerId.id → Ledger

    // pending block requests: cid string → { resolve, reject, timeout }
    this._pending   = new Map();

    // owner's private triple-hash table: cid3.string → { cid1, cid2, h1, rawData }
    // Populated when this node adds a file it owns.
    this._owned     = new Map();

    // ── Flood forwarding state (only used when FLOOD_FORWARD_ENABLED) ─────────
    // _forwardTable: cid → { origin: Connection, holder: Connection|null,
    //                        fanout: Set<Connection>, ts: number }
    //   origin  = the connection the initial WANT_HAVE arrived from (replies go there)
    //   holder  = set to the first peer that responded HAVE/PRIVACY_CHALLENGE
    //             (subsequent client-side follow-ups such as WANT_BLOCK / PRIVACY_RESPONSE
    //              from `origin` are forwarded to `holder`)
    //   fanout  = the connections we broadcast to (used to send DONT_HAVE upstream
    //             only after ALL downstream peers replied DONT_HAVE)
    //   ts      = insertion time; entries older than FORWARD_TTL_MS are pruned
    this._forwardTable = new Map();

    // _forwardSeen: cid → ts. Prevents rebroadcasting a WANT_HAVE we already
    // forwarded (broadcast-loop protection in cyclic topologies).
    this._forwardSeen  = new Map();

    // Ephemeral DH keypairs from Step 2 of privacy handshake (keyed by cid+peer).
    // Declared eagerly so type is consistent whether or not flood is on.
    this._dhEphemeral  = new Map();

    // Periodic cleanup of expired forward entries (unref'd so it doesn't block exit).
    if (FLOOD_FORWARD_ENABLED) {
      this._forwardCleanupInterval = setInterval(() => this._cleanupForward(), 5_000);
      if (this._forwardCleanupInterval.unref) this._forwardCleanupInterval.unref();
    }
  }

  /** Stop internal timers — currently only the forward cleanup interval. */
  stop() {
    if (this._forwardCleanupInterval) {
      clearInterval(this._forwardCleanupInterval);
      this._forwardCleanupInterval = null;
    }
  }

  _cleanupForward() {
    const now = Date.now();
    for (const [cid, entry] of this._forwardTable) {
      if (now - entry.ts > FORWARD_TTL_MS) this._forwardTable.delete(cid);
    }
    for (const [cid, ts] of this._forwardSeen) {
      if (now - ts > FORWARD_SEEN_TTL_MS) this._forwardSeen.delete(cid);
    }
  }

  // ── Connection management ─────────────────────────────────────────────────

  /**
   * addConnection(conn) — register a live Connection with this engine
   *
   * Must be called whenever TCPTransport emits a 'connection' event.
   * Attaches a message handler so the engine processes incoming Bitswap messages.
   *
   * @param {import('../libp2p/transport.js').Connection} conn
   */
  addConnection(conn) {
    const peerId = conn.remotePeer.id;
    if (!this.ledgers.has(peerId)) {
      this.ledgers.set(peerId, new Ledger(peerId));
    }

    // Track active connections for flood-forwarding broadcast (opt-in).
    if (FLOOD_FORWARD_ENABLED) {
      if (!this._connections) this._connections = new Set();
      this._connections.add(conn);
    }

    conn.onMessage(BITSWAP_PROTO, (payload) => {
      this._handleMessage(decode(payload), conn).catch(err =>
        this.emit('error', err)
      );
    });

    conn.on('close', () => {
      if (this._connections) this._connections.delete(conn);
      // Clean up any pending requests that were waiting on this peer
      for (const [cid, pending] of this._pending) {
        if (pending.peerId === peerId) {
          clearTimeout(pending.timeout);
          pending.reject(new Error(`Connection closed before block received: ${cid}`));
          this._pending.delete(cid);
        }
      }
      // Clean up forward entries pointing at this connection.
      if (FLOOD_FORWARD_ENABLED) {
        for (const [cid, entry] of this._forwardTable) {
          if (entry.origin === conn || entry.holder === conn) {
            this._forwardTable.delete(cid);
          } else if (entry.fanout && entry.fanout.has(conn)) {
            entry.fanout.delete(conn);
          }
        }
      }
    });
  }

  // ── Ownership registration ────────────────────────────────────────────────

  /**
   * registerOwned(data, k) — register raw object data as owned by this node
   *
   * Computes the triple hash and stores the private mapping
   * cid3 → { cid1, cid2, h1, h2, k } so we can respond to privacy requests.
   *
   * The HMAC key k is used to compute CID³ = HMAC_k(CID²). It must be kept
   * secret by the owner; it is delivered to requesters out-of-band (alongside
   * CID³ — e.g. via the DHT record or a shared channel), NOT during the Bitswap
   * handshake. If k is omitted, a fresh random 32-byte key
   * is generated automatically.
   *
   * @param {Buffer}        data — raw object bytes
   * @param {Buffer|string} [k]  — 32-byte HMAC key (generated if omitted)
   * @returns {{ cid1, cid2, cid3, k }} the three CIDs and the HMAC key
   */
  registerOwned(data, k) {
    const hmacKey = k ? (Buffer.isBuffer(k) ? k : Buffer.from(k)) : randomBytes(32);
    const { cid1, cid2, cid3, h1, h2 } = tripleHash(data, hmacKey);
    // Store only metadata — do NOT keep full bytes in memory (unbounded growth risk).
    // Raw data is persisted in the block store below and fetched on demand when serving.
    this._owned.set(cid3.string, { cid1, cid2, h1, h2, k: hmacKey });
    // Also store raw data under cid1 so wantBlock / getPublic can serve it
    this.store.put(cid1.string, data);
    return { cid1, cid2, cid3, k: hmacKey };
  }

  // ── Standard Bitswap: requester side ─────────────────────────────────────

  /**
   * wantBlock(cidString, conn) → Promise<Buffer>
   *
   * Standard block request: WANT_HAVE → WANT_BLOCK → receive BLOCK.
   * Returns the raw block bytes.
   *
   * @param {string}     cidString
   * @param {Connection} conn
   * @returns {Promise<Buffer>}
   */
  wantBlock(cidString, conn) {
    return new Promise((resolve, reject) => {
      if (this._pending.size >= MAX_PENDING) {
        return reject(new Error('Too many pending requests'));
      }
      // Step 1: WANT_HAVE
      this._send(conn, MessageType.WANT_HAVE, cidString);

      // Register pending request
      const timeout = setTimeout(() => {
        this._pending.delete(cidString);
        reject(new Error(`Timeout waiting for block: ${cidString.slice(0, 20)}...`));
      }, 15000);

      this._pending.set(cidString, { resolve, reject, timeout, peerId: conn.remotePeer.id, conn });
    });
  }

  // ── Privacy protocol: requester side (Node A) ─────────────────────────────

  /**
   * requestPrivate(cid3String, cid1Digest, conn) → Promise<Buffer>
   *
   * Full 4-step privacy handshake from requester's perspective.
   * Session key K_AB is derived via Diffie-Hellman during the handshake
   * (provides forward secrecy per paper Figure 2).
   *
   * @param {string} cid3String   — CID³ string (what we search for)
   * @param {Buffer} cid1Digest   — raw h1 = H(OBJ), used to verify the response
   * @param {import('../libp2p/transport.js').Connection} conn
   * @returns {Promise<Buffer>} the decrypted object bytes
   */
  requestPrivate(cid3String, cid1Digest, conn) {
    return new Promise((resolve, reject) => {
      if (this._pending.size >= MAX_PENDING) {
        return reject(new Error('Too many pending requests'));
      }
      // Step 1 → WANT_HAVE(CID³)
      this._send(conn, MessageType.WANT_HAVE, cid3String);
      this.emit('handshake:step', { step: 1, total: 4, peerId: conn.remotePeer.id, cid: cid3String, message: 'WANT_HAVE(CID³) sent' });

      const timeout = setTimeout(() => {
        this._pending.delete(cid3String);
        reject(new Error(`Privacy request timeout for: ${cid3String.slice(0, 20)}...`));
      }, 15000);

      this._pending.set(cid3String, {
        peerId: conn.remotePeer.id,
        conn,
        timeout,
        isPrivate: true,
        cid1Digest,
        // K will be derived via DH during Step 3 (set by PRIVACY_CHALLENGE handler)
        K: null,
        resolve,
        reject,
      });
    });
  }

  // ── Message handler (incoming) ────────────────────────────────────────────

  /**
   * _handleMessage(msg, conn) — route an incoming Bitswap message
   *
   * @param {{ type, cid, payload }} msg
   * @param {Connection}             conn
   */
  async _handleMessage(msg, conn) {
    const { type, cid, payload } = msg;
    const peerId = conn.remotePeer.id;
    const ledger = this._ledger(peerId);

    // ── Flood-forwarding hook (opt-in) ────────────────────────────────────────
    // Handled BEFORE local dispatch so a relay node never accidentally treats
    // a passing-through response as its own. The forward table tells us where
    // to send this message next; if there's no entry the message falls through
    // to the normal handlers below.
    if (FLOOD_FORWARD_ENABLED && this._forwardTable.has(cid)) {
      // Upstream direction: responses from downstream peers → back to origin.
      const upstreamResponseTypes = [
        MessageType.HAVE,
        MessageType.DONT_HAVE,
        MessageType.BLOCK,
        MessageType.PRIVACY_CHALLENGE,
        MessageType.PRIVACY_BLOCK,
      ];
      if (upstreamResponseTypes.includes(type)) {
        // Only intercept if the message is coming from a peer we broadcast to
        // (or the locked-in holder). If it's from origin, fall through — origin
        // is upstream, not downstream.
        const entry = this._forwardTable.get(cid);
        if (entry.origin !== conn) {
          this._forwardUpstream(cid, type, payload, conn);
          return;
        }
      }

      // Downstream direction: client follow-ups from origin → holder.
      const downstreamClientTypes = [
        MessageType.WANT_BLOCK,
        MessageType.PRIVACY_RESPONSE,
      ];
      if (downstreamClientTypes.includes(type)) {
        const entry = this._forwardTable.get(cid);
        if (entry.origin === conn && entry.holder) {
          this._forwardDownstream(cid, type, payload, conn);
          return;
        }
        // If origin === conn but holder not yet locked, drop silently — the
        // client shouldn't be sending follow-ups before the challenge arrives.
      }
      // For WANT_HAVE arriving again on a CID we're already forwarding, fall
      // through to the normal handler; the loop-guard in _tryFlood handles it.
    }

    // ── Serving side (we received a request) ─────────────────────────────────

    if (type === MessageType.WANT_HAVE) {
      if (this._owned.has(cid)) {
        // Privacy request — Step 2: send Sign(CID₂ ‖ PKB ‖ Gb), PKB, Gb
        // Per paper Figure 2: B generates ephemeral DH keypair, signs the
        // challenge binding CID₂, its public key, and Gb together.
        // This provides forward secrecy via the DH exchange.
        const owned = this._owned.get(cid);

        // Generate ephemeral DH keypair for this session
        const { privateKey: gb, publicKey: Gb } = generateDHKeyPair();

        // Store gb temporarily so we can compute K_AB when PRIVACY_RESPONSE arrives
        // Key: cid + peerId to handle concurrent requests from different peers
        const dhKey = cid + ':' + peerId;
        if (!this._dhEphemeral) this._dhEphemeral = new Map();
        this._dhEphemeral.set(dhKey, { gb, Gb });

        // Sign (CID₂.digest ‖ PKB ‖ Gb) — binds DH parameter to the signature
        const pubKey = this.localPeer.publicKeyRaw;
        const signedData = Buffer.concat([owned.cid2.digest, pubKey, Gb]);
        const sig = sign(signedData, this.localPeer.privateKey);

        // Pack: [ Gb_length(2) | Gb(65) | sig_length(2) | sig | pubKey_length(2) | pubKey ]
        const packed = Buffer.alloc(2 + Gb.length + 2 + sig.length + 2 + pubKey.length);
        let off = 0;
        packed.writeUInt16BE(Gb.length, off);     off += 2;
        Gb.copy(packed, off);                     off += Gb.length;
        packed.writeUInt16BE(sig.length, off);    off += 2;
        sig.copy(packed, off);                    off += sig.length;
        packed.writeUInt16BE(pubKey.length, off); off += 2;
        pubKey.copy(packed, off);

        this._send(conn, MessageType.PRIVACY_CHALLENGE, cid, packed);
        ledger.bytesSent += packed.length;

      } else if (this.store.has(cid) && this._shouldServe(ledger)) {
        // Standard request — respond with HAVE
        this._send(conn, MessageType.HAVE, cid);
      } else if (FLOOD_FORWARD_ENABLED && this._tryFlood(cid, conn)) {
        // Flood forwarding took over — broadcast WANT_HAVE downstream.
        // Do NOT send DONT_HAVE here; the reply comes via _forwardTable.
      } else {
        this._send(conn, MessageType.DONT_HAVE, cid);
      }
      return;
    }

    if (type === MessageType.WANT_BLOCK) {
      if (this.store.has(cid) && this._shouldServe(ledger)) {
        const blockData = this.store.get(cid);
        this._send(conn, MessageType.BLOCK, cid, blockData);
        ledger.bytesSent += blockData.length;
      }
      return;
    }

    // ── Privacy Step 3: owner receives PRIVACY_RESPONSE ───────────────────────
    if (type === MessageType.PRIVACY_RESPONSE) {
      if (!this._owned.has(cid)) return;
      const owned = this._owned.get(cid);

      try {
        // Decrypt the payload with our private key
        const decrypted = eciesDecrypt(payload, this.localPeer.privateKey);

        // Real privacy request — paper Figure 2 Step 3:
        // Decrypted payload: [ CID₁ digest (32) | H(K_AB) (32) | Ga (65) ]
        if (decrypted.length < 32 + 32 + 65) {
          this._send(conn, MessageType.DONT_HAVE, cid);
          return;
        }
        const receivedCid1Digest = decrypted.slice(0, 32);
        const receivedHK         = decrypted.slice(32, 64);
        const Ga                 = decrypted.slice(64);

        // Verify CID¹: H(receivedCid1Digest) must equal cid2.digest
        const verifiedH2 = hash(receivedCid1Digest);
        if (verifiedH2.length !== owned.cid2.digest.length ||
            !timingSafeEqual(verifiedH2, owned.cid2.digest)) {
          this._send(conn, MessageType.DONT_HAVE, cid);
          return;
        }

        // Retrieve our ephemeral DH private key (gb) stored during Step 2
        const dhKey = cid + ':' + peerId;
        const dhEph = this._dhEphemeral?.get(dhKey);
        if (!dhEph) {
          this._send(conn, MessageType.DONT_HAVE, cid);
          return;
        }
        this._dhEphemeral.delete(dhKey); // one-time use

        // Compute K_AB = KDF(ECDH(gb, Ga))
        const K_AB = computeDHSecret(dhEph.gb, Ga);

        // Verify H(K_AB) matches what A sent — this proves both parties derived
        // the same session key (mutual key confirmation per the paper)
        const computedHK = createHash('sha256').update(K_AB).digest();
        if (!timingSafeEqual(computedHK, receivedHK)) {
          this._send(conn, MessageType.DONT_HAVE, cid);
          return;
        }

        // Fetch raw data from block store
        const rawData = this.store.get(owned.cid1.string);
        if (!rawData) {
          this._send(conn, MessageType.DONT_HAVE, cid);
          return;
        }

        // Encrypt OBJ with K_AB and send PRIVACY_BLOCK
        const encrypted = aesEncrypt(rawData, K_AB);
        this._send(conn, MessageType.PRIVACY_BLOCK, cid, encrypted);
        ledger.bytesSent += encrypted.length;

      } catch (err) {
        this._send(conn, MessageType.DONT_HAVE, cid);
      }
      return;
    }

    // ── Requesting side (we receive a response) ───────────────────────────────

    if (type === MessageType.HAVE) {
      const pending = this._pending.get(cid);
      if (!pending) return;
      // SECURITY: only accept HAVE from the peer we sent the request to
      if (pending.peerId && pending.peerId !== conn.remotePeer.id) return;
      // Upgrade to WANT_BLOCK
      this._send(conn, MessageType.WANT_BLOCK, cid);
      return;
    }

    if (type === MessageType.DONT_HAVE) {
      const errMsg = `Peer does not have block: ${cid.slice(0, 20)}...`;
      const pending = this._pending.get(cid);
      if (!pending) return;
      // SECURITY: only accept DONT_HAVE from the peer we sent the request to
      if (pending.peerId && pending.peerId !== conn.remotePeer.id) return;
      clearTimeout(pending.timeout);
      this._pending.delete(cid);
      pending.reject(new Error(errMsg));
      return;
    }

    if (type === MessageType.BLOCK) {
      const pending = this._pending.get(cid);
      if (!pending) return;
      // SECURITY: only accept BLOCK from the peer we sent the request to
      if (pending.peerId && pending.peerId !== conn.remotePeer.id) return;
      clearTimeout(pending.timeout);
      this._pending.delete(cid);
      ledger.bytesReceived += payload.length;
      pending.resolve(payload);
      return;
    }

    // ── Privacy Step 2 response: requester receives PRIVACY_CHALLENGE ─────────
    if (type === MessageType.PRIVACY_CHALLENGE) {
      // Check for privacy request first
      const pending = this._pending.get(cid);

      if (!pending?.isPrivate) return;

      // SECURITY: bounds check before parsing
      // New format: [ Gb_len(2) | Gb(65) | sig_len(2) | sig | pk_len(2) | pk ]
      if (payload.length < 2 + 65 + 2 + 2) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: payload too short'));
        return;
      }

      // Unpack: [ Gb_len(2) | Gb | sig_len(2) | sig | pk_len(2) | pk ]
      let off       = 0;
      const GbLen   = payload.readUInt16BE(off); off += 2;
      if (off + GbLen + 4 > payload.length) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: malformed payload'));
        return;
      }
      const Gb      = payload.slice(off, off + GbLen); off += GbLen;
      const sigLen  = payload.readUInt16BE(off); off += 2;
      if (off + sigLen + 2 > payload.length) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: malformed payload'));
        return;
      }
      const sig     = payload.slice(off, off + sigLen); off += sigLen;
      const pkLen   = payload.readUInt16BE(off); off += 2;
      if (off + pkLen > payload.length) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: malformed payload'));
        return;
      }
      const pubKeyRaw = payload.slice(off, off + pkLen);

      // SECURITY: verify the public key in the payload matches the key that was
      // authenticated during the TCP handshake.
      const expectedKey = conn.remotePeer.publicKeyRaw;
      if (pubKeyRaw.length !== expectedKey.length ||
          !timingSafeEqual(pubKeyRaw, expectedKey)) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: public key mismatch — possible MITM'));
        return;
      }

      // SECURITY: verify the signature over (CID₂ ‖ PKB ‖ Gb)
      // Per paper Figure 2: signature binds CID₂, B's identity, AND the DH parameter
      const expectedCid2Digest = hash(pending.cid1Digest);
      const signedData = Buffer.concat([expectedCid2Digest, pubKeyRaw, Gb]);
      if (!verify(signedData, sig, conn.remotePeer.publicKey)) {
        clearTimeout(pending.timeout);
        this._pending.delete(cid);
        pending.reject(new Error('PRIVACY_CHALLENGE: signature verification failed'));
        return;
      }

      this.emit('handshake:step', { step: 2, total: 4, peerId: conn.remotePeer.id, cid, message: 'PRIVACY_CHALLENGE verified — signature OK' });

      // Step 3: Generate ephemeral DH keypair, compute K_AB, send ECIES_PKB(CID₁ ‖ H(K_AB) ‖ Ga)
      const { privateKey: ga, publicKey: Ga } = generateDHKeyPair();
      const K_AB = computeDHSecret(ga, Gb);
      const HK = createHash('sha256').update(K_AB).digest();

      // Store K_AB for decrypting the response in Step 4
      pending.K = K_AB;

      const packed    = Buffer.concat([pending.cid1Digest, HK, Ga]);
      const encrypted = eciesEncrypt(packed, conn.remotePeer.publicKey);

      this._send(conn, MessageType.PRIVACY_RESPONSE, cid, encrypted);
      this.emit('handshake:step', { step: 3, total: 4, peerId: conn.remotePeer.id, cid, message: 'PRIVACY_RESPONSE sent (CID¹ + H(K_AB) + Ga)' });
      ledger.bytesSent += encrypted.length;
      return;
    }

    // ── Privacy Step 4: requester receives PRIVACY_BLOCK ─────────────────────
    if (type === MessageType.PRIVACY_BLOCK) {
      const pending = this._pending.get(cid);
      if (!pending?.isPrivate) return;
      clearTimeout(pending.timeout);
      this._pending.delete(cid);
      ledger.bytesReceived += payload.length;

      try {
        // Decrypt with K
        const decrypted = aesDecrypt(payload, pending.K);

        // Verify integrity: H(decrypted) should equal cid1Digest
        const actualHash = hash(decrypted);
        if (actualHash.length !== pending.cid1Digest.length ||
            !timingSafeEqual(actualHash, pending.cid1Digest)) {
          pending.reject(new Error('PRIVACY_BLOCK: content hash does not match CID¹'));
          return;
        }

        this.emit('handshake:step', { step: 4, total: 4, peerId: conn.remotePeer.id, cid, message: 'PRIVACY_BLOCK received and verified' });
        pending.resolve(decrypted);
      } catch (err) {
        pending.reject(new Error(`PRIVACY_BLOCK decrypt failed: ${err.message}`));
      }
      return;
    }

  }

  // ── Ledger / incentive ────────────────────────────────────────────────────

  /**
   * _shouldServe(ledger) → boolean
   *
   * Decides whether to serve a block to this peer based on their debt ratio.
   *
   * SWAP POINT — incentive strategy:
   *   Current rule: serve if debt ratio < 10 (peer has received < 10x what they sent).
   *   Replace this method with a sigmoid function, token bucket, or any other
   *   strategy to tune the incentive behaviour.
   *
   * @param {Ledger} ledger
   * @returns {boolean}
   */
  _shouldServe(ledger) {
    return ledger.debtRatio() < 10;
  }

  _ledger(peerId) {
    if (!this.ledgers.has(peerId)) {
      this.ledgers.set(peerId, new Ledger(peerId));
    }
    return this.ledgers.get(peerId);
  }

  // ── Wire helpers ──────────────────────────────────────────────────────────

  _send(conn, type, cid, payload = Buffer.alloc(0)) {
    const msg = encode(type, cid, payload);
    conn.sendMessage(BITSWAP_PROTO, msg);
  }

  // ── Flood forwarding helpers (only active when FLOOD_FORWARD_ENABLED) ─────

  /**
   * _tryFlood(cid, originConn) → boolean
   *
   * Called when an incoming WANT_HAVE finds nothing locally. Broadcasts the
   * WANT_HAVE to every OTHER connection so the request can reach a distant
   * holder along a chain of relays. Returns true if the flood was initiated
   * (caller must NOT send DONT_HAVE), false if the flood is a no-op
   * (no other peers to forward to, or already seen) so caller sends DONT_HAVE.
   *
   * @param {string}     cid
   * @param {Connection} originConn
   * @returns {boolean}
   */
  _tryFlood(cid, originConn) {
    if (!this._connections || this._connections.size < 2) return false;

    const now = Date.now();

    // Loop-protection: if we've already forwarded this CID recently, don't
    // rebroadcast — the earlier forward's origin will get the reply.
    // Special case: if the earlier forward's origin is the same conn, extend
    // the entry's timestamp so replies still find the origin.
    if (this._forwardSeen.has(cid)) {
      const existing = this._forwardTable.get(cid);
      if (existing) {
        existing.ts = now;
        return true; // pretend we forwarded — reply will come through existing entry
      }
      return false;
    }

    // Broadcast to every other connection.
    const fanout = new Set();
    for (const c of this._connections) {
      if (c === originConn) continue;
      try {
        this._send(c, MessageType.WANT_HAVE, cid);
        fanout.add(c);
      } catch {
        // dead conn — ignore
      }
    }
    if (fanout.size === 0) return false;

    this._forwardTable.set(cid, {
      origin: originConn,
      holder: null,
      fanout,
      dontHaveCount: 0,
      ts: now,
    });
    this._forwardSeen.set(cid, now);

    // Safety net: if nobody responds in time, tell upstream DONT_HAVE.
    setTimeout(() => {
      const e = this._forwardTable.get(cid);
      if (!e) return;
      this._forwardTable.delete(cid);
      try { this._send(e.origin, MessageType.DONT_HAVE, cid); } catch {}
    }, FORWARD_TTL_MS - 100).unref?.();

    return true;
  }

  /**
   * _forwardUpstream(cid, type, payload, senderConn) → boolean
   *
   * If this node has a forward entry for cid, forward the message to the
   * origin (upstream). On the first HAVE / PRIVACY_CHALLENGE we also lock in
   * the "holder" (so subsequent client→holder messages know where to go).
   * Returns true iff forwarding happened.
   *
   * DONT_HAVE forwarded downstream is aggregated: we only forward upstream
   * DONT_HAVE once ALL peers we broadcast to reply DONT_HAVE.
   */
  _forwardUpstream(cid, type, payload, senderConn) {
    if (!FLOOD_FORWARD_ENABLED) return false;
    const entry = this._forwardTable.get(cid);
    if (!entry) return false;

    // DONT_HAVE handling: aggregate — only propagate upstream when the last
    // downstream peer says DONT_HAVE.
    if (type === MessageType.DONT_HAVE) {
      entry.dontHaveCount++;
      if (entry.fanout.has(senderConn)) entry.fanout.delete(senderConn);
      if (entry.fanout.size === 0 && !entry.holder) {
        // All peers said DONT_HAVE, no holder locked — tell origin DONT_HAVE.
        this._forwardTable.delete(cid);
        try { this._send(entry.origin, MessageType.DONT_HAVE, cid); } catch {}
      }
      // If a holder already locked in, ignore stray DONT_HAVEs from other peers.
      return true;
    }

    // First positive reply — lock in the holder if not already.
    // These are the response types that indicate "I have it (in some form)".
    const isPositiveReply =
      type === MessageType.HAVE ||
      type === MessageType.PRIVACY_CHALLENGE ||
      type === MessageType.BLOCK ||
      type === MessageType.PRIVACY_BLOCK;

    if (isPositiveReply && !entry.holder) {
      entry.holder = senderConn;
    }

    // If a different peer than the locked holder is trying to reply, drop it
    // (this is standard bitswap "first response wins" behavior).
    if (entry.holder && entry.holder !== senderConn) return true;

    // Refresh timestamp and forward upstream.
    entry.ts = Date.now();
    try {
      this._send(entry.origin, type, cid, payload);
    } catch {
      // origin dead — drop entry.
      this._forwardTable.delete(cid);
    }

    // Terminal messages: the transaction is done, drop the forward entry.
    const isTerminal =
      type === MessageType.BLOCK ||
      type === MessageType.PRIVACY_BLOCK;
    if (isTerminal) this._forwardTable.delete(cid);

    return true;
  }

  /**
   * _forwardDownstream(cid, type, payload, senderConn) → boolean
   *
   * Client → holder direction. If we forwarded a WANT_HAVE for this cid and
   * senderConn is the original origin, forward the client-side follow-up
   * (WANT_BLOCK / PRIVACY_RESPONSE) to holder.
   * Returns true iff forwarding happened.
   */
  _forwardDownstream(cid, type, payload, senderConn) {
    if (!FLOOD_FORWARD_ENABLED) return false;
    const entry = this._forwardTable.get(cid);
    if (!entry) return false;
    if (entry.origin !== senderConn) return false; // not from the upstream origin
    if (!entry.holder) return false;                // holder not yet locked in
    entry.ts = Date.now();
    try {
      this._send(entry.holder, type, cid, payload);
    } catch {
      this._forwardTable.delete(cid);
    }
    return true;
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  /**
   * ledgerFor(peerId) → Ledger
   * @param {string} peerId
   */
  ledgerFor(peerId) {
    return this.ledgers.get(peerId) || new Ledger(peerId);
  }
}
