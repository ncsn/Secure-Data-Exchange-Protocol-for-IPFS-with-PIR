/**
 * protocol.js — PIR private object retrieval protocol (paper §III,
 * "A kérés előkészítése", "A privát lekérés üzenetváltása", "Visszaállítás").
 *
 * Implements the per-server message exchange between the client U and each of the
 * k selected servers N_i, tying together the three primitive layers:
 *   - shamir.js      — K is reconstructed from the k returned key shares s_i
 *   - xorpir.js      — the k returned partial answers R_i XOR to the record C_j
 *   - collection.js  — C_j is AES-GCM decrypted and verified against H₃(O_j)
 *
 * A server is modelled as a PirServer object that holds its replica D = (C_1..C_m),
 * the signed index I_G, and its own Shamir share s_i. The two request/response
 * round trips mirror the paper exactly:
 *
 *   MAC_KEY_REQUEST / RESPONSE   → establishes a per-request MAC key a_i (ECIES)
 *   PIR_WANT_HAVE / PIR_HAVE     → establishes a per-request session key SK_i (ECIES),
 *                                  authenticated under a_i (HMAC)
 *   PIR_WANT_BLOCK / PIR_BLOCK   → carries (q_i, ρ_i) up and (R_i, s_i) back,
 *                                  both AES-GCM encrypted under SK_i
 *
 * Security properties enforced here: every response is signed by the serving node,
 * the first client message is MAC-authenticated under a_i so a server only answers a
 * request bound to the key it issued, c_i = H(r_i, ρ_i, q_i) is recomputed to bind the
 * masked query, and (G,j) context binding is checked on decrypt (in collection.js).
 */

import { randomBytes, createHmac, timingSafeEqual, createPublicKey } from 'crypto';
import { hash } from '../cid/crypto.js';
import {
  generateKeyPair, sign, verify, eciesEncrypt, eciesDecrypt,
  aesEncrypt, aesDecrypt,
} from '../libp2p/crypto.js';
import { verifyIndex, lookupSlot, decryptRecord, packetCid, H3 } from './collection.js';
import { reconstruct, shareToBuffer, shareFromBuffer } from './shamir.js';
import { splitQuery, answerQuery, combineAnswers } from './xorpir.js';

function hmacTag(key, data) {
  return createHmac('sha256', key).update(data).digest();
}
function eqConst(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * PirServer — one serving node N_i. Holds the collection replica, the signed
 * index, its signing key, its Shamir share, and the set of authorized client
 * verification keys. Keeps minimal per-request state so a request id r_i accepts
 * exactly one authenticated WANT_HAVE (replay protection, paper §III).
 */
export class PirServer {
  constructor({ i, records, index, share, nodeKey, authorizedClients }) {
    this.i = i;
    this.records = records;
    this.index = index;
    this.share = share;                 // {x,y}
    this.nodeKey = nodeKey;             // {privateKey, publicKey}
    this.authorizedClients = authorizedClients; // Map<clientId, KeyObject>
    this._pending = new Map();          // r_i → { a_i, Mi, usedWantHave, clientId }

    // When the signed index pins a packet CID (paper §III), a server must hold the
    // exact replica P published. Verify our stored D = (C_1..C_m) against it on
    // construction so a tampered or stale replica is caught before serving.
    if (index?.meta?.packetCid !== undefined) {
      if (packetCid(records) !== index.meta.packetCid) {
        throw new Error('pir: stored replica does not match signed packet CID');
      }
    }
  }

  get publicKey() { return this.nodeKey.publicKey; }

  /** MAC_KEY_REQUEST → MAC_KEY_RESPONSE. */
  handleMacKeyRequest(req) {
    const { collectionId, clientId, i, r, Bi, sigU } = req;
    if (i !== this.i) throw new Error('pir: request routed to wrong server');
    if (this._pending.has(r)) throw new Error('pir: duplicate request id');

    const clientPub = this.authorizedClients.get(clientId);
    if (!clientPub) throw new Error('pir: client not authorized');

    const Mi = Buffer.from(JSON.stringify({ collectionId, clientId, i, r, Bi }), 'utf8');
    const signed = Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]);
    if (!verify(signed, Buffer.from(sigU, 'base64'), clientPub)) {
      throw new Error('pir: MAC_KEY_REQUEST signature invalid');
    }

    const ai = randomBytes(32);                           // per-request MAC key
    const Ei = eciesEncrypt(ai, deserPubKey(Bi));         // encrypt to client B_i
    // Remember which client this request belongs to so WANT_BLOCK can re-check
    // authorization at serving time (closing the revocation TOCTOU window).
    this._pending.set(r, { ai, Mi, usedWantHave: false, clientId });

    const respSigned = Buffer.concat([Buffer.from('MAC_KEY_RESPONSE'), Mi, Ei]);
    const sigN = sign(respSigned, this.nodeKey.privateKey).toString('base64');
    return { r, Ei: Ei.toString('base64'), sigN };
  }

  /** PIR_WANT_HAVE → PIR_HAVE. */
  handleWantHave(msg) {
    const { r, ci, Xi, tau } = msg;
    const st = this._pending.get(r);
    if (!st) throw new Error('pir: unknown request id');
    if (st.usedWantHave) throw new Error('pir: WANT_HAVE already consumed');

    const Ai = Buffer.from(JSON.stringify({ r, ci, Xi }), 'utf8');
    const expectTau = hmacTag(st.ai, Buffer.concat([Buffer.from('PIR_WANT_HAVE'), st.Mi, Ai]));
    if (!eqConst(Buffer.from(tau, 'base64'), expectTau)) {
      throw new Error('pir: WANT_HAVE MAC invalid');
    }
    st.usedWantHave = true;
    st.ci = ci;

    const SKi = randomBytes(32);                          // per-request session key
    st.SKi = SKi;
    const Wi = eciesEncrypt(SKi, deserPubKey(Xi));
    // β signs the same request context τ_i binds (M_i‖A_i‖W_i), so the server's
    // signature covers the full request, not just the A_i wire fields.
    const haveSigned = Buffer.concat([Buffer.from('PIR_HAVE'), st.Mi, Ai, Wi]);
    const beta = sign(haveSigned, this.nodeKey.privateKey).toString('base64');
    return { r, Wi: Wi.toString('base64'), beta };
  }

  /** PIR_WANT_BLOCK → PIR_BLOCK. Returns the masked answer R_i and share s_i. */
  handleWantBlock(msg) {
    const { r, Li } = msg;                                // Li = enc_{SK_i}(q_i, ρ_i)
    const st = this._pending.get(r);
    if (!st || !st.SKi) throw new Error('pir: no session for request');

    // Re-check authorization at serving time: a client revoked after MAC_KEY_RESPONSE
    // (removed from authorizedClients) must not get a record back from an in-flight
    // request. The initial check in handleMacKeyRequest alone leaves a TOCTOU window.
    if (!this.authorizedClients.has(st.clientId)) {
      throw new Error('pir: client authorization revoked');
    }

    const plain = aesDecrypt(Buffer.from(Li, 'base64'), st.SKi);
    const rhoLen = 32;
    const rho = plain.slice(0, rhoLen);
    const qi = plain.slice(rhoLen);

    // Boundary check: q_i must be the packed bit-vector for exactly m records
    // (⌈m/8⌉ bytes). Rejects a malformed/oversized share before answerQuery.
    if (qi.length !== Math.ceil(this.index.meta.m / 8)) {
      throw new Error('pir: q_i length invalid');
    }

    // Recompute c_i = H(r_i, ρ_i, q_i) and compare to the committed value.
    // Constant-time over raw digest bytes to avoid a timing side-channel.
    const ci = hash(Buffer.concat([Buffer.from(String(r)), rho, qi]));
    if (!eqConst(ci, Buffer.from(st.ci, 'hex'))) throw new Error('pir: c_i commitment mismatch');

    const Ri = answerQuery(this.records, qi);             // R_i = ⊕ q_i[t]·C_t
    const back = Buffer.concat([Ri, shareToBuffer(this.share)]);
    const Li2 = aesEncrypt(back, st.SKi).toString('base64');
    this._pending.delete(r);                              // single-use request
    return { r, Li: Li2 };
  }
}

/**
 * pirRetrieve(target, servers, { collectionId, clientKey, uploaderPublicKey }) → Buffer
 *
 * Client U's full private retrieval of `target` (the plaintext object it wants)
 * against a set of k PirServers. Runs the three round trips per server, then
 * reconstructs K and C_j and decrypts. `servers` must be exactly the k selected
 * nodes (set S); their .i values and .share coordinates drive reconstruction.
 */
export async function pirRetrieve(target, servers, { collectionId, clientKey, uploaderPublicKey }) {
  const k = servers.length;
  if (k < 2) throw new Error('pir: need at least k=2 servers');

  // Local search: verify I_G and resolve slot j from H₃(target). The index is the
  // same signed object on every server; use the first.
  const index = servers[0].index;
  if (!verifyIndex(index, uploaderPublicKey)) throw new Error('pir: index signature invalid');
  const m = index.meta.m;
  const j = lookupSlot(index, H3(target));
  if (j < 0) throw new Error('pir: target not found in collection index');

  const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  // Resolve the verification key to check each server's signatures against. When the
  // signed index pins node keys (paper §III), bind to meta.nodes[i-1].verifyKey — a
  // server presenting a key P never signed for is then rejected, even if it holds a
  // self-consistent keypair. Without pinned nodes, fall back to the server's own key
  // (key-agnostic, backward compatible).
  const nodeVerifyKey = (srv) => {
    const nodes = index.meta.nodes;
    if (!nodes) return srv.publicKey;
    const entry = nodes[srv.i - 1];
    if (!entry) throw new Error(`pir: server ${srv.i} not present in signed index`);
    return createPublicKey({
      key: Buffer.from(entry.verifyKey, 'base64'), format: 'der', type: 'spki',
    });
  };

  // PIR query shares, one per selected server, XOR = e_j.
  const qShares = splitQuery(m, j, k);

  const answers = [];
  const keyShares = [];
  for (let idx = 0; idx < k; idx++) {
    const srv = servers[idx];
    const qi = qShares[idx];
    const r = randomBytes(8).toString('hex');            // fresh request id

    // Make a failure attributable to the server that caused it. The paper (§III)
    // has U restart with a fresh set S on failure; automatic failover is future
    // work — here we only re-throw with srv.i so the caller knows which node failed.
    try {
      // ── MAC_KEY_REQUEST / RESPONSE: obtain a_i ───────────────────────────────
      const Bkp = generateKeyPair();                        // ephemeral ECIES keypair B_i
      const Bi = serPubKey(Bkp.publicKey);
      const Mi = Buffer.from(JSON.stringify({ collectionId, clientId, i: srv.i, r, Bi }), 'utf8');
      const sigU = sign(Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]), clientKey.privateKey).toString('base64');
      const macResp = srv.handleMacKeyRequest({ collectionId, clientId, i: srv.i, r, Bi, sigU });

      const respSigned = Buffer.concat([Buffer.from('MAC_KEY_RESPONSE'), Mi, Buffer.from(macResp.Ei, 'base64')]);
      if (!verify(respSigned, Buffer.from(macResp.sigN, 'base64'), nodeVerifyKey(srv))) {
        throw new Error('pir: MAC_KEY_RESPONSE signature invalid');
      }
      const ai = eciesDecrypt(Buffer.from(macResp.Ei, 'base64'), Bkp.privateKey);

      // ── PIR_WANT_HAVE / PIR_HAVE: obtain SK_i, authenticated under a_i ────────
      const rho = randomBytes(32);
      const ci = hash(Buffer.concat([Buffer.from(String(r)), rho, qi])).toString('hex');
      const Xkp = generateKeyPair();                        // ephemeral ECIES keypair X_i
      const Xi = serPubKey(Xkp.publicKey);
      const Ai = Buffer.from(JSON.stringify({ r, ci, Xi }), 'utf8');
      const tau = hmacTag(ai, Buffer.concat([Buffer.from('PIR_WANT_HAVE'), Mi, Ai])).toString('base64');
      const have = srv.handleWantHave({ r, ci, Xi, tau });

      // Verify β over the same bound context (M_i‖A_i‖W_i) the server signed.
      const haveSigned = Buffer.concat([Buffer.from('PIR_HAVE'), Mi, Ai, Buffer.from(have.Wi, 'base64')]);
      if (!verify(haveSigned, Buffer.from(have.beta, 'base64'), nodeVerifyKey(srv))) {
        throw new Error('pir: PIR_HAVE signature invalid');
      }
      const SKi = eciesDecrypt(Buffer.from(have.Wi, 'base64'), Xkp.privateKey);

      // ── PIR_WANT_BLOCK / PIR_BLOCK: send (q_i, ρ_i), receive (R_i, s_i) ───────
      const Li = aesEncrypt(Buffer.concat([rho, qi]), SKi).toString('base64');
      const block = srv.handleWantBlock({ r, Li });
      const backPlain = aesDecrypt(Buffer.from(block.Li, 'base64'), SKi);
      const recordSize = index.meta.recordSize;
      const Ri = backPlain.slice(0, recordSize);
      const si = shareFromBuffer(backPlain.slice(recordSize));

      answers.push(Ri);
      keyShares.push(si);
    } catch (e) {
      throw new Error(`pir: server ${srv.i} failed: ${e.message}`);
    }
  }

  // ── Reconstruction at the client ───────────────────────────────────────────
  // Guard: Lagrange interpolation needs exactly the k shares the collection was
  // split for. Fewer than k reconstructs a wrong K silently; assert instead.
  if (keyShares.length < index.meta.k || answers.length < index.meta.k) {
    throw new Error(`pir: need ${index.meta.k} server responses, got ${keyShares.length}`);
  }
  const Cj = combineAnswers(answers);                     // ⊕ R_i = C_j
  const K = reconstruct(keyShares);                       // Lagrange f(0) = K
  const obj = decryptRecord(Cj, K, { collectionId, slot: j });

  // Final integrity check: recomputed H₃(O_j) must equal the requested tag.
  if (!H3(obj).equals(H3(target))) throw new Error('pir: integrity check failed (H₃ mismatch)');
  return obj;
}

// ── ECIES public-key (de)serialization for the wire ──────────────────────────
function serPubKey(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}
function deserPubKey(b64) {
  return createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}
