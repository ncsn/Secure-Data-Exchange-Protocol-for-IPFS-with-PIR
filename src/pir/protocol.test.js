/**
 * protocol.test.js — End-to-end tests for the PIR retrieval protocol.
 *
 * Run with:  node src/pir/protocol.test.js
 *
 * Tests:
 *   1. Full private retrieval returns the correct object (k in-process servers)
 *   2. Retrieval works for every object in the collection
 *   3. Unauthorized client is rejected at MAC_KEY_REQUEST
 *   4. Tampered MAC (wrong a_i) rejected at PIR_WANT_HAVE
 *   5. A server never sees the plaintext choice j (its q_i ≠ e_j)
 *   6. Requesting an object not in the collection fails cleanly
 *   7. Replayed request id is rejected (single-use)
 *   8. A malformed (wrong-length) q_i is rejected at PIR_WANT_BLOCK
 *   9. Signed index binds node verify keys; a substituted server key is rejected
 *  10. A client revoked after MAC_KEY_RESPONSE is rejected at PIR_WANT_BLOCK
 *  11. A server whose replica differs from the signed packet CID is rejected on construct
 *  12. Tampering index.meta after signing is rejected by verifyIndex
 */

import { randomBytes, createPublicKey } from 'crypto';
import { generateKeyPair, aesEncrypt, eciesDecrypt, sign } from '../libp2p/crypto.js';
import { hash } from '../cid/crypto.js';
import { setupCollection, verifyIndex, H3 } from './collection.js';
import { PirServer, pirRetrieve } from './protocol.js';
import { unitVector, vectorBytes } from './xorpir.js';

let passed = 0, failed = 0;
function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { console.log(`  ✓  ${name}`); passed++; })
    .catch(e => { console.log(`  ✗  ${name}`); console.log(`     ${e.message}`); failed++; });
}
function assert(c, m) { if (!c) throw new Error(m || 'Assertion failed'); }

const G = 'pir-protocol-collection';
const uploaderKey = generateKeyPair();

const OBJECTS = [
  Buffer.from('the first secret object'),
  Buffer.from('second object, a bit longer than the first one here'),
  Buffer.from('third'),
  randomBytes(40),
  Buffer.from('fifth and final object'),
];

/** Build k PirServers for threshold k, n total, authorizing clientKey.
 *  When `withNodes` is true, the collection index is set up with node-key binding
 *  (paper §III signed metadata), using the same keypairs assigned to the servers. */
function buildServers(k, n, clientKey, { withNodes = false } = {}) {
  const nodeKeys = [];
  for (let idx = 0; idx < n; idx++) nodeKeys.push(generateKeyPair());

  const setupOpts = { collectionId: G, k, n, uploaderKey };
  if (withNodes) {
    setupOpts.nodes = nodeKeys.map((kp, idx) => ({
      address: `node-${idx + 1}`, publicKey: kp.publicKey,
    }));
  }
  const c = setupCollection(OBJECTS, setupOpts);
  const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const authorizedClients = new Map([[clientId, clientKey.publicKey]]);
  const servers = [];
  for (let idx = 0; idx < n; idx++) {
    servers.push(new PirServer({
      i: idx + 1,                                 // x-coordinate = i (matches shamir)
      records: c.records,
      index: c.index,
      share: c.shares[idx],                       // s_i for coordinate i
      nodeKey: nodeKeys[idx],
      authorizedClients,
    }));
  }
  return { servers, collection: c, nodeKeys, authorizedClients };
}

async function main() {
  console.log('\n── PIR Protocol (end-to-end) Tests ───────────────────────────\n');

  // 1. Full retrieval
  await test('private retrieval returns the correct object', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(3, 5, clientKey);
    const S = servers.slice(0, 3);                 // select k=3 servers
    const got = await pirRetrieve(OBJECTS[2], S, {
      collectionId: G, clientKey, uploaderPublicKey: uploaderKey.publicKey,
    });
    assert(got.equals(OBJECTS[2]), 'retrieved object differs from target');
  });

  // 2. Every object retrievable
  await test('every object in the collection is retrievable', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(3, 5, clientKey);
    for (let j = 0; j < OBJECTS.length; j++) {
      const S = servers.slice(0, 3);
      const got = await pirRetrieve(OBJECTS[j], S, {
        collectionId: G, clientKey, uploaderPublicKey: uploaderKey.publicKey,
      });
      assert(got.equals(OBJECTS[j]), `object ${j} did not retrieve`);
    }
  });

  // 3. Unauthorized client
  await test('unauthorized client is rejected at MAC_KEY_REQUEST', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(3, 5, clientKey);
    const attacker = generateKeyPair();            // not in authorizedClients
    let threw = false;
    try {
      await pirRetrieve(OBJECTS[0], servers.slice(0, 3), {
        collectionId: G, clientKey: attacker, uploaderPublicKey: uploaderKey.publicKey,
      });
    } catch { threw = true; }
    assert(threw, 'attacker was not rejected');
  });

  // 4. Tampered MAC
  await test('tampered MAC (wrong a_i) is rejected at PIR_WANT_HAVE', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(2, 3, clientKey);
    const srv = servers[0];
    // Drive the first round manually, then feed a WANT_HAVE with a bad MAC.
    const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const r = 'deadbeef';
    const Bkp = generateKeyPair();
    const Bi = Bkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Mi = Buffer.from(JSON.stringify({ collectionId: G, clientId, i: srv.i, r, Bi }), 'utf8');
    const { sign } = await import('../libp2p/crypto.js');
    const sigU = sign(Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]), clientKey.privateKey).toString('base64');
    srv.handleMacKeyRequest({ collectionId: G, clientId, i: srv.i, r, Bi, sigU });
    let threw = false;
    try {
      srv.handleWantHave({ r, ci: 'x', Xi: Bi, tau: Buffer.alloc(32).toString('base64') });
    } catch { threw = true; }
    assert(threw, 'forged MAC accepted');
  });

  // 5. Server never sees the plaintext choice
  await test('a server\'s query share never equals the unit vector e_j', async () => {
    const clientKey = generateKeyPair();
    const { servers, collection } = buildServers(3, 5, clientKey);
    // Intercept what each server receives by wrapping answerQuery via handleWantBlock:
    // simplest check — inspect the shares the splitter would hand out are not e_j.
    const m = collection.index.meta.m;
    const j = 1;
    const { splitQuery } = await import('./xorpir.js');
    const qs = splitQuery(m, j, 3);
    const e = unitVector(m, j);
    assert(qs.every(q => q.length === vectorBytes(m)), 'share size wrong');
    assert(!qs.some(q => q.equals(e)), 'a server would receive the plaintext choice');
  });

  // 6. Object not in collection
  await test('requesting an object not in the collection fails cleanly', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(3, 5, clientKey);
    let threw = false;
    try {
      await pirRetrieve(Buffer.from('never uploaded'), servers.slice(0, 3), {
        collectionId: G, clientKey, uploaderPublicKey: uploaderKey.publicKey,
      });
    } catch (e) { threw = /not found/.test(e.message); }
    assert(threw, 'missing object did not fail with a not-found error');
  });

  // 7. Replay rejected
  await test('replayed request id is rejected (single-use)', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(2, 3, clientKey);
    const srv = servers[0];
    const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const { sign } = await import('../libp2p/crypto.js');
    const r = 'cafebabe';
    const Bkp = generateKeyPair();
    const Bi = Bkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Mi = Buffer.from(JSON.stringify({ collectionId: G, clientId, i: srv.i, r, Bi }), 'utf8');
    const sigU = sign(Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]), clientKey.privateKey).toString('base64');
    srv.handleMacKeyRequest({ collectionId: G, clientId, i: srv.i, r, Bi, sigU });
    let threw = false;
    try { srv.handleMacKeyRequest({ collectionId: G, clientId, i: srv.i, r, Bi, sigU }); }
    catch { threw = true; }
    assert(threw, 'duplicate request id accepted');
  });

  // 8. Malformed q_i length rejected at WANT_BLOCK
  await test('a malformed (wrong-length) q_i is rejected at PIR_WANT_BLOCK', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(2, 3, clientKey);
    const srv = servers[0];
    const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

    // Round 1: MAC_KEY_REQUEST/RESPONSE → recover a_i.
    const r = 'feedface';
    const Bkp = generateKeyPair();
    const Bi = Bkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Mi = Buffer.from(JSON.stringify({ collectionId: G, clientId, i: srv.i, r, Bi }), 'utf8');
    const sigU = sign(Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]), clientKey.privateKey).toString('base64');
    const macResp = srv.handleMacKeyRequest({ collectionId: G, clientId, i: srv.i, r, Bi, sigU });
    const ai = eciesDecrypt(Buffer.from(macResp.Ei, 'base64'), Bkp.privateKey);

    // Round 2: WANT_HAVE/HAVE → recover SK_i. Commit c_i over an oversized q_i.
    const m = srv.index.meta.m;
    const rho = randomBytes(32);
    const badQi = Buffer.alloc(vectorBytes(m) + 1);        // one byte too long
    const ci = hash(Buffer.concat([Buffer.from(String(r)), rho, badQi])).toString('hex');
    const Xkp = generateKeyPair();
    const Xi = Xkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Ai = Buffer.from(JSON.stringify({ r, ci, Xi }), 'utf8');
    const { createHmac } = await import('crypto');
    const tau = createHmac('sha256', ai)
      .update(Buffer.concat([Buffer.from('PIR_WANT_HAVE'), Mi, Ai])).digest().toString('base64');
    const have = srv.handleWantHave({ r, ci, Xi, tau });
    const SKi = eciesDecrypt(Buffer.from(have.Wi, 'base64'), Xkp.privateKey);

    // Round 3: submit the oversized q_i; the length guard must reject it.
    const Li = aesEncrypt(Buffer.concat([rho, badQi]), SKi).toString('base64');
    let threw = false;
    try { srv.handleWantBlock({ r, Li }); }
    catch (e) { threw = /q_i length invalid/.test(e.message); }
    assert(threw, 'oversized q_i was not rejected by the length guard');
  });

  // 9. Node-key binding: a substituted server signing key is rejected (#1)
  await test('signed index binds node verify keys; substituted server key is rejected', async () => {
    const clientKey = generateKeyPair();
    const { servers } = buildServers(3, 5, clientKey, { withNodes: true });

    // Sanity: with the genuine, index-bound keys, retrieval still works.
    const ok = await pirRetrieve(OBJECTS[1], servers.slice(0, 3), {
      collectionId: G, clientKey, uploaderPublicKey: uploaderKey.publicKey,
    });
    assert(ok.equals(OBJECTS[1]), 'bound-key retrieval failed');

    // Now swap server 1's keypair for one P never signed into the index. The
    // server still produces self-consistent signatures, but against the wrong key.
    const impostorKeys = buildServers(3, 5, clientKey).nodeKeys; // fresh unrelated keys
    const tampered = servers.slice(0, 3);
    tampered[0] = new PirServer({
      i: servers[0].i,
      records: servers[0].records,
      index: servers[0].index,
      share: servers[0].share,
      nodeKey: impostorKeys[0],                 // key not in the signed index
      authorizedClients: servers[0].authorizedClients,
    });
    let threw = false;
    try {
      await pirRetrieve(OBJECTS[1], tampered, {
        collectionId: G, clientKey, uploaderPublicKey: uploaderKey.publicKey,
      });
    } catch (e) { threw = /signature invalid/.test(e.message); }
    assert(threw, 'server with an unsigned key was accepted');
  });

  // 10. Authorization revoked mid-flight is rejected at WANT_BLOCK (#3)
  await test('client revoked after MAC_KEY_RESPONSE is rejected at PIR_WANT_BLOCK', async () => {
    const clientKey = generateKeyPair();
    const { servers, authorizedClients } = buildServers(2, 3, clientKey);
    const srv = servers[0];
    const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

    // Round 1: MAC_KEY_REQUEST/RESPONSE → a_i (client is still authorized here).
    const r = 'c0ffee11';
    const Bkp = generateKeyPair();
    const Bi = Bkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Mi = Buffer.from(JSON.stringify({ collectionId: G, clientId, i: srv.i, r, Bi }), 'utf8');
    const sigU = sign(Buffer.concat([Buffer.from('MAC_KEY_REQUEST'), Mi]), clientKey.privateKey).toString('base64');
    const macResp = srv.handleMacKeyRequest({ collectionId: G, clientId, i: srv.i, r, Bi, sigU });
    const ai = eciesDecrypt(Buffer.from(macResp.Ei, 'base64'), Bkp.privateKey);

    // Round 2: WANT_HAVE/HAVE → SK_i.
    const m = srv.index.meta.m;
    const rho = randomBytes(32);
    const qi = unitVector(m, 0);                 // any valid-length share
    const ci = hash(Buffer.concat([Buffer.from(String(r)), rho, qi])).toString('hex');
    const Xkp = generateKeyPair();
    const Xi = Xkp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const Ai = Buffer.from(JSON.stringify({ r, ci, Xi }), 'utf8');
    const { createHmac } = await import('crypto');
    const tau = createHmac('sha256', ai)
      .update(Buffer.concat([Buffer.from('PIR_WANT_HAVE'), Mi, Ai])).digest().toString('base64');
    const have = srv.handleWantHave({ r, ci, Xi, tau });
    const SKi = eciesDecrypt(Buffer.from(have.Wi, 'base64'), Xkp.privateKey);

    // Revoke the client between HAVE and WANT_BLOCK.
    authorizedClients.delete(clientId);

    // Round 3: the authorization re-check must reject the in-flight request.
    const Li = aesEncrypt(Buffer.concat([rho, qi]), SKi).toString('base64');
    let threw = false;
    try { srv.handleWantBlock({ r, Li }); }
    catch (e) { threw = /authorization revoked/.test(e.message); }
    assert(threw, 'revoked client still got a block answer');
  });

  // 11. Replica mismatch vs signed packet CID rejected on construct (#1)
  await test('a replica differing from the signed packet CID is rejected on construct', async () => {
    const clientKey = generateKeyPair();
    const { collection, nodeKeys } = buildServers(3, 5, clientKey, { withNodes: true });
    const clientId = clientKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

    // Corrupt one byte of the stored replica so packetCid(records) no longer matches.
    const badRecords = collection.records.map(r => Buffer.from(r));
    badRecords[0][badRecords[0].length - 1] ^= 0xff;

    let threw = false;
    try {
      new PirServer({
        i: 1, records: badRecords, index: collection.index, share: collection.shares[0],
        nodeKey: nodeKeys[0], authorizedClients: new Map([[clientId, clientKey.publicKey]]),
      });
    } catch (e) { threw = /packet CID/.test(e.message); }
    assert(threw, 'replica not matching the signed packet CID was accepted');
  });

  // 12. Tampered index.meta rejected by verifyIndex (#4)
  await test('tampering index.meta after signing is rejected by verifyIndex', async () => {
    const c = setupCollection(OBJECTS, { collectionId: G, k: 3, n: 5, uploaderKey });
    assert(verifyIndex(c.index, uploaderKey.publicKey), 'genuine index failed to verify');

    // Keep the valid (metaBytes, signature) pair but swap in a different meta object.
    const forged = {
      meta: { ...c.index.meta, collectionId: 'attacker-controlled' },
      metaBytes: c.index.metaBytes,
      signature: c.index.signature,
    };
    assert(!verifyIndex(forged, uploaderKey.publicKey), 'tampered index.meta was accepted');
  });

  console.log(`\n  ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main();
