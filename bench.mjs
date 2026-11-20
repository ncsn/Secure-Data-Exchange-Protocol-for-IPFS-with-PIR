/**
 * bench.mjs — Measure protocol execution times for the research paper.
 * Runs each operation 20 times on localhost and reports averages.
 */

import { Node } from './src/node/node.js';
import { cidFromString, CID } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';
import {
  generateKeyPair, generateDHKeyPair, computeDHSecret,
  sign, verify, eciesEncrypt, eciesDecrypt, aesEncrypt, aesDecrypt,
} from './src/libp2p/crypto.js';

const RUNS = 20;
const CRYPTO_RUNS = 1000; // crypto primitives are sub-ms — average over many iterations

async function measure(label, fn) {
  const times = [];
  for (let i = 0; i < RUNS; i++) {
    const start = performance.now();
    await fn();
    times.push(performance.now() - start);
  }
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);
  console.log(`  ${label.padEnd(45)} avg=${avg.toFixed(1)}ms  min=${min.toFixed(1)}ms  max=${max.toFixed(1)}ms`);
  return avg;
}

/**
 * measureMicro — time a synchronous primitive over CRYPTO_RUNS iterations and
 * report the per-operation average in microseconds. Used for the crypto
 * breakdown, where individual operations are well under a millisecond.
 */
function measureMicro(label, fn) {
  // Warm up the JIT so the first few (slow) calls don't skew the average.
  for (let i = 0; i < 50; i++) fn();
  const start = performance.now();
  for (let i = 0; i < CRYPTO_RUNS; i++) fn();
  const totalMs = performance.now() - start;
  const perOpUs = (totalMs / CRYPTO_RUNS) * 1000;
  console.log(`  ${label.padEnd(45)} ${perOpUs.toFixed(1).padStart(7)} µs/op  (${CRYPTO_RUNS}×)`);
  return perOpUs;
}

async function main() {
  console.log('');
  console.log('=== Protocol Benchmark (20 runs each) ===');
  console.log('');

  // Create two nodes
  const nodeA = new Node({ announceIp: '127.0.0.1' });
  const nodeB = new Node({ announceIp: '127.0.0.1' });
  const portB = await nodeB.start(0);

  // 1. TCP handshake (mutual auth)
  await measure('TCP handshake (mutual auth)', async () => {
    const portTemp = await nodeA.start(0);
    const conn = await nodeA.connect('127.0.0.1', portB);
    conn.close();
    await nodeA.stop();
  });

  // Re-start A and connect permanently
  const portA = await nodeA.start(0);
  const connAB = await nodeA.connect('127.0.0.1', portB);
  await new Promise(r => setTimeout(r, 50));

  // 2. File add + triple hash + DHT publish
  let addResult;
  const testKey = Buffer.alloc(32, 0xab); // fixed benchmark HMAC key
  await measure('File add + triple hash + DHT publish', async () => {
    const content = Buffer.from('Benchmark test content ' + Math.random());
    addResult = await nodeB.addBytes(content, { name: 'bench.txt', k: testKey });
  });

  // Prepare CIDs for retrieval. addBytes registered CID3 = HMAC_testKey(H(H(obj))),
  // so we re-derive it here under the same key.
  const cid1 = cidFromString(addResult.cid1);
  const h1 = cid1.digest;
  const h2 = hash(h1);
  const { createHmac } = await import('crypto');
  const h3 = createHmac('sha256', testKey).update(h2).digest();
  const cid3 = new CID(h3);

  // 3. Privacy retrieval (4-step)
  await measure('Privacy retrieval (4-step, small file)', async () => {
    await nodeA.bitswap.requestPrivate(cid3.string, h1, connAB);
  });

  // 4. DHT iterative lookup
  await measure('DHT provider lookup (2 nodes)', async () => {
    await nodeA.dht.findProviders(cid3.string, 5000);
  });

  // ── 6. Baseline: plain fetch vs. privacy fetch (the "privacy premium") ──────
  // Standard Bitswap retrieval is WANT_HAVE → HAVE → WANT_BLOCK → BLOCK with no
  // challenge, no signature, no encryption. registerOwned() stores the raw bytes
  // under cid1, so the owner serves them directly via wantBlock. Comparing this
  // against the 4-step privacy retrieval on the SAME payload isolates the cost
  // of the privacy guarantees.
  //
  // This runs on a FRESH pair of nodes. The incentive ledger on the main nodeB
  // has accumulated debt from the preceding privacy-retrieval loop (bytesSent ≫
  // bytesReceived), which pushes the debt ratio past the _shouldServe threshold
  // so nodeB refuses to serve a plain block. A clean pair sidesteps that state
  // entirely and gives a like-for-like comparison from zero debt.
  console.log('');
  const baseOwner = new Node({ announceIp: '127.0.0.1' });
  const baseReq   = new Node({ announceIp: '127.0.0.1' });
  const basePort  = await baseOwner.start(0);
  await baseReq.start(0);
  const baseConn  = await baseReq.connect('127.0.0.1', basePort);
  await new Promise(r => setTimeout(r, 50));

  const baseContent = Buffer.from('Baseline privacy-premium payload ' + Math.random());
  const baseAdd     = await baseOwner.addBytes(baseContent, { name: 'base.txt', k: testKey });
  const baseCid1    = cidFromString(baseAdd.cid1);
  const baseH1      = baseCid1.digest;
  const baseH2      = hash(baseH1);
  const baseH3      = createHmac('sha256', testKey).update(baseH2).digest();
  const baseCid3    = new CID(baseH3);

  // Each measured iteration resets the owner's ledgers first. A plain fetch is
  // purely one-way (owner sends a block, receives nothing), so the incentive
  // debt ratio climbs every iteration and would trip _shouldServe after ~10
  // fetches. We are timing protocol LATENCY here, not the incentive throttle
  // (which is a separate property), so we measure each fetch from neutral debt.
  const resetLedgers = (node) => {
    for (const ledger of node.bitswap.ledgers.values()) {
      ledger.bytesSent = 0;
      ledger.bytesReceived = 0;
    }
  };

  const plainAvg = await measure('Plain fetch (WANT_HAVE/BLOCK, no privacy)', async () => {
    resetLedgers(baseOwner);
    await baseReq.bitswap.wantBlock(baseCid1.string, baseConn);
  });
  const privAvg = await measure('Privacy fetch (4-step, same payload)', async () => {
    resetLedgers(baseOwner);
    await baseReq.bitswap.requestPrivate(baseCid3.string, baseH1, baseConn);
  });
  const premiumMs  = privAvg - plainAvg;
  const premiumPct = plainAvg > 0 ? (premiumMs / plainAvg) * 100 : 0;
  console.log(`  ${'→ Privacy premium'.padEnd(45)} +${premiumMs.toFixed(1)}ms  (+${premiumPct.toFixed(0)}% over plain)`);

  await baseReq.stop();
  await baseOwner.stop();

  // 5. Large file transfer
  const largeContent = Buffer.alloc(1024 * 1024, 0x42); // 1 MB
  const largeRes = await nodeB.addBytes(largeContent, { name: 'large.bin', k: testKey });
  const largeCid1 = cidFromString(largeRes.cid1);
  const largeH1 = largeCid1.digest;
  const largeH2 = hash(largeH1);
  const largeH3 = createHmac('sha256', testKey).update(largeH2).digest();
  const largeCid3 = new CID(largeH3);

  await measure('Privacy retrieval (4-step, 1 MB file)', async () => {
    await nodeA.bitswap.requestPrivate(largeCid3.string, largeH1, connAB);
  });

  // ── 7. Cryptographic overhead breakdown (per-operation cost of privacy) ─────
  // These are the primitives the 4-step handshake is built from. Measuring them
  // in isolation quantifies exactly where the privacy latency goes. No network.
  console.log('');
  console.log('  Cryptographic primitive breakdown:');

  // Identity keypairs for sign/verify and ECIES targets.
  const idKeys = generateKeyPair();

  // ECDSA — owner signs CID² ‖ PKB ‖ Gb (Step 2); requester verifies (Step 2).
  const signData = Buffer.concat([hash(h1), idKeys.publicKeyRaw, generateDHKeyPair().publicKey]);
  let sig;
  measureMicro('ECDSA sign (ownership proof)', () => { sig = sign(signData, idKeys.privateKey); });
  measureMicro('ECDSA verify', () => { verify(signData, sig, idKeys.publicKey); });

  // ECDH — ephemeral keygen (Steps 2 & 3) and shared-secret + HKDF (both sides).
  let dh;
  measureMicro('ECDH ephemeral keygen', () => { dh = generateDHKeyPair(); });
  const peerDH = generateDHKeyPair();
  measureMicro('ECDH secret + HKDF (session key)', () => { computeDHSecret(dh.privateKey, peerDH.publicKey); });

  // ECIES — requester encrypts CID₁ ‖ H(K_AB) ‖ Ga to the owner (Step 3).
  const eciesPayload = Buffer.concat([h1, Buffer.alloc(32), peerDH.publicKey]); // 32+32+65 bytes
  let eciesCt;
  measureMicro('ECIES encrypt (CID₁+H(K)+Ga)', () => { eciesCt = eciesEncrypt(eciesPayload, idKeys.publicKey); });
  measureMicro('ECIES decrypt', () => { eciesDecrypt(eciesCt, idKeys.privateKey); });

  // AES-256-GCM — owner encrypts OBJ with K_AB (Step 4). Measure on 1 MB so the
  // number reflects bulk-transfer throughput, not just fixed per-call overhead.
  const sessionKey = computeDHSecret(dh.privateKey, peerDH.publicKey);
  let aesCt;
  measureMicro('AES-256-GCM encrypt (1 MB payload)', () => { aesCt = aesEncrypt(largeContent, sessionKey); });
  measureMicro('AES-256-GCM decrypt (1 MB payload)', () => { aesDecrypt(aesCt, sessionKey); });

  console.log('');
  console.log('Done.');

  await nodeA.stop();
  await nodeB.stop();
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
