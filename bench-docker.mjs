/**
 * bench-docker.mjs — Measure Table II protocol times against a running Docker stack.
 *
 * Unlike bench.mjs (which spawns its own local nodes), this script:
 *   - Connects to the already-running Docker owner (localhost:4001) as the requester
 *   - Runs the Table II operations 20 times each
 *   - Reports avg / min / max
 *
 * Usage:
 *   node bench-docker.mjs           # default: 20 runs
 *   node bench-docker.mjs --runs 50 # match the paper's 50 runs
 *
 * The number of Docker peer nodes (3/8/13) only affects the DHT population and
 * background gossip — the measured operations still target owner:4001.
 */

import { Node } from './src/node/node.js';
import { cidFromString, CID } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';
import { createHmac } from 'crypto';

const argv = process.argv.slice(2);
const runsIdx = argv.indexOf('--runs');
const RUNS = runsIdx >= 0 ? parseInt(argv[runsIdx + 1], 10) : 20;
const WARMUP = 2;

const OWNER_HOST = process.env.BENCH_OWNER_HOST || 'localhost';
const OWNER_PORT = parseInt(process.env.BENCH_OWNER_PORT || '4001', 10);

function stats(times) {
  const sorted = [...times].sort((a, b) => a - b);
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  return { avg, min: sorted[0], max: sorted[sorted.length - 1] };
}

async function measure(label, fn) {
  const times = [];
  // Warmup
  for (let i = 0; i < WARMUP; i++) {
    try { await fn(); } catch {}
  }
  for (let i = 0; i < RUNS; i++) {
    const start = performance.now();
    await fn();
    times.push(performance.now() - start);
  }
  const s = stats(times);
  console.log(`  ${label.padEnd(45)} avg=${s.avg.toFixed(1)}ms  min=${s.min.toFixed(1)}ms  max=${s.max.toFixed(1)}ms`);
  return s;
}

async function main() {
  console.log('');
  console.log(`=== Docker-stack Protocol Benchmark (${RUNS} runs each, ${WARMUP} warmup) ===`);
  console.log(`    Owner:  ${OWNER_HOST}:${OWNER_PORT}`);
  console.log('');

  // Requester node (host-side, will dial into the Docker containers)
  const requester = new Node({ announceIp: '127.0.0.1' });
  await requester.start(0);

  // ── 1. TCP handshake ────────────────────────────────────────────────────
  // Connect + disconnect to owner repeatedly. Each iteration is a fresh dial.
  await measure('TCP handshake (peer identification)', async () => {
    const throwaway = new Node({ announceIp: '127.0.0.1' });
    await throwaway.start(0);
    await throwaway.connect(OWNER_HOST, OWNER_PORT);
    await throwaway.stop();
  });

  // Persistent connections for the rest of the operations
  const connOwner = await requester.connect(OWNER_HOST, OWNER_PORT);
  await new Promise(r => setTimeout(r, 300)); // let bitswap handshake settle

  // ── 2. File add + triple hash + DHT publish ──────────────────────────────
  let lastAdd;
  await measure('File add + triple hash + DHT publish', async () => {
    const content = Buffer.from('Docker bench content ' + Math.random());
    lastAdd = await requester.addBytes(content, { name: 'bench.txt' });
  });

  // ── 3. Privacy retrieval (4-step) ────────────────────────────────────────
  // Retrieve the file that the Docker owner published on startup.
  // CID1 below is H(OBJ) of docker-node.mjs runOwner()'s fixed `content` string.
  // IMPORTANT: if that owner content changes, this literal must be updated to match.
  // The owner derives CID³ with the SAME key as BENCH_HMAC_KEY below (deterministic).
  const ownerCid1Str = 'bafkreig6cli4w2mkrmhnbcu7bdgeblsbeldl3ztzx7ytfttpnocrgicdme';
  const ownerCid1 = cidFromString(ownerCid1Str);
  const ownerH1 = ownerCid1.digest;
  const ownerH2 = hash(ownerH1);
  // HMAC key exchanged out-of-band for bench (docker-node.mjs uses the same key)
  const benchKey = Buffer.from(process.env.BENCH_HMAC_KEY || 'bench-hmac-key-32-bytes-padding!!', 'utf8').slice(0, 32);
  const ownerH3 = createHmac('sha256', benchKey).update(ownerH2).digest();
  const ownerCid3 = new CID(ownerH3);

  await measure('Privacy retrieval (4-step)', async () => {
    await requester.bitswap.requestPrivate(ownerCid3.string, ownerH1, connOwner);
  });

  // ── 4. DHT provider lookup ────────────────────────────────────────────────
  await measure('DHT provider lookup', async () => {
    await requester.dht.findProviders(ownerCid3.string, 5000);
  });

  console.log('');
  console.log('Done.');

  await requester.stop();
  process.exit(0);
}

main().catch(err => {
  console.error('BENCH ERROR:', err);
  process.exit(1);
});
