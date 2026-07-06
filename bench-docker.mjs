/**
 * bench-docker.mjs — Measure Table II protocol times against a running Docker stack.
 *
 * Unlike bench.mjs (which spawns its own 3 local nodes), this script:
 *   - Connects to the already-running Docker owner (localhost:4001) as the requester
 *   - Connects to the already-running Docker cache (localhost:4002) as the requester
 *   - Runs the 6 Table II operations 20 times each
 *   - Reports avg / min / max
 *
 * Usage:
 *   node bench-docker.mjs           # default: 20 runs
 *   node bench-docker.mjs --runs 50 # match the paper's 50 runs
 *
 * The number of Docker peer nodes (3/8/13) only affects the DHT population and
 * background gossip — the measured operations still target owner:4001 and cache:4002.
 */

import crypto from 'crypto';
import { Node } from './src/node/node.js';
import { cidFromString, CID } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';

const argv = process.argv.slice(2);
const runsIdx = argv.indexOf('--runs');
const RUNS = runsIdx >= 0 ? parseInt(argv[runsIdx + 1], 10) : 20;
const WARMUP = 2;

const OWNER_HOST = process.env.BENCH_OWNER_HOST || 'localhost';
const OWNER_PORT = parseInt(process.env.BENCH_OWNER_PORT || '4001', 10);
const CACHE_HOST = process.env.BENCH_CACHE_HOST || 'localhost';
const CACHE_PORT = parseInt(process.env.BENCH_CACHE_PORT || '4002', 10);

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
  console.log(`    Cache:  ${CACHE_HOST}:${CACHE_PORT}`);
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
  const connCache = await requester.connect(CACHE_HOST, CACHE_PORT);
  await new Promise(r => setTimeout(r, 300)); // let bitswap handshake settle

  // ── 2. File add + triple hash + DHT publish ──────────────────────────────
  // This is a local operation on the requester node — we still measure it
  // because it's what a real user does before publishing to the network.
  let lastAdd;
  await measure('File add + triple hash + DHT publish', async () => {
    const content = Buffer.from('Docker bench content ' + Math.random());
    lastAdd = await requester.addBytes(content, { name: 'bench.txt' });
  });

  // ── 3. Privacy retrieval (4-step) ────────────────────────────────────────
  // Retrieve the file that the Docker owner published on startup.
  // The Docker owner writes CID1 = bafkreig6cli4w2mkrmhnbcu7bdgeblsbeldl3ztzx7ytfttpnocrgicdme
  const ownerCid1Str = 'bafkreig6cli4w2mkrmhnbcu7bdgeblsbeldl3ztzx7ytfttpnocrgicdme';
  const ownerCid1 = cidFromString(ownerCid1Str);
  const ownerH1 = ownerCid1.digest;
  const ownerH2 = hash(ownerH1);
  const ownerH3 = hash(ownerH2);
  const ownerCid3 = new CID(ownerH3);

  await measure('Privacy retrieval (4-step)', async () => {
    await requester.bitswap.requestPrivate(ownerCid3.string, ownerH1, connOwner);
  });

  // ── 4. Decoy request (4-step, discarded) ────────────────────────────────
  await measure('Decoy request (4-step, discarded)', async () => {
    await requester.bitswap.sendDecoy(ownerCid3.string, connOwner);
  });

  // ── 5. Cache population (from owner) ────────────────────────────────────
  // A third-party cacher node asks the owner to serve encrypted content for caching.
  // Persistent cacher (setup once outside the measure loop) — mirrors the paper's
  // methodology: only the protocol overhead of requestCache() is measured,
  // not node bootstrap / TCP handshake / bitswap settle time.
  const cacher = new Node({ announceIp: '127.0.0.1' });
  await cacher.start(0);
  const cacherConn = await cacher.connect(OWNER_HOST, OWNER_PORT);
  await new Promise(r => setTimeout(r, 300)); // let bitswap handshake settle

  await measure('Cache population (from owner)', async () => {
    await cacher.bitswap.requestCache(ownerCid3.string, cacherConn);
  });

  // ── 6. Cache retrieval (from cache node) ────────────────────────────────
  // The Docker cache already has the owner's file cached. Retrieve from it.
  await measure('Cache retrieval (from cache node)', async () => {
    await requester.bitswap.requestFromCache(
      ownerCid3.string,
      ownerH1,
      crypto.randomBytes(32),
      connCache,
    );
  });

  console.log('');
  console.log('Done.');

  await cacher.stop();
  await requester.stop();
  process.exit(0);
}

main().catch(err => {
  console.error('BENCH ERROR:', err);
  process.exit(1);
});
