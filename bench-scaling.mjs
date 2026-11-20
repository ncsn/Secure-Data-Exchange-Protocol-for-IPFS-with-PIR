/**
 * bench-scaling.mjs — Element 2 scaling measurements against a running Docker stack.
 *
 * Two independent scaling dimensions (see README "Scaling"):
 *
 *   --mode dht   : DHT provider-lookup latency vs. network size (STAR stacks).
 *                  Dials owner:4001, times findProviders(CID3). Node count only
 *                  changes DHT population / discovery cost.
 *
 *   --mode chain : plain-fetch relay latency vs. hop count (CHAIN stacks).
 *                  Dials the chain TAIL port; a plain wantBlock floods hop-by-hop
 *                  up to the owner. Measures per-hop relay cost. This is the
 *                  NON-private path — the 4-step privacy handshake is end-to-end
 *                  authenticated and cannot be transparently relayed.
 *
 * Usage:
 *   node bench-scaling.mjs --mode dht   --runs 50
 *   node bench-scaling.mjs --mode chain --tail-port 4008 --hops 6 --runs 50
 */

import { Node } from './src/node/node.js';
import { cidFromString, CID } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';
import { createHmac } from 'crypto';

const argv = process.argv.slice(2);
const opt = (name, dflt) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : dflt; };
const MODE      = opt('--mode', 'dht');
const RUNS      = parseInt(opt('--runs', '50'), 10);
const WARMUP    = 3;
const TAIL_PORT = parseInt(opt('--tail-port', '4001'), 10);
const HOPS      = parseInt(opt('--hops', '0'), 10);
const OWNER_HOST = process.env.BENCH_OWNER_HOST || 'localhost';
const OWNER_PORT = parseInt(process.env.BENCH_OWNER_PORT || '4001', 10);

function stats(times) {
  const sorted = [...times].sort((a, b) => a - b);
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  return { avg, min: sorted[0], max: sorted[sorted.length - 1] };
}

async function measure(label, fn) {
  const times = [];
  for (let i = 0; i < WARMUP; i++) { try { await fn(); } catch {} }
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    await fn();
    times.push(performance.now() - t0);
  }
  const s = stats(times);
  console.log(`  ${label.padEnd(45)} avg=${s.avg.toFixed(2)}ms  min=${s.min.toFixed(2)}ms  max=${s.max.toFixed(2)}ms`);
  return s;
}

// CID3 derivation matching docker-node.mjs runOwner()'s fixed content + key.
const OWNER_CID1 = 'bafkreig6cli4w2mkrmhnbcu7bdgeblsbeldl3ztzx7ytfttpnocrgicdme';
const benchKey = Buffer.from(process.env.BENCH_HMAC_KEY || 'bench-hmac-key-32-bytes-padding!!', 'utf8').slice(0, 32);

async function main() {
  console.log('');
  console.log(`=== Scaling benchmark — mode=${MODE}, ${RUNS} runs (${WARMUP} warmup) ===`);

  const requester = new Node({ announceIp: '127.0.0.1' });
  await requester.start(0);

  if (MODE === 'dht') {
    const conn = await requester.connect(OWNER_HOST, OWNER_PORT);
    await new Promise(r => setTimeout(r, 400));
    const cid1 = cidFromString(OWNER_CID1);
    const h3 = createHmac('sha256', benchKey).update(hash(cid1.digest)).digest();
    const cid3 = new CID(h3);
    console.log(`    Owner: ${OWNER_HOST}:${OWNER_PORT}`);
    console.log('');
    await measure('DHT provider lookup', async () => {
      await requester.dht.findProviders(cid3.string, 5000);
    });
    conn.close?.();
  } else if (MODE === 'chain') {
    const conn = await requester.connect(OWNER_HOST, TAIL_PORT);
    await new Promise(r => setTimeout(r, 500)); // let the whole chain settle
    const cid1 = cidFromString(OWNER_CID1);
    console.log(`    Tail: ${OWNER_HOST}:${TAIL_PORT}  (hops=${HOPS})`);
    console.log('');
    await measure(`Plain fetch via ${HOPS}-hop chain`, async () => {
      await requester.bitswap.wantBlock(cid1.string, conn);
    });
    conn.close?.();
  } else {
    throw new Error(`Unknown --mode ${MODE} (use dht|chain)`);
  }

  console.log('');
  console.log('Done.');
  await requester.stop();
  process.exit(0);
}

main().catch(err => { console.error('BENCH ERROR:', err.message); process.exit(1); });
