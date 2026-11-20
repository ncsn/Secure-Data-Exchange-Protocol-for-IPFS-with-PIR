/**
 * perf.test.js — Performance benchmark (50 iterations)
 *
 * Measures the three core operations of the privacy protocol:
 *   1. TCP handshake (peer identification)
 *   2. File add + triple hash + DHT publish
 *   3. Privacy retrieval (4-step authenticated handshake)
 *
 * Run with:  node src/node/perf.test.js
 */

import { Node } from './node.js';
import { hash } from '../cid/crypto.js';

const ITERATIONS = 50;

// ── Helpers ──────────────────────────────────────────────────────────────────

async function makeNode() {
  const n = new Node({ ephemeral: true });
  await n.start();
  return n;
}

function stats(times) {
  const sorted = [...times].sort((a, b) => a - b);
  const avg = times.reduce((s, t) => s + t, 0) / times.length;
  return {
    avg: avg.toFixed(1),
    min: sorted[0].toFixed(1),
    max: sorted[sorted.length - 1].toFixed(1),
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  console.log('\n══ Performance Benchmark (50 iterations, 2 nodes) ══════════\n');

  // Spin up 2 nodes: Owner and Requester
  const owner     = await makeNode();
  const requester = await makeNode();

  // Connect: requester → owner
  await requester.connect('127.0.0.1', owner._listenAddr.port);

  // Prepare a test file
  const testContent = Buffer.from('Performance test payload for benchmarking the privacy protocol.');

  // ── 1. TCP Handshake ────────────────────────────────────────────────────────
  const handshakeTimes = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const tempNode = await makeNode();
    const t0 = performance.now();
    await requester.connect('127.0.0.1', tempNode._listenAddr.port);
    handshakeTimes.push(performance.now() - t0);
    await tempNode.stop();
  }

  // ── 2. File add + triple hash + DHT publish ─────────────────────────────────
  const addTimes = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    await owner.addBytes(Buffer.from(`bench-payload-${i}-${Date.now()}`));
    addTimes.push(performance.now() - t0);
  }

  // ── 3. Privacy retrieval (4-step) ──────────────────────────────────────────
  // Add a file on owner, then retrieve it from requester
  const { cid3 } = await owner.addBytes(testContent);
  const h1 = hash(testContent);
  // Give DHT a moment to propagate
  await new Promise(r => setTimeout(r, 100));

  const retrievalTimes = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    await requester.get(cid3, h1);
    retrievalTimes.push(performance.now() - t0);
  }

  // ── Results ────────────────────────────────────────────────────────────────
  console.log('┌────────────────────────────────────────┬────────┬────────┬────────┐');
  console.log('│ Operation                              │ Avg    │ Min    │ Max    │');
  console.log('├────────────────────────────────────────┼────────┼────────┼────────┤');

  const results = [
    ['TCP handshake (peer identification)', handshakeTimes],
    ['File add + triple hash + DHT publish', addTimes],
    ['Privacy retrieval (4-step)', retrievalTimes],
  ];

  for (const [name, times] of results) {
    if (times.length === 0) {
      console.log(`│ ${name.padEnd(38)} │  N/A   │  N/A   │  N/A   │`);
      continue;
    }
    const s = stats(times);
    console.log(`│ ${name.padEnd(38)} │ ${(s.avg + ' ms').padStart(6)} │ ${(s.min + ' ms').padStart(6)} │ ${(s.max + ' ms').padStart(6)} │`);
  }

  console.log('└────────────────────────────────────────┴────────┴────────┴────────┘');
  console.log(`\n  Iterations: ${ITERATIONS} | Nodes: 2 (localhost)\n`);

  // Cleanup
  await owner.stop();
  await requester.stop();
}

run().catch(e => { console.error(e); process.exit(1); });
