/**
 * bench.mjs — Measure protocol execution times for the research paper.
 * Runs each operation 20 times on localhost and reports averages.
 */

import { Node } from './src/node/node.js';
import { cidFromString, CID } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';

const RUNS = 20;

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
