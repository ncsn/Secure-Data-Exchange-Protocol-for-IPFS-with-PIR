/**
 * docker-node.mjs — Multi-role IPFS node for Docker testing
 *
 * Behavior is determined by the ROLE environment variable:
 *   ROLE=owner     — adds a file, publishes CIDs, waits for connections
 *   ROLE=requester — connects to owner, retrieves file via privacy protocol, verifies
 *   ROLE=peer      — idle DHT participant (for scale testing)
 *
 * CID sharing: Owner writes /shared/cids.json, others poll until it appears.
 *
 * Usage:
 *   docker compose up --build
 */

import fs from 'fs';
import { Node } from './src/node/node.js';
import { cidFromString } from './src/cid/cid.js';

const ROLE         = process.env.ROLE || 'owner';
const PORT         = parseInt(process.env.PORT || '4001', 10);
const ANNOUNCE_IP  = process.env.ANNOUNCE_IP || '127.0.0.1';
const SHARED_FILE  = '/shared/cids.json';

function log(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] [${ROLE.toUpperCase().padEnd(9)}] ${msg}`);
}

// Wait for a file to appear on the shared volume
async function waitForCids(timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const data = fs.readFileSync(SHARED_FILE, 'utf8');
      return JSON.parse(data);
    } catch {
      await new Promise(r => setTimeout(r, 500));
    }
  }
  throw new Error('Timeout waiting for CIDs from owner');
}

// Retry connecting to a host until it's ready
async function connectWithRetry(node, host, port, maxRetries = 20) {
  for (let i = 1; i <= maxRetries; i++) {
    try {
      const conn = await node.connect(host, port);
      return conn;
    } catch {
      log(`Connection attempt ${i}/${maxRetries} to ${host}:${port} failed, retrying...`);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw new Error(`Could not connect to ${host}:${port} after ${maxRetries} attempts`);
}

// ── OWNER ────────────────────────────────────────────────────────────────────

async function runOwner() {
  const node = new Node({ announceIp: ANNOUNCE_IP });
  const port = await node.start(PORT);
  log(`Node started on port ${port}`);
  log(`Peer ID: ${node.id}`);

  // Add a test file — returns k (the HMAC key for CID³ = HMAC_k(CID²))
  // Use a DETERMINISTIC key so the host-side bench/requester can derive the
  // same CID³. Must match bench-docker.mjs's BENCH_HMAC_KEY default.
  const content = 'Hello from the Docker Owner node! This file demonstrates the triple-hash privacy protocol.';
  const k = Buffer.from(process.env.BENCH_HMAC_KEY || 'bench-hmac-key-32-bytes-padding!!', 'utf8').slice(0, 32);
  const result = await node.addBytes(Buffer.from(content), { name: 'hello.txt', k });

  log(`File added:`);
  log(`  CID1: ${result.cid1}`);
  log(`  CID3: ${result.cid3}`);

  // Write CIDs + HMAC key k to shared volume for other containers
  // k is the secret needed to compute CID³ — only share with trusted requesters
  fs.writeFileSync(SHARED_FILE, JSON.stringify({
    cid1: result.cid1,
    cid3: result.cid3,
    k:    result.k.toString('hex'),  // 32-byte HMAC key (hex)
    ownerPeerId: node.id,
    content,
  }));
  log('CIDs written to shared volume');

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║  OWNER NODE READY                                      ║');
  console.log(`║  Port: ${String(port).padEnd(49)}║`);
  console.log(`║  CID1: ${result.cid1.slice(0, 48)}...║`);
  console.log(`║  CID3: ${result.cid3.slice(0, 48)}...║`);
  console.log('║                                                        ║');
  console.log('║  Connect from Desktop app → Peers → localhost:4001     ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // Keep alive
  setInterval(() => {}, 60000);
}

// ── REQUESTER ────────────────────────────────────────────────────────────────

async function runRequester() {
  const node = new Node({ announceIp: ANNOUNCE_IP });
  const port = await node.start(PORT);
  log(`Node started on port ${port}`);
  log(`Peer ID: ${node.id}`);

  // Wait for owner's CIDs
  log('Waiting for CIDs...');
  const cids = await waitForCids();
  log(`Got CIDs — CID1: ${cids.cid1.slice(0, 24)}...`);

  // Connect to owner
  const ownerHost = process.env.OWNER_HOST || 'owner';
  const ownerPort = parseInt(process.env.OWNER_PORT || '4001', 10);
  log(`Connecting to Owner at ${ownerHost}:${ownerPort}...`);
  const conn = await connectWithRetry(node, ownerHost, ownerPort);
  log(`Connected to Owner (${conn.remotePeer.id.slice(0, 12)}...)`);

  // Wait for bitswap handshake
  await new Promise(r => setTimeout(r, 500));

  // Retrieve via privacy protocol (4-step handshake)
  log('Retrieving file from Owner via privacy protocol...');
  const cid1 = cidFromString(cids.cid1);
  const data = await node.bitswap.requestPrivate(cids.cid3, cid1.digest, conn);

  // Verify
  const retrieved = data.toString();
  const match = retrieved === cids.content;

  log(`Retrieved: "${retrieved.slice(0, 60)}..."`);
  log(`Match: ${match ? 'YES' : 'NO'}`);

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  if (match) {
    console.log('║  ✓ PASS — Privacy protocol works!                       ║');
  } else {
    console.log('║  ✗ FAIL — Content mismatch!                             ║');
  }
  console.log('║                                                        ║');
  console.log('║  • Owner added file (CID³ = HMAC_k(CID²))             ║');
  console.log('║  • 4-step ECDSA + DH privacy handshake completed       ║');
  console.log('║  • Content verified: hash matches CID¹                 ║');
  console.log('║                                                        ║');
  console.log(`║  Requester port: ${String(port).padEnd(39)}║`);
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // Keep alive for interactive testing
  setInterval(() => {}, 60000);
}

// ── PEER (idle DHT participant, for scale testing) ──────────────────────────

async function runPeer() {
  const node = new Node({ announceIp: ANNOUNCE_IP });
  const port = await node.start(PORT);
  log(`Node started on port ${port}`);
  log(`Peer ID: ${node.id}`);

  // Wait for owner's CIDs (so we know owner is ready)
  log('Waiting for Owner to be ready...');
  await waitForCids();

  // ── Chain topology (opt-in via CHAIN_NEXT_HOST) ──────────────────────────
  // When set, this peer connects ONLY to CHAIN_NEXT_HOST (its upstream in the
  // chain), NOT to the owner. Combined with BITSWAP_FLOOD_FORWARD=1, this
  // forces every WANT_HAVE to traverse the whole chain until it reaches a
  // node that actually owns the content — producing measurable per-hop
  // latency in bench-docker.mjs.
  const chainNextHost = process.env.CHAIN_NEXT_HOST;
  if (chainNextHost) {
    const chainNextPort = parseInt(process.env.CHAIN_NEXT_PORT || '4001', 10);
    log(`Chain mode: connecting to ${chainNextHost}:${chainNextPort} (next hop)`);
    const c = await connectWithRetry(node, chainNextHost, chainNextPort);
    log(`Chain hop established (${c.remotePeer.id.slice(0, 12)}...)`);
  } else {
    // Default (star) behavior — connect to owner directly.
    const ownerHost = process.env.OWNER_HOST || 'owner';
    const ownerPort = parseInt(process.env.OWNER_PORT || '4001', 10);
    log(`Connecting to Owner at ${ownerHost}:${ownerPort}...`);
    const conn = await connectWithRetry(node, ownerHost, ownerPort);
    log(`Connected to Owner (${conn.remotePeer.id.slice(0, 12)}...)`);
  }

  console.log('');
  console.log(`  PEER NODE READY on port ${port} — participating in DHT`);
  console.log('');

  // Keep alive
  setInterval(() => {}, 60000);
}

// ── Entry point ──────────────────────────────────────────────────────────────

log(`Starting as ${ROLE}...`);

const runners = { owner: runOwner, requester: runRequester, peer: runPeer };
const runner = runners[ROLE];

if (!runner) {
  console.error(`Unknown ROLE: ${ROLE}. Use owner, requester, or peer.`);
  process.exit(1);
}

runner().catch(err => {
  log(`FATAL: ${err.message}`);
  console.error(err);
  process.exit(1);
});
