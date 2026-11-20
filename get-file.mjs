#!/usr/bin/env node

/**
 * get-file.mjs — CLI tool to retrieve a file using the privacy protocol
 *
 * CID³ is HMAC_k(H(H(file))) and therefore cannot be derived from CID¹ alone —
 * it is shared out-of-band (together with the key k) by the owner, exactly like
 * the desktop app's "Get File" tab. So both CID¹ and CID³ are supplied directly:
 * CID¹ provides the integrity digest, CID³ is the DHT discovery handle.
 *
 * Usage:
 *   node get-file.mjs <CID1> <CID3> <host> <port> [output-path]
 *
 * Example:
 *   node get-file.mjs bafkrei...CID1 bafkrei...CID3 127.0.0.1 4001
 *   node get-file.mjs bafkrei...CID1 bafkrei...CID3 localhost 4001 ./myfile.bin
 */

import fs from 'fs';
import path from 'path';
import { Node } from './src/node/node.js';
import { cidFromString } from './src/cid/cid.js';
import { hash } from './src/cid/crypto.js';

// ── Parse args ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.length < 4) {
  console.log('Usage: node get-file.mjs <CID1> <CID3> <host> <port> [output-path]');
  console.log('');
  console.log('  CID1        The private integrity CID (starts with "b", ~59 chars)');
  console.log('  CID3        The public discovery CID = HMAC_k(CID2), shared out-of-band');
  console.log('  host        IP or hostname of the owner/provider node');
  console.log('  port        TCP port of the owner/provider node');
  console.log('  output-path Optional output file path (default: ./retrieved-<cid>.bin)');
  process.exit(1);
}

const [cid1String, cid3String, host, portStr, outputArg] = args;
const port = parseInt(portStr, 10);

if (isNaN(port) || port < 1 || port > 65535) {
  console.error(`Invalid port: ${portStr}`);
  process.exit(1);
}

// ── Run ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('');
  console.log('IPFS Privacy Protocol — CLI File Retrieval');
  console.log('==========================================');
  console.log('');

  // Parse CID1 (integrity digest) and CID3 (discovery handle)
  let cid1, cid3;
  try {
    cid1 = cidFromString(cid1String);
  } catch (e) {
    console.error(`Invalid CID1: ${e.message}`);
    process.exit(1);
  }
  try {
    cid3 = cidFromString(cid3String);
  } catch (e) {
    console.error(`Invalid CID3: ${e.message}`);
    process.exit(1);
  }

  const h1 = cid1.digest;          // H(OBJ) — used for integrity verification

  console.log(`  CID1:  ${cid1String.slice(0, 40)}...`);
  console.log(`  CID3:  ${cid3String.slice(0, 40)}...`);
  console.log(`  Peer:  ${host}:${port}`);
  console.log('');

  // Create a temporary node
  const node = new Node({ announceIp: '127.0.0.1' });
  const listenPort = await node.start(0);
  console.log(`  Local node started on port ${listenPort}`);
  console.log(`  Peer ID: ${node.id}`);
  console.log('');

  // Connect to the target peer
  console.log(`  Connecting to ${host}:${port}...`);
  try {
    await node.connect(host, port);
  } catch (e) {
    console.error(`  Failed to connect: ${e.message}`);
    await node.stop();
    process.exit(1);
  }
  console.log('  Connected!');
  console.log('');

  // Small delay for handler registration
  await new Promise(r => setTimeout(r, 100));

  // Retrieve the file using the 4-step privacy protocol
  console.log('  Starting 4-step privacy handshake...');
  console.log('    Step 1: WANT_HAVE(CID3) →');

  let bytes;
  try {
    bytes = await node.get(cid3.string, h1);
  } catch (e) {
    console.error(`  Retrieval failed: ${e.message}`);
    await node.stop();
    process.exit(1);
  }

  console.log('    Step 2: ← PRIVACY_CHALLENGE (signature verified)');
  console.log('    Step 3: PRIVACY_RESPONSE (encrypted CID1 + K) →');
  console.log('    Step 4: ← PRIVACY_BLOCK (decrypted and verified)');
  console.log('');
  console.log(`  Retrieved ${bytes.length} bytes`);

  // Verify integrity
  const verifyHash = hash(bytes);
  const verified = Buffer.from(verifyHash).equals(Buffer.from(h1));
  console.log(`  Integrity: ${verified ? 'PASS — H(data) matches CID1' : 'FAIL — hash mismatch!'}`);

  // Save to file
  const outputPath = outputArg || `./retrieved-${cid1String.slice(1, 13)}.bin`;
  fs.writeFileSync(outputPath, bytes);
  console.log(`  Saved to: ${path.resolve(outputPath)}`);

  // Try to show content if it looks like text
  if (bytes.length < 2000) {
    try {
      const text = bytes.toString('utf8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(text.slice(0, 200))) {
        console.log('');
        console.log('  Content preview:');
        console.log('  ─────────────────────────────────────────');
        for (const line of text.split('\n').slice(0, 10)) {
          console.log(`  ${line}`);
        }
        if (text.split('\n').length > 10) console.log('  ...');
        console.log('  ─────────────────────────────────────────');
      }
    } catch {}
  }

  console.log('');
  console.log('Done.');

  await node.stop();
  process.exit(0);
}

main().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
