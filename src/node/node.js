/**
 * node.js — Full IPFS-like node
 *
 * This is the top-level class that wires every component together into
 * a single, coherent system. All previous modules are implementation details
 * hidden behind a clean public API.
 *
 * ── Component map ─────────────────────────────────────────────────────────────
 *
 *   Node
 *     ├── PeerId          (identity — ECDSA key pair)
 *     ├── BlockStore      (local block persistence + pinning)
 *     ├── BitswapEngine   (block exchange + privacy handshake)
 *     ├── DHTNode         (content + peer discovery)
 *     └── TCPTransport    (network connections)
 *
 * ── Public API ────────────────────────────────────────────────────────────────
 *
 *   await node.start(port)               — start listening
 *   await node.connect(ip, port)         — dial a peer
 *   await node.stop()                    — shut down
 *
 *   await node.add(filePath, [opts])     — add a file, returns { cid1, cid2, cid3, k }
 *   await node.addBytes(bytes, [opts])   — add raw bytes
 *   await node.addDirectory(dirPath)     — add a directory recursively
 *
 *   await node.get(cid3Str, cid1Digest)  — retrieve a private file (privacy protocol)
 *   await node.getPublic(cid1Str)        — retrieve a standard (non-private) file
 *   await node.ls(cidStr)               — list directory contents
 *   await node.stat(cidStr)             — file metadata
 *
 *   node.id                             — this node's peer ID string
 *   node.multiaddr(ip)                  — this node's multiaddr string
 *
 * ── Data flows ────────────────────────────────────────────────────────────────
 *
 *  ADD:
 *    addFile(path)
 *      → UnixFS.addFile → blocks stored in BlockStore
 *      → BitswapEngine.registerOwned(rawBytes) → builds CID¹/²/³ map, generates HMAC key k
 *      → DHT.provide(cid1) + DHT.provide(cid3)  ← CID² and k never announced
 *      → return { cid1, cid2, cid3, k }
 *
 *  GET (privacy protocol):
 *    get(cid3, cid1Digest)
 *      → BlockStore.has(cid3)? return locally
 *      → DHT.findProviders(cid3) → list of peers
 *      → TCPTransport.dial(provider.ip, provider.port) → Connection
 *      → BitswapEngine.requestPrivate(cid3, cid1Digest, K, conn)
 *          → 4-step handshake → returns raw OBJ bytes
 *      → store received blocks in BlockStore
 *      → return bytes
 *
 *  GET PUBLIC (standard Bitswap):
 *    getPublic(cid1)
 *      → BlockStore.has(cid1)? return locally
 *      → DHT.findProviders(cid1) → peers
 *      → BitswapEngine.wantBlock(cid1, conn) → bytes
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';

import { PeerId }                              from '../libp2p/peer.js';
import { TCPTransport }                        from '../libp2p/transport.js';
import { BlockStore }                          from '../blockstore/blockstore.js';
import { BitswapEngine }                       from '../bitswap/bitswap.js';
import { DHTNode }                             from '../dht/dht.js';
import { addBytes as addBytesUnixFS,
         addDirectory as addDirectoryUnixFS }  from '../unixfs/importer.js';
import { cat, ls as lsUnixFS, stat as statUnixFS } from '../unixfs/exporter.js';

export class Node {
  /**
   * @param {object} [opts]
   * @param {string}  [opts.dataDir]    — where to store blocks (default: temp dir)
   * @param {boolean} [opts.ephemeral]  — use a temp dir, clean up on stop (default: false)
   * @param {string}  [opts.host]       — bind address for the TCP server (default: '0.0.0.0')
   * @param {string}  [opts.announceIp] — externally reachable IP to announce to the DHT
   *                                      (default: '127.0.0.1' for local use; set to your LAN/public IP
   *                                       when running across machines)
   * @param {number}  [opts.listenPort] — default port passed to start() (default: 0 = OS picks)
   */
  constructor(opts = {}) {
    const { dataDir, ephemeral = false,
            host = '0.0.0.0', announceIp, listenPort = 0 } = opts;

    this._ephemeral    = ephemeral;
    this._dataDir      = dataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'ipfs-node-'));
    this._host         = host;
    this._announceIp   = announceIp || '127.0.0.1';
    this._defaultPort  = listenPort;

    // ── Core components ──────────────────────────────────────────────────────
    this.peerId    = PeerId.create();
    this.store     = new BlockStore(this._dataDir);
    this.bitswap   = new BitswapEngine(this.store, this.peerId);
    this.dht       = new DHTNode(this.peerId, this._announceIp);
    this.transport = new TCPTransport(this.peerId);

    // Track our listen address
    this._listenAddr = null;

    // CIDs this node owns — used for periodic re-announcement to the DHT
    this._ownedCids          = new Set(); // Set of { cid1: string, cid3: string }
    this._reannounceInterval = null;

    // Wire transport → bitswap + dht on every new connection
    this.transport.on('connection', (conn) => {
      this.bitswap.addConnection(conn);
      this.dht.addConnection(conn, conn.remoteIp || '127.0.0.1', conn.remotePort || 0);
    });

    // Suppress unhandled error events from sub-components
    this.bitswap.on('error', err =>
      console.error(`[bitswap] ${err.message}`)
    );
    this.dht.on('error', err =>
      console.error(`[dht] ${err.message}`)
    );
  }

  // ── Identity ──────────────────────────────────────────────────────────────

  get id() { return this.peerId.id; }

  multiaddr(ip = '127.0.0.1') {
    if (!this._listenAddr) return null;
    return `/ip4/${ip}/tcp/${this._listenAddr.port}/p2p/${this.id}`;
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * start([port]) → Promise<number>  — start listening, returns bound port
   * @param {number} [port=0] — 0 = OS picks a free port
   */
  async start(port = this._defaultPort) {
    this._listenAddr = await this.transport.listen(port, this._host, this._announceIp);

    // Re-announce owned CIDs every 12 hours so provider records don't expire
    // (DHT TTL is 24 hours; re-announcing at 12h keeps records fresh)
    const REANNOUNCE_MS = 12 * 60 * 60 * 1000;
    this._reannounceInterval = setInterval(() => {
      const p = this._listenAddr?.port || 0;
      for (const { cid1, cid3 } of this._ownedCids) {
        this.dht.provide(cid1, p);
        this.dht.provide(cid3, p);
      }
    }, REANNOUNCE_MS);
    if (this._reannounceInterval.unref) this._reannounceInterval.unref();

    return this._listenAddr.port;
  }

  /**
   * connect(ip, port) → Promise<void>  — dial a peer and register with all engines
   */
  async connect(ip, port) {
    const conn = await this.transport.dial(ip, port);
    // TCPTransport also fires 'connection' on the listening side — but for the
    // dialing side we must register manually since the event doesn't fire here.
    this.bitswap.addConnection(conn);
    this.dht.addConnection(conn, ip, port);
    return conn;
  }

  /**
   * stop() — shut down all connections and clean up
   */
  async stop() {
    if (this._reannounceInterval) clearInterval(this._reannounceInterval);
    this.transport.stop();
    this.dht.stop();
    if (this._ephemeral) {
      fs.rmSync(this._dataDir, { recursive: true, force: true });
    }
  }

  // ── Write path ────────────────────────────────────────────────────────────

  /**
   * add(filePath, [opts]) → { cid1, cid2, cid3 }
   *
   * Adds a file from disk. Stores blocks, registers ownership,
   * and announces CID¹ + CID³ to the DHT.
   *
   * @param {string}  filePath
   * @param {object}  [opts]
   * @param {boolean} [opts.preserveMeta=false] — include mtime/mode in CID
   *   Default false so identical files always produce the same CID regardless
   *   of when they were modified. Set true to preserve filesystem metadata.
   * @returns {{ cid1: string, cid2: string, cid3: string, k: Buffer }}
   */
  async add(filePath, opts = {}) {
    const { preserveMeta = false } = opts;
    const bytes = fs.readFileSync(filePath);
    return this.addBytes(bytes, {
      name: path.basename(filePath),
      preserveMeta,
      ...opts,
    });
  }

  /**
   * addBytes(bytes, [opts]) → { cid1, cid2, cid3 }
   *
   * Adds raw bytes. Returns all three CIDs.
   * cid2 is returned for the owner's private use — never pass it to anyone else.
   *
   * @param {Buffer|Uint8Array} bytes
   * @param {object}            [opts]
   * @param {string}            [opts.name]
   * @param {Buffer|string}     [opts.k]  — optional 32-byte HMAC key for CID³ = HMAC_k(CID²).
   *   Pass a deterministic key when another party must independently derive the
   *   same CID³ (e.g. the Docker bench/requester). Omit for a fresh random key.
   */
  async addBytes(bytes, opts = {}) {
    const buf  = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const name = opts.name || '';

    // 1. Store blocks via UnixFS importer
    addBytesUnixFS(buf, this.store, {
      name,
      mtime: opts.preserveMeta ? Date.now() : 0,
      mode:  opts.mode || 0o644,
      pin:   true,
    });

    // 2. Register ownership in Bitswap (builds CID¹/²/³ map). When opts.k is
    //    provided, CID³ = HMAC_k(CID²) is deterministic; otherwise a fresh
    //    random 32-byte key is generated.
    const { cid1, cid2, cid3, k } = this.bitswap.registerOwned(buf, opts.k);

    // 3. Announce to DHT — CID¹ (standard) and CID³ (privacy) only
    //    CID² is NEVER announced — it is the secret proof of ownership
    const port = this._listenAddr?.port || 0;
    this.dht.provide(cid1.string, port);
    this.dht.provide(cid3.string, port);

    // Remember for periodic re-announcement
    this._ownedCids.add({ cid1: cid1.string, cid3: cid3.string });

    return { cid1: cid1.string, cid2: cid2.string, cid3: cid3.string, k };
  }

  /**
   * addDirectory(dirPath) → string  — returns directory root CID
   */
  async addDirectory(dirPath) {
    return addDirectoryUnixFS(dirPath, this.store, { pin: true });
  }

  // ── Read path ─────────────────────────────────────────────────────────────

  /**
   * get(cid3String, cid1Digest) → Promise<Buffer>
   *
   * Retrieves a private file using the full 4-step privacy handshake.
   *
   * @param {string} cid3String   — CID³ of the object (public search key)
   * @param {Buffer} cid1Digest   — raw 32-byte digest of CID¹ (H(OBJ))
   * @returns {Promise<Buffer>} decrypted file bytes
   */
  async get(cid3String, cid1Digest) {
    // Fast path: this node owns the object — serve directly from local store
    const owned = this.bitswap._owned.get(cid3String);
    if (owned) {
      const data = this.store.get(owned.cid1.string);
      if (data) return data;
    }

    // Try connected peers directly first (they may have it in their Bitswap engine)
    for (const [, conn] of this.transport.connections) {
      try {
        const bytes = await this.bitswap.requestPrivate(cid3String, cid1Digest, conn);
        return bytes;
      } catch {
        // This peer doesn't have it — try next
      }
    }

    // Fall back to DHT discovery
    const providers = await this.dht.findProviders(cid3String, 8000);
    if (providers.length === 0) {
      throw new Error(`No providers found for ${cid3String.slice(0, 20)}...`);
    }

    for (const provider of providers) {
      if (provider.peerId === this.id) continue; // skip ourselves
      try {
        let conn = this.transport.connections.get(provider.peerId);
        if (!conn) {
          conn = await this.connect(provider.ip, provider.port);
          // Give the remote peer a moment to register its message handlers
          // for this new connection before we send the first message.
          await new Promise(r => setTimeout(r, 20));
        }
        const bytes = await this.bitswap.requestPrivate(cid3String, cid1Digest, conn);
        return bytes;
      } catch {
        // Try next provider
      }
    }

    throw new Error(`Failed to retrieve ${cid3String.slice(0, 20)}... from all providers`);
  }

  /**
   * getPublic(cid1String) → Promise<Buffer>
   *
   * Standard (non-private) block retrieval via Bitswap.
   * Uses the DHT to find providers, then fetches with standard WANT_HAVE/BLOCK.
   */
  async getPublic(cid1String) {
    // Check local store first
    if (this.store.has(cid1String)) {
      return cat(cid1String, this.store);
    }

    // DHT lookup
    const providers = await this.dht.findProviders(cid1String, 8000);
    if (providers.length === 0) {
      throw new Error(`No providers found for ${cid1String.slice(0, 20)}...`);
    }

    for (const provider of providers) {
      if (provider.peerId === this.id) continue;
      try {
        let conn = this.transport.connections.get(provider.peerId);
        if (!conn) {
          conn = await this.connect(provider.ip, provider.port);
          await new Promise(r => setTimeout(r, 20));
        }
        const blockBytes = await this.bitswap.wantBlock(cid1String, conn);
        // Store received block
        this.store.put(cid1String, blockBytes);
        return blockBytes;
      } catch {
        // Try next
      }
    }

    throw new Error(`Could not fetch ${cid1String.slice(0, 20)}...`);
  }

  /**
   * ls(cidString) → Promise<Entry[]>  — list directory contents
   */
  async ls(cidString) {
    return lsUnixFS(cidString, this.store);
  }

  /**
   * stat(cidString) → Promise<UnixFSNode>  — file metadata
   */
  async stat(cidString) {
    return statUnixFS(cidString, this.store);
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  /**
   * info() → object  — summary of this node's state
   */
  info() {
    const bs = this.store.stat();
    const dh = this.dht.stat();
    return {
      peerId:        this.id,
      listenPort:    this._listenAddr?.port || null,
      blocks:        bs.blockCount,
      storageBytes:  bs.totalBytes,
      pinnedBlocks:  bs.pinnedCount,
      dhtPeers:      dh.peers,
      dhtProviders:  dh.providers,
      connections:   this.transport.connections.size,
    };
  }
}
