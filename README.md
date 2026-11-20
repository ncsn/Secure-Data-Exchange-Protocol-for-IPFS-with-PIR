# Secure Data Exchange Protocol for IPFS (with PIR)

Electron desktop application implementing the **Secure Data Exchange Protocol** for IPFS — a privacy-preserving file sharing system built on **keyed triple hashing** and an authenticated retrieval handshake. Based on the research paper *"Secure Data Exchange Protocol for IPFS"*.

## Table of Contents

- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Windows Setup](#windows-setup)
  - [WSL Setup (for Docker testing)](#wsl-setup-for-docker-testing)
  - [Install the Application](#install-the-application)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Features](#features)
- [Docker Multi-Node Testing](#docker-multi-node-testing)
- [Architecture](#architecture)
- [Testing](#testing)
- [Experimental Evaluation](#experimental-evaluation)
- [Usage Guide](#usage-guide)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Node.js** | 18+ | Runtime |
| **npm** | 9+ | Package manager |
| **Git** | 2.30+ | Version control |
| **Docker** | 20+ | Multi-node testing (optional) |
| **WSL 2** | Ubuntu 22.04+ | Docker on Windows (optional) |

### Windows Setup

1. **Install Node.js** (if not installed):
   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```
   Or download from https://nodejs.org

2. **Install Git** (if not installed):
   ```powershell
   winget install Git.Git
   ```

3. **Verify installations:**
   ```powershell
   node --version    # Should be 18+
   npm --version     # Should be 9+
   git --version
   ```

### WSL Setup (for Docker testing)

The Docker multi-node test environment requires WSL 2 with Docker. Skip this section if you only want to run the desktop app.

1. **Enable WSL 2** (run PowerShell as Administrator):
   ```powershell
   wsl --install
   ```
   Restart your computer if prompted.

2. **Install Ubuntu** (if not already present):
   ```powershell
   wsl --install -d Ubuntu-22.04
   ```

3. **Install Docker Desktop for Windows:**
   - Download from https://www.docker.com/products/docker-desktop/
   - During installation, enable **"Use WSL 2 based engine"**
   - After installation, open Docker Desktop > Settings > Resources > WSL Integration > Enable for your Ubuntu distro

4. **Verify Docker inside WSL:**
   ```bash
   wsl
   docker --version
   docker compose version
   ```

5. **Clone the repo inside WSL** (for Docker builds):
   ```bash
   # Inside WSL terminal
   cd ~
   git clone https://github.com/ncsn/Secure-Data-Exchange-Protocol-for-IPFS-with-PIR.git
   cd Secure-Data-Exchange-Protocol-for-IPFS-with-PIR
   ```

### Install the Application

**On Windows (for the desktop app):**
```powershell
git clone https://github.com/ncsn/Secure-Data-Exchange-Protocol-for-IPFS-with-PIR.git
cd Secure-Data-Exchange-Protocol-for-IPFS-with-PIR
npm install
```

**On WSL/Linux/macOS:**
```bash
git clone https://github.com/ncsn/Secure-Data-Exchange-Protocol-for-IPFS-with-PIR.git
cd Secure-Data-Exchange-Protocol-for-IPFS-with-PIR
npm install
```

---

## Quick Start

### Run the Desktop App

```bash
npm start
```

This launches the Electron app. Click **Start Node** in the sidebar to begin.

### Run the Docker Test Network (3 nodes)

```bash
cd docker
docker compose up --build
```

This starts Owner (port 4001), Peer1 (port 4002), and Requester (port 4003) and runs the retrieval benchmark end-to-end over the privacy protocol.

---

## How It Works

Standard IPFS publishes content-addressed CIDs to a public DHT. Anyone observing the network can link requesters to specific files. This project breaks that link with **keyed triple hashing**:

| CID | Derivation | Visibility | Purpose |
|-----|-----------|------------|---------|
| **CID1** | `H(file)` | Private (shared out-of-band) | Integrity check — requester verifies `H(data) == CID1` |
| **CID2** | `H(H(file))` | Secret (never leaves owner) | Ownership proof (signed challenge) |
| **CID3** | `HMAC_k(H(H(file)))` | Public (published to DHT) | Network discovery — keyed, so it cannot be reversed or dictionary-attacked |

The key difference from a plain `H(H(H(file)))` chain is that **CID3 is keyed**: it is `HMAC_k(CID2)` under a secret 32-byte key `k` chosen by the owner. Because `k` never appears on the wire, an observer who sees CID3 on the DHT cannot brute-force candidate files back to CID3 — a plain hash chain would be vulnerable to exactly that dictionary attack.

### Out-of-Band Key Delivery

`k` is delivered **out-of-band**, alongside CID3 — for example embedded in a DHT record, shared over a side channel, or handed to the recipient directly. It is **not** negotiated during the Bitswap handshake: the handshake is keyed on CID3, so deriving CID3 would be circular if `k` came from the handshake itself. A recipient therefore needs three things to retrieve a file: **CID1** (for the integrity check), **CID3** (for DHT discovery), and **`k`** (only the owner can recompute CID3, so the recipient receives CID3 directly rather than deriving it).

### The 4-Step Authenticated Privacy Protocol

```
Requester (A)                     Owner (B)
    |                                 |
    |--- WANT_HAVE(CID3) ------------>|   Step 1: A searches by the public, keyed CID3
    |<-- PRIVACY_CHALLENGE ---------- |   Step 2: B proves ownership (signs CID2) + sends DH public key
    |--- PRIVACY_RESPONSE ----------->|   Step 3: A sends encrypted CID1 + its DH public key
    |    K = HKDF(ECDH(A,B))          |           Both derive a shared session key via ECDH
    |<-- PRIVACY_BLOCK -------------- |   Step 4: B sends the AES-256-GCM-encrypted file
    |                                 |
    verify H(decrypted) == CID1 digest
```

The session key `K` is derived via **Elliptic Curve Diffie-Hellman** (ECDH on P-256) + HKDF-SHA256, providing forward secrecy — compromising a long-term key does not reveal past session keys.

---

## Features

### Desktop Application (8 Tabs)

- **Dashboard** — Peer ID, connections, storage, DHT peers. Privacy health score (based on connected peers). Network topology graph.
- **Add File** — Drag-and-drop or file browser. Computes keyed triple-hash CIDs, generates a random key `k`, and publishes CID1 + CID3 to the DHT. Returns CID1, CID3, and `k` (hex).
- **Get File** — Enter CID1, CID3, and the hex key `k` to retrieve. Visual 4-step protocol stepper shows handshake progress.
- **Storage** — Browse all local blocks, pin/unpin management, garbage collection, disk usage.
- **Peers** — Connect by IP:port, per-peer bandwidth stats, disconnect individual peers.
- **DHT** — Kademlia routing table: k-buckets, provider records, interactive lookup.
- **Event Log** — Real-time timestamped event stream.
- **Settings** — Listen port, announce IP, bootstrap peers, download path.
- **Toast Notifications** — Slide-in alerts for connections, transfers, and errors.

### Privacy Properties

- **No CID reversal** — CID3 = `HMAC_k(H(H(x)))` is keyed; without `k` it cannot be reversed to `x` or linked to a candidate file
- **Dictionary-attack resistance** — because `k` is never transmitted, an observer cannot enumerate guessed files to match a published CID3
- **Mutual authentication** — owner signs CID2 (ECDSA), requester encrypts CID1 with the owner's public key (ECIES)
- **End-to-end encryption** — ECIES key exchange + AES-256-GCM block encryption
- **Forward secrecy** — ECDH ephemeral key exchange makes each session key independent; compromise of long-term keys cannot decrypt past sessions

### Cryptographic Primitives

| Operation | Primitive |
|-----------|-----------|
| Content hashing | SHA-256 (32-byte digest) |
| Keyed CID3 | HMAC-SHA-256 under owner key `k` |
| Identity keys | ECDSA on NIST P-256 |
| Digital signatures | ECDSA-SHA256 (DER-encoded) |
| Key exchange | ECDH on P-256 + HKDF-SHA256 (forward secrecy) |
| Asymmetric encryption | ECIES with HKDF-SHA256 + AES-256-GCM |
| Session encryption | AES-256-GCM (12-byte IV, 16-byte auth tag) |

---

## Docker Multi-Node Testing

The Docker setup creates a 3-node benchmark network in a star topology:

```bash
cd docker
docker compose up --build
```

| Service | Port | Role |
|---------|------|------|
| **owner** | 4001 | Adds a test file, publishes CID1 + CID3 to the DHT |
| **peer1** | 4002 | DHT participant connected to the owner |
| **requester** | 4003 | Connects to the owner and retrieves via the privacy protocol |

All nodes run with `BITSWAP_FLOOD_FORWARD=1` and share the HMAC key through the `BENCH_HMAC_KEY` environment variable so CID3 is reproducible across the owner and the benchmark harness. In this baseline star topology flood forwarding adds no extra hops; the chain topology used for the scaling comparison is defined separately (see `bench-docker.mjs`).

### Connecting the Desktop App to Docker Nodes

1. Start Docker nodes: `docker compose up --build`
2. Start the desktop app: `npm start`
3. Go to the **Peers** tab and connect to `127.0.0.1:4001` (owner)
4. Use the CID1, CID3, and key `k` from the Docker owner's log to retrieve the file in the **Get File** tab

---

## Architecture

```
Electron Renderer (HTML/CSS/JS)
    |
    |  IPC (contextBridge)
    v
Electron Main Process (main.cjs)
    |
    |  controller/controller.cjs
    v
Core Node (src/)
    ├── node/       — Node class, orchestrates all subsystems
    ├── bitswap/    — Block exchange + authenticated privacy handshake
    ├── dht/        — Kademlia DHT + provider records
    ├── blockstore/ — Filesystem block storage + pinning + GC
    ├── cid/        — Keyed triple-hash CID computation + crypto
    ├── unixfs/     — File import/export (chunking, directories)
    ├── dag/        — DAG node serialization
    └── libp2p/     — TCP transport + peer identification
```

### Project Structure

```
.
├── main.cjs                 — Electron main process + IPC handlers
├── preload.cjs              — Context bridge (window.ipfs API)
├── get-file.mjs             — CLI retrieval tool
├── bench.mjs                — Local (in-process) benchmark
├── bench-docker.mjs         — Docker chain-topology scaling benchmark
├── controller/
│   └── controller.cjs       — Bridge: main process ↔ core node
├── renderer/
│   ├── index.html           — Single-page app (8 tab sections)
│   ├── renderer.js           — UI logic, event handling, topology canvas
│   └── styles.css           — Dark theme, cards, tables, animations
├── src/
│   ├── node/node.js         — Node class
│   ├── bitswap/bitswap.js   — Bitswap engine + privacy handshake
│   ├── dht/dht.js           — DHT node
│   ├── dht/kademlia.js      — Routing table + XOR distance
│   ├── blockstore/          — Block storage + pinning + GC
│   ├── cid/                 — CID + keyed triple-hash + crypto
│   ├── unixfs/              — File import/export
│   ├── dag/                 — DAG serialization
│   └── libp2p/              — TCP transport
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-node.mjs      — Docker entry point
└── package.json
```

---

## Testing

### Unit and Integration Tests

```bash
node src/libp2p/libp2p.test.js         # Transport + crypto (18 tests)
node src/bitswap/bitswap.test.js        # Bitswap + privacy protocol + DH key exchange (13 tests)
node src/node/node.test.js              # End-to-end integration (14 tests)
node src/dht/dht.test.js                # DHT routing + provider lookup (15 tests)
node src/cid/cid.test.js                # CID + keyed triple hash (8 tests)
node src/blockstore/blockstore.test.js  # Block storage + pinning (15 tests)
node src/unixfs/unixfs.test.js          # File chunking + directories (13 tests)
node src/dag/dag.test.js                # DAG serialization (8 tests)
```

### Performance Benchmark

```bash
node src/node/perf.test.js    # 50-iteration benchmark (2 nodes, localhost)
```

Measures the three core operations: TCP handshake (peer identification), file add + triple hash + DHT publish, and the 4-step privacy retrieval.

### Benchmark Harnesses (paper numbers)

```bash
node bench.mjs                                   # Privacy premium + crypto breakdown (local)
node bench-scaling.mjs --mode dht   --runs 30    # DHT lookup vs. node count (needs a star stack up)
node bench-scaling.mjs --mode chain --tail-port 4008 --hops 6 --runs 30   # plain relay vs. hops
```

The scaling harnesses dial a running Docker stack. Bring one up first, e.g.
`docker compose -f docker-compose.yml -f docker-compose.star8.yml up --build -d`
(star stacks for `--mode dht`, chain stacks for `--mode chain`). See
[Experimental Evaluation](#experimental-evaluation) for the measured results.

### Docker Integration Test

```bash
cd docker
docker compose up --build    # Owner → Requester retrieval benchmark
docker compose down
```

---

## Usage Guide

### Basic Workflow

1. Click **Start Node** in the sidebar
2. Add bootstrap peers in **Settings** (e.g. `127.0.0.1:4001` for Docker nodes)
3. Go to **Add File** — drop a file. Copy the **CID1**, **CID3**, and key **`k`** shown.
4. Share CID1, CID3, and `k` privately with the recipient (out-of-band)
5. Recipient enters CID1, CID3, and `k` in **Get File** — watches the 4-step protocol complete
6. File is saved to the Downloads folder

### Key Rules

| Value | Use in... | Notes |
|-------|-----------|-------|
| **CID1** | Get File | Private; used only for the integrity check |
| **CID3** | Get File / DHT discovery | Public; keyed, safe to publish |
| **CID2** | Never shared | Secret; stays on the owner |
| **`k`** | Get File | Secret HMAC key; delivered out-of-band with CID3 |

### CLI Retrieval

Because CID3 is keyed, it cannot be derived from CID1 — supply both CIDs (the recipient already has CID3 out-of-band):

```bash
node get-file.mjs <CID1> <CID3> <host> <port> [output-path]

# Example (from the Docker owner)
node get-file.mjs bafkrei...CID1 bafkrei...CID3 localhost 4001
node get-file.mjs bafkrei...CID1 bafkrei...CID3 localhost 4001 ./myfile.bin
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "Cannot find module" on `npm start` | Missing dependencies | Run `npm install` |
| Docker: "nonce missing or truncated" | Old Docker image cached | `docker compose build --no-cache && docker compose up` |
| Get File: "No providers found" | Not connected to the owner | Connect to the peer first in the Peers tab |
| Get File: "Peer does not have block" | Wrong CID3 or wrong key `k` | Use the exact CID3 and `k` the owner shared out-of-band |
| Get File: integrity/hash mismatch | Wrong CID1 digest | Use the CID1 the owner shared out-of-band |
| WSL: Docker commands not found | Docker Desktop WSL integration off | Docker Desktop > Settings > WSL Integration > Enable |

---

## Experimental Evaluation

All numbers below are measured on localhost (`node bench.mjs`) and against the Docker
multi-node stacks (`node bench-scaling.mjs`). The crypto primitives are averaged over
1000 iterations after a JIT warm-up; protocol operations over 20–30 runs.

### Privacy Premium (cost of the guarantees)

A plain Bitswap retrieval (`WANT_HAVE → HAVE → WANT_BLOCK → BLOCK`, no challenge, no
signature, no encryption) is compared against the 4-step privacy retrieval on the **same
payload**, so the delta isolates exactly what the privacy protocol costs.

| Retrieval (small file) | Latency |
|------------------------|---------|
| Plain fetch (no privacy) | 2.6 ms |
| Privacy fetch (4-step) | 4.5 ms |
| **Privacy premium** | **+1.9 ms (+72%)** |
| Privacy fetch, 1 MB file | 14.2 ms |

The privacy premium is a sub-2 ms, one-time handshake cost; it does not grow with file
size (the extra time for a 1 MB file is dominated by AES-GCM bulk encryption, below).

### Cryptographic Overhead Breakdown

Per-operation cost of the primitives the 4-step handshake is built from, measured in
isolation (no network). This shows exactly where the privacy latency goes.

| Primitive | Role in handshake | Cost (µs/op) |
|-----------|-------------------|--------------|
| ECDSA sign | Owner signs `CID2 ‖ PKB ‖ Gb` (Step 2) | 21 |
| ECDSA verify | Requester verifies ownership proof (Step 2) | 49 |
| ECDH ephemeral keygen | Fresh DH keypair per session (Steps 2 & 3) | 28 |
| ECDH secret + HKDF | Session-key derivation (both sides) | 91 |
| ECIES encrypt | Requester encrypts `CID1 ‖ H(K) ‖ Ga` (Step 3) | 152 |
| ECIES decrypt | Owner decrypts the response (Step 3) | 128 |
| AES-256-GCM encrypt (1 MB) | Owner encrypts the block (Step 4) | 1047 |
| AES-256-GCM decrypt (1 MB) | Requester decrypts the block (Step 4) | 981 |

The asymmetric handshake crypto totals well under 0.5 ms; bulk transfer is bounded by
AES-GCM throughput (~1 GB/s), as expected for a hybrid encryption scheme.

### Scaling

Two independent scaling dimensions are measured against the Docker stacks via
`bench-scaling.mjs` (see the star/chain compose overrides in `docker/`):

**DHT provider lookup vs. network size** (`--mode dht`, star topology). Measured at 3, 7,
and 8 nodes, `findProviders(CID3)` resolves in **~0.00 ms** across all sizes: once the
provider record is cached in the local Kademlia routing table (after warm-up), discovery
cost is dominated by the local table hit rather than by network size. In a larger,
latency-bearing deployment this is where real RTT would appear; in the in-memory test
network it is effectively free.

> **Note on the plain-relay dimension.** The chain topology (`--mode chain`,
> `docker-compose.chain8/13.yml`) relays a *plain* `wantBlock` hop-by-hop via
> flood-forwarding. The 4-step **privacy** handshake deliberately **cannot** be relayed
> this way: it is end-to-end authenticated, and the anti-MITM key-binding check
> (`bitswap.js`) rejects a challenge signed by anyone other than the directly-connected
> peer. This is a security property, not a limitation — privacy retrieval is always a
> direct, mutually-authenticated exchange between requester and owner.

## Formal Verification

The protocol has been formally verified using **ProVerif** under the Dolev-Yao adversarial model, confirming:
- Mutual authentication between requester and owner
- Key secrecy (session keys are not leaked)
- Resistance to MITM and replay attacks

---
