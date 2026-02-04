# **Experimental UTXO Payment Protocol (EUPP)**

**EUPP** is a minimal implementation of a UTXO-based ledger.

This repository is organized as a Cargo workspace with three crates:
- [eupp](./) — top-level binary that boots a local node.
- [eupp-core](./eupp-core) — core blockchain implementation (blocks, transactions, ledger, VM, etc.).
- [eupp-net](./eupp-net) — networking, mempool, and RPC protocol built on libp2p.
- [eupp-cli](./eupp-cli) — a small CLI used to query peers and construct/sign/broadcast transactions.

See [WHITEPAPER.md](./WHITEPAPER.md) for design details and protocol rationale.

## Requirements

- rust
- gcc

## Build

Build the whole workspace:

```sh
git clone https://github.com/snakedye/eupp.git
cargo build --workspace --release`
```

Build a single crate (example: the top-level node):
```sh
cargo build -p eupp --release
```

## Run a node

The `eupp` binary boots a simple node, configured from [environment variables](./.env.template) or a `.env` file:

#### Quick start (single node)
1. Generate a secret key (example using `openssl`):
   - `openssl rand -hex 32` (this prints 64 hex chars — use this as `EUPP_SECRET_KEY`)
   - Or: `xxd -l 32 -p /dev/urandom`

2. Export the key and run:
   - `export EUPP_SECRET_KEY=<your-64-hex-chars>`
   - `cargo run -p eupp --release`
