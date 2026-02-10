# EUPP — Experimental UTXO Payment Protocol

## Introduction
EUPP is a compact UTXO ledger that ties transaction semantics to consensus via the Lead UTXO model. It includes a stack-based VM for programmable spending conditions and a Chained Mask Proof-of-Work for block production.

See [WHITEPAPER.md](./WHITEPAPER.md) for the full protocol rationale and design details.

> [!WARNING]
> AI is used in the development and coding of this project.

## Components
- [eupp](./) — Node binary. Boots and runs a local node, orchestrates networking, mempool, block assembly, consensus validation, and persistence.
- [eupp-core](./eupp-core) — Core library. Defines blocks, transactions, the UTXO model, validation rules, and the VM used to enforce spending conditions.
- [eupp-net](./eupp-net) — Networking layer. Implements libp2p-based peer discovery, gossip, mempool sync, and RPC endpoints consumed by the node.
- [eupp-db](./eupp-db) — Storage backend. Durable store for blocks, indices, and UTXO state; intended to be the node's pluggable persistence layer.
- [eupp-cli](./eupp-cli) — Command-line tools. Small utilities to inspect peers/state, construct and sign transactions, and broadcast them to a running node.


## Requirements
- Rust (stable) + Cargo
- `gcc` (for some deps)

## Quick start

Clone:
```sh
git clone https://github.com/snakedye/eupp.git
cd eupp
```

## Build
```sh
cargo build --workspace --release
```

Build one crate:
```sh
cargo build -p eupp --release
```

## Run (single node)
1. Create a 32-byte secret (hex, 64 chars), e.g.:
```sh
openssl rand -hex 32
```
2. Export and run:
```sh
export EUPP_SECRET_KEY=<your-64-hex>
cargo run -p eupp --release
```

## Notes
- The node reads configuration from `.env` or environment variables. See [.env.template](./.env.template).
- Use `eupp-cli` to inspect peers, construct and broadcast transactions:
```sh
cargo run -p eupp-cli -- --help
```

## Contributing
1. Read the [WHITEPAPER.md](./WHITEPAPER.md)
2. Open issues or PRs for bugs and features

That's it — enough to build and run a local node.
