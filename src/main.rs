mod core;

use core::ledger::InMemoryLedger;

use crate::core::{
    block::Block,
    ledger::Ledger,
    miner,
    transaction::{Output, Transaction},
};
use blake2::Blake2s256;

fn main() {
    // Minimal startup log to avoid noisy stdout in library/runtime contexts.
    eprintln!("AUPP demo starting...");

    // Create an in-memory ledger
    let mut ledger = InMemoryLedger::new();

    // Build coinbase (genesis) block
    // The coinbase transaction contains the minting UTXO at output index 0.
    // We'll place a simple mask in the `commitment` field of the minting output.
    // A mask requiring ~2.5 bytes of zeros for a valid PoW solution.
    let mask = [0_u8; 32];
    let mut prev_tx_hash;

    let coinbase_tx = Transaction {
        version: core::Version::V1,
        inputs: vec![], // coinbase has no inputs
        outputs: vec![Output {
            amount: 100000,
            data: [0u8; 32],
            commitment: mask,
        }],
    };
    prev_tx_hash = coinbase_tx.hash::<Blake2s256>();

    let mut coinbase_block = Block::new(core::Version::V1, [0u8; 32]);
    coinbase_block.transactions.push(coinbase_tx);
    let coinbase_block_hash = coinbase_block.header().hash::<Blake2s256>();

    // Add genesis/coinbase block to ledger
    if let Err(e) = ledger.add_block(coinbase_block) {
        eprintln!("Failed to add genesis block: {:?}", e);
        return;
    }
    eprintln!(
        "Added genesis block. Hash: {}",
        hex::encode(&coinbase_block_hash)
    );

    loop {
        // Get the last block in the chain to mine on top of it
        let prev_block = match ledger.get_last_block_metadata() {
            Some(b) => b,
            None => {
                eprintln!("Ledger is empty: no last block metadata available. Exiting.");
                break;
            }
        };

        eprintln!(
            "\nMining Block #{} (on top of block with hash: {})...",
            prev_block.height + 1,
            hex::encode(prev_block.hash)
        );

        // Mine the next block. We use u64::MAX attempts to mine "forever" until a solution is found.
        match miner::build_next_block(&ledger, &prev_tx_hash, u64::MAX) {
            Some((_signing_key, new_block)) => {
                let new_block_hash = new_block.header().hash::<Blake2s256>();
                println!(
                    "Found a potential block! Hash: {}",
                    hex::encode(new_block_hash)
                );

                // Verify the new block before adding
                prev_tx_hash = new_block.transactions[0].hash::<Blake2s256>();
                if let Err(e) = ledger.add_block(new_block) {
                    eprintln!("Failed to add new block: {:?}", e);
                    continue;
                }
                eprintln!("Block #{} added to ledger.", prev_block.height + 1);
            }
            None => {
                // This should not happen with u64::MAX attempts
                eprintln!("Mining attempt failed unexpectedly; retrying.");
            }
        }
    }
}
