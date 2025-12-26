mod core;

use crate::core::{
    block::Block,
    ledger::Ledger,
    miner,
    transaction::{Output, Transaction},
};

fn main() {
    println!("AUPP demo: create coinbase block, add to ledger, then mine the second block");

    // Create an in-memory ledger
    let mut ledger = Ledger::new();

    // Build coinbase (genesis) block
    // The coinbase transaction contains the minting UTXO at output index 0.
    // We'll place a simple mask in the `public_key_hash` field of the minting output.
    let mask: [u8; 32] = [0x00u8; 32]; // mask for (Hash(x) & M) == 0

    let coinbase_tx = Transaction {
        version: core::Version::V1,
        inputs: vec![], // coinbase has no inputs
        outputs: vec![Output {
            amount: 0u64,         // arbitrary payload
            data_hash: [0u8; 32], // empty data hash for demo purposes
            commitment: mask,     // encoding the minting mask
        }],
    };
    let coinbase_tx_hash = coinbase_tx.hash::<blake2::Blake2s256>();

    let mut coinbase_block = Block::new(core::Version::V1, [0u8; 32]);
    coinbase_block.transactions.push(coinbase_tx);

    // Add genesis/coinbase block to ledger
    ledger.add_block(coinbase_block);
    println!(
        "Added coinbase (genesis) block to ledger. Chain height: {}",
        ledger.chain_len()
    );

    // Mine the second block by spending the minting UTXO from the previous (genesis) block.
    // The miner key is derived during mining; no separate miner destination is required here.

    // Retrieve reference to the previous block (genesis)
    let prev_block = ledger
        .get_block(&coinbase_tx_hash)
        .expect("expected genesis block present");

    // Attempt to mine: allow some number of attempts (deterministic miner wrapper uses random seed internally)
    let max_attempts = 10_000u64;

    println!("Starting mining attempt (up to {} tries)...", max_attempts);

    // Use the helper that mines and assembles the next block for us.
    match miner::build_next_block(prev_block, max_attempts) {
        Some((_signing_key, new_block)) => {
            println!("Found a valid mined block.");

            // Verify the new block against the previous block before adding
            if new_block.verify(&ledger).is_some() {
                ledger.add_block(new_block);
                println!(
                    "Mined second block and added to ledger. Chain height: {}",
                    ledger.chain_len()
                );
            }
        }
        None => {
            println!("Mining attempt failed (no solution found within attempt limit).");
        }
    }
}
