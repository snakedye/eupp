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
    println!("AUPP demo: create coinbase block, then continuously mine.");

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
            data_hash: [0u8; 32],
            commitment: mask,
        }],
    };
    prev_tx_hash = coinbase_tx.hash::<Blake2s256>();

    let mut coinbase_block = Block::new(core::Version::V1, [0u8; 32]);
    coinbase_block.transactions.push(coinbase_tx);
    let coinbase_block_hash = coinbase_block.header().hash::<Blake2s256>();

    // Add genesis/coinbase block to ledger
    ledger.add_block(coinbase_block).unwrap();
    println!(
        "Added Genesis Block. Hash: {}",
        // ledger.chain_len(),
        hex::encode(&coinbase_block_hash)
    );

    loop {
        // Get the last block in the chain to mine on top of it
        let prev_block = ledger
            .get_last_block_metadata()
            .expect("chain should not be empty");

        println!(
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
                ledger.add_block(new_block).unwrap();
                println!(
                    "Block #{} is valid and added to ledger.",
                    prev_block.height + 1,
                );
            }
            None => {
                // This should not happen with u64::MAX attempts
                println!("Mining attempt failed unexpectedly. Retrying.");
            }
        }
    }
}
