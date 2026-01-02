use eupp_core::{
    block::Block,
    ledger::{InMemoryLedger, Ledger},
    miner,
    transaction::{Output, Transaction},
};

fn main() {
    // Minimal startup log to avoid noisy stdout in library/runtime contexts.
    eprintln!("AUPP demo starting...");

    // Create an in-memory ledger
    let mut ledger = InMemoryLedger::new();

    // Build coinbase (genesis) block
    // The coinbase transaction contains the minting UTXO at output index 0.
    // We'll place a simple mask in the `commitment` field of the minting output.
    // A mask requiring ~2.5 bytes of zeros for a valid PoW solution.
    let mut mask = [0_u8; 32];
    mask[0] = 0xFF;
    mask[1] = 0x0F;

    let coinbase_tx = Transaction {
        inputs: vec![], // coinbase has no inputs
        outputs: vec![Output {
            version: eupp_core::transaction::Version::V0,
            amount: 100000,
            data: [0u8; 32],
            commitment: mask,
        }],
    };
    let mut genesis_block = Block::new(0, [0u8; 32]);
    genesis_block.transactions.push(coinbase_tx);
    let genesis_block_hash = genesis_block.header().hash();

    // Add genesis block to ledger
    if let Err(e) = ledger.add_block(genesis_block) {
        eprintln!("Failed to add genesis block: {:?}", e);
        return;
    }
    eprintln!(
        "Added genesis block. Hash: {}",
        hex::encode(&genesis_block_hash)
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

        // Mine the next block. We use usize::MAX attempts to mine "forever" until a solution is found.
        match miner::build_next_block(&ledger, usize::MAX) {
            Some((_signing_key, new_block)) => {
                let new_block_hash = new_block.header().hash();
                println!(
                    "Found a potential block! Hash: {}",
                    hex::encode(new_block_hash)
                );

                // Verify the new block before adding
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
