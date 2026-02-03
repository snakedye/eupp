use eupp_core::{
    block::Block,
    ledger::{FullInMemoryLedger, Indexer},
    transaction::{Output, Transaction},
};
use eupp_net::{EuppNode, config::Config, mempool::SimpleMempool};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("EUPP node starting...");

    // Create an in-memory ledger
    let mut ledger = FullInMemoryLedger::new();

    // Build coinbase (genesis) block
    // The coinbase transaction contains the minting UTXO at output index 0.
    // A mask requiring 2.5 bytes of zeros for a valid PoW solution.
    let mut mask = [0_u8; 32];
    mask[0] = 0xFF;
    mask[1] = 0xFF;
    mask[2] = 0xF0; // 20 bits of zeros

    let coinbase_tx = Transaction {
        inputs: vec![], // coinbase has no inputs
        outputs: vec![Output::new_v0(std::u64::MAX, &mask, &[0; 32])],
    };
    let mut genesis_block = Block::new(0, [0u8; 32]);
    genesis_block.transactions.push(coinbase_tx);
    let genesis_block_hash = genesis_block.header().hash();

    // Add genesis block to ledger
    if let Err(e) = ledger.add_block(&genesis_block) {
        eprintln!("Failed to add genesis block: {:?}", e);
        return Ok(());
    }
    eprintln!(
        "Added genesis block. Hash: {}",
        hex::encode(&genesis_block_hash)
    );

    // Create a mempool
    let mempool = SimpleMempool::new();

    // Create a config
    let config = Config::from_env()?;

    // Create and run the EuppNode
    let mut node = EuppNode::new(config, ledger, mempool);
    println!("Launching network node...");
    node.run().await?;

    Ok(())
}
