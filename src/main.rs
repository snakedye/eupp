use eupp_core::{
    block::Block,
    commitment,
    ledger::Indexer,
    transaction::{Output, Transaction, Version},
};
use eupp_db::RedbIndexer;
use eupp_net::{EuppNode, config::Config, mempool::SimpleMempool};
use std::net::SocketAddr;
mod api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("EUPP node starting...");

    // Create a config
    let config = Config::from_env()?;
    let public_key = config.public_key();

    // Create a ledger
    let mut ledger = RedbIndexer::from(config.index_db_path().expect("Index DB path not found"))
        .with_scanner(move |output| {
            let commitment = commitment(&public_key, Some(output.data().as_slice()));
            commitment.eq(output.address()) && output.version() == Version::V1
        })
        .with_fs(config.block_file_path().expect("Block file path not found"))
        .unwrap();

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
    if let Ok(_) = ledger.add_block(&genesis_block) {
        println!(
            "Added genesis block. Hash: {}",
            hex::encode(&genesis_block_hash)
        );
    }

    // Create a mempool
    let mempool = SimpleMempool::new();

    // Create the EuppNode (do not block the current task yet)
    let node = EuppNode::new(config.clone(), ledger, mempool);

    // Run the node in the current task. If it returns an error, log it.
    if let Err(e) = node
        .run(move |rpc_client| {
            // Build the Axum router using the `api` module (routes wired to RpcClient).
            // Wrap the RpcClient in an Arc and hand it to the router creator.
            let app = api::router(rpc_client);

            // Bind address (use port from config if present, otherwise 3000)
            let bind_port = config.port.unwrap_or(3000);
            let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
            println!("Starting HTTP API on http://{}", addr);

            // Spawn the HTTP server as a background task, and run the node in the main task.
            let server = axum::Server::bind(&addr).serve(app.into_make_service());
            let _server_handle = tokio::spawn(async move {
                if let Err(e) = server.await {
                    eprintln!("HTTP server error: {:?}", e);
                }
            });
        })
        .await
    {
        eprintln!("Node error: {:?}", e);
    }

    Ok(())
}
