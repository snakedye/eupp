use eupp_core::{
    block::Block,
    ledger::{FullInMemoryLedger, Indexer},
    transaction::{Output, Transaction},
};
use eupp_net::{EuppNode, config::Config, mempool::SimpleMempool};
use std::net::SocketAddr;
mod api;

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

    // Create the EuppNode (do not block the current task yet)
    let node = EuppNode::new(config.clone(), ledger, mempool);

    // Obtain an RpcClient handle that can be cloned and used by the Axum handlers.
    // Note: The node's run() method sets up the internal RPC channel before entering
    // the main loop; the `rpc_client()` accessor returns a client that uses the node's
    // internal mpsc sender. We clone this client and move it into the HTTP server.
    let rpc_client = node.rpc_client();

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

    // Run the node in the current task. If it returns an error, log it.
    if let Err(e) = node.run().await {
        eprintln!("Node error: {:?}", e);
    }

    Ok(())
}
