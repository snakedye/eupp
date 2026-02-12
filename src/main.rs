mod api;
mod indexer;

use eupp_core::{
    SecretKey,
    block::Block,
    commitment,
    ledger::Indexer,
    miner,
    transaction::{Output, Transaction, Version},
};
use eupp_db::RedbIndexer;
use eupp_net::{EuppNode, RpcClient, SyncHandle, config::Config, mempool::SimpleMempool};
use indexer::NodeStore;
use rand::{TryRngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tracing::{Level, error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(Level::INFO.as_str())),
        )
        .init();

    info!("EUPP node starting...");

    // Create a config
    let config = Config::from_env()?;
    let public_key = config.public_key();

    // Create a ledger
    let mut indexer = config
        .index_db_path()
        .map(RedbIndexer::from)
        .unwrap_or_default()
        .with_scanner(move |output| {
            let commitment = commitment(&public_key, Some(output.data().as_slice()));
            commitment.eq(output.address()) && output.version() == Version::V1
        });

    // Store the public key in the recovery table
    indexer.store("public_key", public_key)?;

    // Build coinbase (genesis) block
    let mask = [0_u8; 32];

    let coinbase_tx = Transaction {
        inputs: vec![], // coinbase has no inputs
        outputs: vec![Output::new_v0(std::u64::MAX, &mask, &[0; 32])],
    };
    let mut genesis_block = Block::new(0, [0u8; 32]);
    genesis_block.transactions.push(coinbase_tx);
    let genesis_block_hash = genesis_block.header().hash();

    // Add genesis block to ledger
    if let Ok(_) = indexer.add_block(&genesis_block) {
        info!(
            hash = %hex::encode(&genesis_block_hash),
            "Added genesis block",
        );
    }

    // Select the node store
    let ledger = match config.block_file_path() {
        Some(path) => NodeStore::Full(indexer.with_fs(path)?),
        None => NodeStore::Pruned(indexer),
    };

    // Create a mempool
    let mempool = SimpleMempool::new();

    // Create the EuppNode (do not block the current task yet)
    let node = EuppNode::new(config.clone(), ledger, mempool);

    // Create handles for the node
    let sync = node.sync_handle();
    let indexer = node.indexer();

    // Run the node in the current task. If it returns an error, log it.
    if let Err(e) = node
        .run(move |rpc_client| {
            // Build the Axum router using the `api` module (routes wired to RpcClient).
            // Wrap the RpcClient in an Arc and hand it to the router creator.
            let app = api::router(rpc_client.clone());

            // Bind address (use port from config if present, otherwise 3000)
            let bind_port = config.api_port.unwrap_or(3000);
            let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
            info!(address = %addr, "Starting HTTP API");

            // Spawn the HTTP server as a background task, and run the node in the main task.
            let server = axum::Server::bind(&addr).serve(app.into_make_service());
            let _server_handle = tokio::spawn(async move {
                if let Err(e) = server.await {
                    error!("HTTP server error: {:?}", e);
                }
            });

            // Launch mining loop if difficulty is set.
            if let Some(difficulty) = config.difficulty {
                let secret_key = config.secret_key();
                tokio::spawn(mining_loop(
                    secret_key, rpc_client, indexer, sync, difficulty,
                ));
            }
        })
        .await
    {
        error!("Node error: {:?}", e);
    }

    Ok(())
}

/// Set the first `n` bits of a 32-byte array to 1.
/// Bits are filled starting from byte index 0, LSB-first within each byte.
fn set_n_bits(arr: &mut [u8; 32], n: usize) {
    let full_bytes = n / 8;
    let remaining_bits = n % 8;

    arr[..full_bytes.min(32)].fill(0xFF);

    if remaining_bits > 0 && full_bytes < 32 {
        arr[full_bytes] |= (1u8 << remaining_bits) - 1;
    }
}

/// Mine a block with the given difficulty.
async fn mining_loop<L: Indexer>(
    secret_key: SecretKey,
    rpc_client: RpcClient,
    ledger: Arc<RwLock<L>>,
    sync: SyncHandle,
    difficulty: usize,
) {
    let mut mask = [0_u8; 32];
    set_n_bits(&mut mask, difficulty);

    // Larger batch size for more mining attempts per iteration
    const BATCH_SIZE: usize = 10_000;

    loop {
        // Sleep for a second before checking sync status
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Check sync status before sleeping to avoid unnecessary delay
        if sync.is_synced() {
            continue;
        }

        let metadata = {
            let lg = ledger.read().unwrap();
            lg.get_last_block_metadata().and_then(|prev_block| {
                lg.get_output(&prev_block.lead_output)
                    .map(|lead_utxo| (prev_block.hash, prev_block.lead_output, lead_utxo))
            })
        };

        let Some((prev_block_hash, lead_utxo_id, lead_utxo)) = metadata else {
            continue;
        };

        let start = OsRng.try_next_u64().unwrap() as usize;

        let result = tokio::task::spawn_blocking(move || {
            miner::build_mining_tx(
                &secret_key,
                &prev_block_hash,
                &lead_utxo_id.tx_hash,
                &lead_utxo,
                Some(&mask),
                start..start + BATCH_SIZE,
            )
        })
        .await
        .ok()
        .flatten();

        if let Some(mining_tx) = result {
            let mut block = Block::new(0, prev_block_hash);
            block.transactions.push(mining_tx);
            if rpc_client
                .request(eupp_net::protocol::RpcRequest::BroadcastBlock { block })
                .await
                .is_err()
            {
                break;
            }
        }

        tokio::task::yield_now().await;
    }
}
