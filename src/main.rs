mod api;
mod indexer;

use eupp_core::{
    Block, MAX_BLOCK_SIZE, Output, SecretKey, Transaction, Version, VirtualSize, commitment,
    ledger::{Indexer, Query},
    miner,
};
use eupp_db::{FileStore, RedbIndexer};
use eupp_net::{
    EuppNode, RpcClient, SyncHandle, config::Config, mempool::SimpleMempool, protocol::RpcResponse,
};
use indexer::NodeStore;
use rand::{TryRngCore, rngs::OsRng};
use std::{net::SocketAddr, time::Duration};
use tracing::{Level, debug, error, info};

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
        outputs: vec![Output::new_v0(u64::MAX, &mask, &[0; 32])],
    };
    let mut genesis_block = Block::new(0, [0u8; 32]);
    genesis_block.transactions.push(coinbase_tx);
    let genesis_block_hash = genesis_block.header().hash();

    // Add genesis block to ledger
    if indexer.add_block(&genesis_block).is_ok() {
        info!(
            hash = %const_hex::encode(genesis_block_hash),
            "Added genesis block",
        );
    }

    // Select the node store
    let ledger = match config.block_file_path() {
        Some(path) => NodeStore::Full(indexer.with_fs(FileStore::new(path)?)),
        None => NodeStore::Pruned(indexer),
    };

    // Create a mempool
    let mempool = SimpleMempool::new();

    // Create the EuppNode (do not block the current task yet)
    let node = EuppNode::new(config.clone(), ledger, mempool);
    let sync_handle = node.sync_handle();

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
                    error!(?e, "HTTP server error");
                }
            });

            // Launch mining loop if difficulty is set.
            if let Some(difficulty) = config.difficulty {
                let secret_key = config.secret_key();
                tokio::spawn(mining_loop(sync_handle, secret_key, rpc_client, difficulty));
            }
        })
        .await
    {
        error!(?e, "Node error");
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
async fn mining_loop(
    sync: SyncHandle,
    secret_key: SecretKey,
    rpc_client: RpcClient,
    difficulty: usize,
) {
    let mut mask = [0_u8; 32];
    set_n_bits(&mut mask, difficulty);

    // Larger batch size for more mining attempts per iteration
    const BATCH_SIZE: usize = 10_000;

    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if sync.is_syncing() {
            debug!("Node is syncing; skipping mining iteration");
            continue;
        }
        if let RpcResponse::Transactions(txs) = rpc_client
            .request(eupp_net::protocol::RpcRequest::GetMempool)
            .await
            .unwrap()
        {
            if txs.is_empty() {
                debug!("Mempool is empty; skipping mining iteration");
                continue;
            }
            if let RpcResponse::NetworkInfo(network_info) = rpc_client
                .request(eupp_net::protocol::RpcRequest::GetNetworkInfo)
                .await
                .unwrap()
            {
                if let RpcResponse::BlockSummary(block_summary) = rpc_client
                    .request(eupp_net::protocol::RpcRequest::GetBlockByHash {
                        hash: network_info.tip_hash,
                    })
                    .await
                    .unwrap()
                {
                    if let RpcResponse::Outputs(outputs) = rpc_client
                        .request(eupp_net::protocol::RpcRequest::GetOutputs {
                            query: Query::TransactionID(block_summary.lead_tx_hash),
                        })
                        .await
                        .unwrap()
                    {
                        // Process outputs here
                        let start = OsRng.try_next_u64().unwrap() as usize;

                        let result = tokio::task::spawn_blocking(move || {
                            miner::build_mining_tx(
                                &secret_key,
                                &block_summary.hash,
                                &block_summary.lead_tx_hash,
                                &outputs[0].1,
                                Some(&mask),
                                start..start + BATCH_SIZE,
                            )
                        })
                        .await
                        .ok()
                        .flatten();

                        if let Some(mining_tx) = result {
                            let mut block = Block::new(0, block_summary.hash);
                            block.transactions.push(mining_tx);

                            // Calculate the remaining virtual size for the block
                            let remaining = MAX_BLOCK_SIZE.saturating_sub(block.vsize());
                            let selected = txs.into_iter().scan(remaining, |remaining, tx| {
                                // Select transactions for the block
                                let tx_vsize = tx.vsize();
                                *remaining = remaining.saturating_sub(tx_vsize);
                                (*remaining > 0).then_some(tx)
                            });
                            // Add the selected transactions to the block
                            block.transactions.extend(selected);

                            if let Err(err) = rpc_client
                                .request(eupp_net::protocol::RpcRequest::BroadcastBlock { block })
                                .await
                            {
                                error!(?err, "Failed to send block");
                            }
                        }
                    }
                }
            }
        }

        tokio::task::yield_now().await;
    }
}
