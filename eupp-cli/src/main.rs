use std::time::Duration;

use anyhow::Result;
use eupp_core::transaction::{Input, Output, OutputId, Transaction};
use eupp_core::{Hash, PublicKey, Signature};
use eupp_rpc::EuppRpcClient;
use hex;
use jsonrpsee::http_client::HttpClientBuilder;

/// Minimal CLI that constructs a hardcoded transaction and broadcasts it via RPC.
/// This is intentionally tiny for a first draft — no CLI args, fixed values.
///
/// It expects an RPC server to be listening at http://127.0.0.1:9944 that implements
/// the `eupp_sendRawTransaction` method from the `eupp` namespace.
#[tokio::main]
async fn main() -> Result<()> {
    // RPC endpoint where the node is listening
    let rpc_url = "http://127.0.0.1:9944";

    // Build JSON-RPC HTTP client
    let http_client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(rpc_url)?;

    let client = EuppRpcClient::new(http_client);

    // --- Construct a very small, hardcoded transaction ---
    //
    // Note: These are dummy values for a first draft CLI. Real transactions must
    // use real previous output ids, public keys, and signatures.
    let prev_tx_hash: Hash = [1u8; 32];
    let prev_output_index: u8 = 0;
    let output_id = OutputId::new(prev_tx_hash, prev_output_index);

    let public_key: PublicKey = [2u8; 32];
    let signature: Signature = [0u8; 64];

    let input = Input::new(output_id, public_key, signature);

    // Create a single output sending 50 units back to `public_key` with dummy data.
    let data: Hash = [3u8; 32];
    let output = Output::new_v1(50, &public_key, &data);

    let tx = Transaction::new(vec![input], vec![output]);

    // Print transaction hash locally
    let tx_hash = tx.hash();
    println!(
        "Constructed transaction with hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Broadcast using the RPC client
    println!("Broadcasting transaction to {rpc_url} ...");
    match client.send_raw_transaction(tx).await {
        Ok(broadcasted_hash) => {
            println!(
                "Transaction broadcasted successfully. Node returned hash: 0x{}",
                hex::encode(broadcasted_hash)
            );
        }
        Err(err) => {
            // jsonrpsee's errors implement Debug; print them for now.
            eprintln!("Failed to broadcast transaction: {:?}", err);
        }
    }

    Ok(())
}
