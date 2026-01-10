use std::time::Duration;

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use eupp_core::Hash;
use eupp_core::transaction::{Input, Output, OutputId, Transaction, sighash};
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
    let rpc_url = "http://127.0.0.1:36331";

    // Build JSON-RPC HTTP client
    let http_client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(rpc_url)?;

    // --- Construct a very small, hardcoded transaction ---
    let secret_key =
        hex::decode("66faba5cc813b8567435c8c4935e83f0f20bcda85f78797b39852559a4488b11").unwrap();
    let signing_key = SigningKey::from_bytes(&secret_key.try_into().unwrap());
    let public_key = signing_key.verifying_key().to_bytes();

    let prev_tx_hash =
        hex::decode("983e7b6f65079858b7fcee203b63aca24195d36772fb16569774379db0ce2b70").unwrap();
    let prev_output_index: u8 = 1;

    let output_id = OutputId::new(prev_tx_hash.try_into().unwrap(), prev_output_index);
    let input = Input::new_unsigned(output_id, public_key);

    // Create a single output sending 5 units back to `public_key` with dummy data.
    let data: Hash = [3u8; 32];
    let output = Output::new_v1(11, &public_key, &data);
    let sighash = sighash([&output_id], Some(&output));
    let signature = signing_key.sign(&sighash);

    let tx = Transaction::new(
        vec![input.with_signature(signature.to_bytes())],
        vec![output],
    );

    // Print transaction hash locally
    let tx_hash = tx.hash();
    println!(
        "Constructed transaction with hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Broadcast using the RPC client
    println!("Broadcasting transaction to {rpc_url} ...");
    match http_client.send_raw_transaction(tx).await {
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
