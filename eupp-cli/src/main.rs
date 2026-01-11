use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use eupp_core::Hash;
use eupp_core::transaction::{Input, Output, OutputId, Transaction, sighash};
use eupp_rpc::EuppRpcClient;
use hex;
use jsonrpsee::http_client::HttpClientBuilder;

/// A CLI for interacting with the Eupp network by sending transactions.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The port of the node to connect to.
    #[arg(long, default_value_t = 42745)]
    port: u16,

    /// The secret key to sign the transaction with (hex-encoded).
    #[arg(long)]
    secret_key: String,

    /// The hash of the transaction to spend (hex-encoded).
    #[arg(long)]
    tx_id: String,

    /// The index of the output to spend in the transaction.
    #[arg(long)]
    index: u8,

    /// The public key of the recipient (hex-encoded). If not provided, sends back to self.
    #[arg(long)]
    remote_pubkey: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // RPC endpoint where the node is listening
    let rpc_url = format!("http://127.0.0.1:{}", args.port);

    // Build JSON-RPC HTTP client
    let http_client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&rpc_url)?;

    // --- Construct a transaction from CLI arguments ---
    let secret_key_bytes = hex::decode(args.secret_key)?;
    let signing_key = SigningKey::from_bytes(
        &secret_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key length, expected 32 bytes"))?,
    );
    let public_key = signing_key.verifying_key().to_bytes();

    let prev_tx_hash = hex::decode(args.tx_id)?;
    let prev_output_index = args.index;

    let output_id = OutputId::new(
        prev_tx_hash
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid tx_id length, expected 32 bytes"))?,
        prev_output_index,
    );
    let input = Input::new_unsigned(output_id, public_key);

    // Determine recipient
    let recipient_pubkey = if let Some(remote_pubkey_hex) = args.remote_pubkey {
        hex::decode(remote_pubkey_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid remote_pubkey length, expected 32 bytes"))?
    } else {
        public_key
    };

    // Create a single output sending 11 units with dummy data.
    let data: Hash = [3u8; 32];
    let output = Output::new_v1(11, &recipient_pubkey, &data);
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
                "Transaction broadcasted successfully. Node returned hash: {}",
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
