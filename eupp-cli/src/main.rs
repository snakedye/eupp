use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use eupp_core::ledger::Query;
use eupp_core::transaction::{Input, Output, Transaction, sighash};
use eupp_core::{Hash, commitment};
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

    /// The public key of the recipient (hex-encoded). If not provided, sends back to self.
    #[arg(long)]
    remote_pubkey: Option<String>,

    /// The amount to send in the transaction.
    #[arg(long)]
    amount: u64,
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
    let data = [0_u8; 32];
    let address = commitment(&public_key, Some(data.as_slice()));

    // Fetch UTXOs
    let query = Query::new().with_address(address);
    let utxos = http_client.get_utxos(query).await.unwrap();
    let balance: u64 = utxos.iter().map(|(_, output)| output.amount).sum();
    println!("Address balance: {}", balance);

    // Determine recipient
    let recipient_pubkey = if let Some(remote_pubkey_hex) = args.remote_pubkey {
        hex::decode(remote_pubkey_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid remote_pubkey length, expected 32 bytes"))?
    } else {
        public_key
    };

    // Create a single output sending the specified amount with dummy data.
    let data: Hash = [0u8; 32];
    let to_remote = Output::new_v1(args.amount, &recipient_pubkey, &data);
    let to_self = Output::new_v1(balance - args.amount, &public_key, &data);
    let outputs = vec![to_remote, to_self];

    // Construct the signature
    let sighash = sighash(utxos.iter().map(|(output_id, _)| output_id), &outputs);
    let signature = signing_key.sign(&sighash);

    // Create inputs
    let inputs = utxos
        .iter()
        .map(|(output_id, _)| Input::new(*output_id, public_key, signature.to_bytes()))
        .collect();
    let tx = Transaction::new(inputs, outputs);

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
                "Transaction {} broadcasted successfully.",
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
