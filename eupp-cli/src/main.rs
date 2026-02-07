use anyhow::Result;
use clap::Parser;
use ed25519_dalek::SigningKey;
use eupp_core::ledger::Query;
use eupp_core::transaction::{Input, Output, Transaction, sighash};
use eupp_core::{Hash, commitment};
use hex;
use std::time::Duration;

/// A CLI for interacting with the Eupp node via its HTTP REST API.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The base URL of the node's REST API (e.g. http://127.0.0.1:3000).
    #[arg(long)]
    peer: String,

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

fn main() -> Result<()> {
    let args = Args::parse();

    // --- Construct a transaction from CLI arguments ---
    let secret_key_bytes = hex::decode(args.secret_key.as_bytes())?;
    let signing_key = SigningKey::try_from(secret_key_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse secret key: {}", e))?;
    let public_key = signing_key.verifying_key().to_bytes();
    let data = [0_u8; 32];
    let address = commitment(&public_key, Some(data.as_slice()));

    // Build query for UTXOs
    let query = Query::new().with_address(address);

    // Interpret peer as base URL (remove trailing slash if present)
    let base = args.peer.trim_end_matches('/').to_string();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Fetch UTXOs via HTTP POST /transactions/utxos <query>
    let resp = client
        .post(format!("{base}/transactions/utxos"))
        .json(&query)
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to fetch UTXOs: {}", resp.status()));
    }

    // Deserialize to Vec<(OutputId, Output)>
    let utxos: Vec<(eupp_core::transaction::OutputId, Output)> = resp.json()?;
    let balance: u64 = utxos.iter().map(|(_, output)| output.amount()).sum();
    println!("Address: {}", hex::encode(address));
    println!("Balance: {} units", balance);

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
    let to_self = Output::new_v1(balance.saturating_sub(args.amount), &public_key, &data);
    let new_outputs = vec![to_remote, to_self];

    // Construct the signature
    // sighash expects an iterator of OutputId references; adapt accordingly
    let sighash_val = sighash(utxos.iter().map(|(output_id, _)| output_id), &new_outputs);

    // Create inputs
    let inputs = utxos
        .iter()
        .map(|(output_id, _)| {
            Input::new_unsigned(*output_id).sign(signing_key.as_bytes(), sighash_val)
        })
        .collect();
    let tx = Transaction::new(inputs, new_outputs);

    // Print transaction hash locally
    let tx_hash = tx.hash();
    println!(
        "Constructed transaction with hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Broadcast the transaction via HTTP POST /transactions <tx>
    let resp = client
        .post(format!("{base}/transactions"))
        .json(&tx)
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to broadcast transaction: {}",
            resp.status()
        ));
    }

    // Expect a TransactionHash in the response body (array of bytes)
    let broadcasted_hash: eupp_core::transaction::TransactionHash = resp.json()?;
    println!(
        "Transaction {} broadcasted successfully.",
        hex::encode(broadcasted_hash)
    );

    Ok(())
}
