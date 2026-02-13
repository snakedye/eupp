use clap::{Parser, Subcommand};
use eupp_core::{Hash, TransactionHash, commitment, keypair};
use eupp_core::{Input, Output, OutputId, Transaction, ledger::Query, sighash};
use std::time::Duration;

/// A CLI for interacting with the Eupp node via its HTTP REST API.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// The base URL of the node's REST API (e.g. http://127.0.0.1:3000).
    peer: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send a P2PKH transaction to a recipient identified by their public key hash (address).
    SendTo {
        /// The secret key to sign the transaction with (hex-encoded).
        #[arg(long)]
        secret_key: String,

        /// The public key hash (address/commitment) of the recipient (hex-encoded, 32 bytes).
        #[arg(long)]
        address: String,

        /// The amount to send in the transaction.
        #[arg(long)]
        amount: u64,
    },

    /// Broadcast a ready-made transaction provided as a JSON string.
    Broadcast {
        /// The transaction in JSON format.
        #[arg(long)]
        tx: String,
    },

    /// Fetch and display network information from the node.
    Network,
}

fn build_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client")
}

fn base_url(peer: &str) -> String {
    peer.trim_end_matches('/').to_string()
}

fn cmd_send_to(peer: &str, secret_key: &str, address_hex: &str, amount: u64) {
    let base = base_url(peer);
    let client = build_client();

    // Parse the secret key
    let secret_key_bytes = hex::decode(secret_key).expect("Invalid hex for secret key");
    let signing_key = secret_key_bytes
        .try_into()
        .as_ref()
        .map(keypair)
        .expect("Failed to parse secret key (expected 32 bytes)");
    let public_key = signing_key.verifying_key().to_bytes();
    let data = [0_u8; 32];
    let self_address = commitment(&public_key, Some(data.as_slice()));

    // Parse the recipient address (public key hash / commitment)
    let recipient_bytes = hex::decode(address_hex).expect("Invalid hex for recipient address");
    let recipient_address: Hash = recipient_bytes
        .as_slice()
        .try_into()
        .expect("Recipient address must be exactly 32 bytes");

    // Build query for our own UTXOs
    let query = Query::new().with_address(self_address);

    // Fetch UTXOs
    let resp = client
        .post(format!("{base}/transactions/outputs"))
        .json(&query)
        .send()
        .expect("Failed to send UTXO query");

    if !resp.status().is_success() {
        panic!("Failed to fetch UTXOs: {}", resp.status());
    }

    let utxos: Vec<(OutputId, Output)> = resp.json().expect("Failed to parse UTXO response");
    let balance: u64 = utxos.iter().map(|(_, output)| output.amount()).sum();
    println!("Address: {}", hex::encode(self_address));
    println!("Balance: {} units", balance);

    if amount > balance {
        panic!(
            "Insufficient balance: have {} but trying to send {}",
            balance, amount
        );
    }

    // Create outputs: one to the recipient (by address), one back to self for change
    let data: Hash = [0u8; 32];
    let to_remote = Output::to_address(amount, &recipient_address, &data);
    let change = balance.saturating_sub(amount);
    let to_self = Output::new_v1(change, &public_key, &data);
    let new_outputs = vec![to_remote, to_self];

    // Compute sighash and sign inputs
    let sighash_val = sighash(utxos.iter().map(|(oid, _)| oid), &new_outputs);

    let inputs: Vec<Input> = utxos
        .iter()
        .map(|(output_id, _)| {
            Input::new_unsigned(*output_id).sign(signing_key.as_bytes(), sighash_val)
        })
        .collect();
    let tx = Transaction::new(inputs, new_outputs);

    let tx_hash = tx.hash();
    println!(
        "Constructed transaction with hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Broadcast
    let resp = client
        .post(format!("{base}/transactions"))
        .json(&tx)
        .send()
        .expect("Failed to broadcast transaction");

    if !resp.status().is_success() {
        panic!(
            "Failed to broadcast transaction: {:?}",
            resp.text().unwrap_or_default()
        );
    }

    let broadcasted_hash: TransactionHash =
        resp.json().expect("Failed to parse broadcast response");
    println!(
        "Transaction {} broadcasted successfully.",
        hex::encode(broadcasted_hash)
    );
}

fn cmd_broadcast(peer: &str, tx_json: &str) {
    let base = base_url(peer);
    let client = build_client();

    let tx: Transaction = serde_json::from_str(tx_json).expect("Failed to parse transaction JSON");

    let tx_hash = tx.hash();
    println!("Transaction hash: 0x{}", hex::encode(tx_hash));

    let resp = client
        .post(format!("{base}/transactions"))
        .json(&tx)
        .send()
        .expect("Failed to broadcast transaction");

    if !resp.status().is_success() {
        panic!(
            "Failed to broadcast transaction: {:?}",
            resp.text().unwrap_or_default()
        );
    }

    let broadcasted_hash: TransactionHash =
        resp.json().expect("Failed to parse broadcast response");
    println!(
        "Transaction {} broadcasted successfully.",
        hex::encode(broadcasted_hash)
    );
}

fn cmd_network(peer: &str) {
    let base = base_url(peer);
    let client = build_client();

    let resp = client
        .get(format!("{base}/network"))
        .send()
        .expect("Failed to fetch network info");

    if !resp.status().is_success() {
        panic!("Failed to fetch network info: {}", resp.status());
    }

    let info: serde_json::Value = resp.json().expect("Failed to parse network info response");

    println!("{}", serde_json::to_string_pretty(&info).unwrap());
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::SendTo {
            secret_key,
            address,
            amount,
        } => cmd_send_to(&cli.peer, &secret_key, &address, amount),
        Command::Broadcast { tx } => cmd_broadcast(&cli.peer, &tx),
        Command::Network => cmd_network(&cli.peer),
    }
}
