use clap::{Parser, Subcommand};
use const_hex as hex;
use helm_core::{Hash, TransactionHash, commitment, keypair};
use helm_core::{
    Input, Output, Transaction,
    ledger::{OutputEntry, Query},
    sighash,
};
use std::time::Duration;

// ============================================================================
// CLI STRUCTURES
// ============================================================================

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
        address: Option<String>,

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
    Info,
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn build_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client")
}

fn base_url(peer: &str) -> String {
    peer.trim_end_matches('/').to_string()
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

fn print_section(title: &str) {
    println!("\n╭─ {} ─────────────────────────────────────", title);
}

fn print_entry(key: &str, value: &str) {
    println!("│  {:<25} {}", format!("{}:", key), value);
}

fn print_end_section() {
    println!("╰────────────────────────────────────────────\n");
}

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

fn cmd_send_to(peer: &str, secret_key: &str, address_hex: Option<&String>, amount: u64) {
    let base = base_url(peer);
    let client = build_client();

    // --- Parse credentials ---
    let secret_key = hex::decode_to_array(secret_key).expect("Invalid hex for secret key");
    let signing_key = keypair(&secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let data = [0_u8; 32];
    let self_address = commitment(&public_key, Some(data.as_slice()));

    // --- Parse recipient address ---
    let recipient_address: Hash = address_hex
        .map(|hex| hex::decode_to_array(hex).expect("Invalid hex for recipient address"))
        .unwrap_or(self_address);

    // --- Fetch UTXOs ---
    let query = Query::Addresses(vec![self_address]);
    let resp = client
        .post(format!("{base}/outputs/search"))
        .json(&query)
        .send()
        .expect("Failed to send UTXO query");

    if !resp.status().is_success() {
        panic!("Failed to fetch UTXOs: {}", resp.status());
    }

    let outputs: Vec<OutputEntry> = resp.json().expect("Failed to parse outputs response");
    let utxos = outputs.iter().take(255);
    let balance: u64 = utxos.clone().map(|entry| entry.output.amount()).sum();

    print_section("Wallet Information");
    print_entry("Address", &hex::encode_prefixed(self_address));
    print_entry("Spendable Balance", &format!("{} units", balance));
    print_end_section();

    if amount > balance {
        panic!(
            "\n  ❌ Insufficient balance: have {} but trying to send {}",
            balance, amount
        );
    }

    // --- Build transaction ---
    let data: Hash = [0u8; 32];
    let to_remote = Output::to_address(amount, &recipient_address, &data);
    let change = balance.saturating_sub(amount);
    let to_self = Output::new_v1(change, &public_key, &data);
    let new_outputs = vec![to_remote, to_self];

    // --- Sign inputs ---
    let sighash_val = sighash(utxos.clone().map(|entry| &entry.id), &new_outputs);

    let inputs: Vec<Input> = utxos
        .clone()
        .map(|entry| {
            Input::builder()
                .with_output_id(*&entry.id)
                .sign(signing_key.as_bytes(), sighash_val)
                .build()
                .unwrap()
        })
        .collect();
    let tx = Transaction::new(inputs, new_outputs);

    let tx_hash = tx.hash();
    print_section("Transaction Details");
    print_entry("Hash", &format!("0x{}", hex::encode(tx_hash)));
    print_entry("Amount", &format!("{} units", amount));
    print_entry("Recipient", &hex::encode_prefixed(recipient_address));
    print_entry("Change", &format!("{} units", change));
    print_end_section();

    // --- Broadcast transaction ---
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
    print_section("Broadcast Status");
    print_entry("Status", "✓ Success");
    print_entry("Transaction Hash", &hex::encode_prefixed(broadcasted_hash));
    print_end_section();
}

fn cmd_broadcast(peer: &str, tx_json: &str) {
    let base = base_url(peer);
    let client = build_client();

    // --- Parse and display transaction ---
    let tx: Transaction = serde_json::from_str(tx_json).expect("Failed to parse transaction JSON");
    let tx_hash = tx.hash();

    print_section("Transaction Information");
    print_entry("Hash", &hex::encode_prefixed(tx_hash));
    print_end_section();

    // --- Broadcast transaction ---
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
    print_section("Broadcast Status");
    print_entry("Status", "✓ Success");
    print_entry("Confirmed Hash", &hex::encode(broadcasted_hash));
    print_end_section();
}

fn cmd_info(peer: &str) {
    let base = base_url(peer);
    let client = build_client();

    // --- Fetch network info ---
    let resp = client
        .get(format!("{base}/info"))
        .send()
        .expect("Failed to fetch network info");

    if !resp.status().is_success() {
        panic!("Failed to fetch network info: {}", resp.status());
    }

    let info: serde_json::Value = resp.json().expect("Failed to parse network info response");

    print_section("Network Information");
    println!("{}", serde_json::to_string_pretty(&info).unwrap());
    print_end_section();
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::SendTo {
            secret_key,
            address,
            amount,
        } => cmd_send_to(&cli.peer, &secret_key, address.as_ref(), amount),
        Command::Broadcast { tx } => cmd_broadcast(&cli.peer, &tx),
        Command::Info => cmd_info(&cli.peer),
    }
}
