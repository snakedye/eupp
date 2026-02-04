use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use eupp_core::ledger::Query;
use eupp_core::transaction::{Input, Output, Transaction, sighash};
use eupp_core::{Hash, commitment};
use eupp_net::protocol::{RpcRequest, RpcResponse};
use futures::StreamExt;
use hex;
use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
};
use std::str::FromStr;
use std::sync::Once;

static READY: Once = Once::new();

/// A CLI for interacting with the Eupp network by sending transactions.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The multiaddr of the peer to connect to for libp2p RPC.
    /// Example: /ip4/127.0.0.1/tcp/12345/p2p/12D3... . If provided, CLI will use libp2p RPC.
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    // Fetch UTXOs via libp2p request/response RPC — the `--peer` multiaddr is required.
    let query = Query::new().with_address(address);
    let ma = Multiaddr::from_str(&args.peer).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Create a channel for communication with the swarm thread
    let (request_tx, mut request_rx) = tokio::sync::mpsc::channel::<RpcRequest>(1);
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<RpcResponse>(1);

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_key| {
            let rpc_proto = StreamProtocol::new("/eupp/rpc/1");
            Ok(request_response::cbor::Behaviour::new(
                [(rpc_proto, ProtocolSupport::Full)],
                Default::default(),
            ))
        })?
        .build();

    // Dial the peer
    swarm
        .dial(ma.clone())
        .map_err(|e| anyhow::anyhow!(format!("Dial error: {:?}", e)))?;

    // Spawn the swarm thread
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(request) = request_rx.recv() => {
                    let peer_id = swarm.connected_peers().next().unwrap().clone();
                    swarm.behaviour_mut().send_request(&peer_id, request);
                }
                event = swarm.select_next_some() => {
                    // Drive libp2p events and handle connection establishment & responses.
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            READY.call_once(|| println!("Connected to peer: {}", peer_id));
                        }
                        SwarmEvent::Behaviour(request_response::Event::Message { message, .. }) => {
                            if let request_response::Message::Response { response, .. } = message {
                                let _ = response_tx.send(response).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    // Wait for the connection to be established
    READY.wait();

    // Send GetUtxos request to the swarm thread
    request_tx.send(RpcRequest::GetUtxos { query }).await?;

    // Wait for the response
    let utxos = match response_rx.recv().await {
        Some(RpcResponse::Utxos(utxos)) => utxos,
        _ => return Err(anyhow::anyhow!("Failed to receive UTXOs response")),
    };
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
    let new_outputs = vec![to_remote, to_self];

    // Construct the signature
    let sighash = sighash(utxos.iter().map(|(output_id, _)| output_id), &new_outputs);
    let signature = signing_key.sign(&sighash);

    // Create inputs
    let inputs = utxos
        .iter()
        .map(|(output_id, _)| Input::new(*output_id, public_key, signature.to_bytes()))
        .collect();
    let tx = Transaction::new(inputs, new_outputs);

    // Print transaction hash locally
    let tx_hash = tx.hash();
    println!(
        "Constructed transaction with hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Send SendRawTransaction request to the swarm thread
    request_tx
        .send(RpcRequest::SendRawTransaction { tx: tx.clone() })
        .await?;

    match response_rx.recv().await {
        Some(RpcResponse::TransactionHash(broadcasted_hash)) => println!(
            "Transaction {} broadcasted successfully.",
            hex::encode(broadcasted_hash)
        ),
        _ => eprintln!("Failed to receive broadcast response from peer."),
    }

    Ok(())
}
