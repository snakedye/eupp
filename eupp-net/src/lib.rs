pub mod behavior;
pub mod mempool;
pub mod protocol;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::mempool::Mempool;
use crate::protocol::{NetworkMessage, NetworkRequest, NetworkResponse};
use eupp_core::ledger::Ledger;
use eupp_core::{VirtualSize, block::Block, miner};
use libp2p::{SwarmBuilder, futures::StreamExt, gossipsub, mdns, swarm::SwarmEvent};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::{sync::mpsc, time::Duration};

/// Sentinel value used to represent "no expected height".
const EXPECTED_NONE: u32 = u32::MAX;

/// Helper that checks whether a sync session is in progress.
///
/// Returns `true` when the atomic contains a value other than `EXPECTED_NONE`.
pub fn is_syncing(expected: &Arc<AtomicU32>) -> bool {
    expected.load(Ordering::SeqCst) != EXPECTED_NONE
}

pub struct EuppNode<L: Ledger, M: Mempool> {
    ledger: Arc<RwLock<L>>,
    mempool: Arc<RwLock<M>>,

    // In-memory sync state for assembling streamed blocks
    pending_blocks: Arc<Mutex<HashMap<u32, Block>>>,
    expected_sync_height: Arc<AtomicU32>,
}

impl<L: Ledger + Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    pub fn new(ledger: L, mempool: M) -> Self {
        Self {
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            pending_blocks: Arc::new(Mutex::new(HashMap::new())),
            expected_sync_height: Arc::new(AtomicU32::new(EXPECTED_NONE)),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                Default::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let gossip_config = gossipsub::ConfigBuilder::default().build()?;

                Ok(EuppBehaviour {
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossip_config,
                    )?,
                    mdns: mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        key.public().to_peer_id(),
                    )?,
                })
            })?
            .build();

        let topic = gossipsub::IdentTopic::new("eupp-testnet");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let (block_sender, mut block_receiver) = mpsc::channel(10);
        let ledger_clone = Arc::clone(&self.ledger);
        let expected_sync_clone = Arc::clone(&self.expected_sync_height);

        // Mining helper task that builds mining transactions and sends new blocks into the channel
        tokio::spawn(async move {
            loop {
                if is_syncing(&expected_sync_clone) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let metadata = {
                    let lg = ledger_clone.read().unwrap();
                    lg.get_last_block_metadata().and_then(|prev_block| {
                        lg.get_utxo(&prev_block.lead_utxo)
                            .map(|lead_utxo| (prev_block.hash, prev_block.lead_utxo, lead_utxo))
                    })
                };

                let Some((prev_block_hash, lead_utxo_id, lead_utxo)) = metadata else {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                };

                let result = tokio::task::spawn_blocking(move || {
                    miner::build_mining_tx(
                        &prev_block_hash,
                        &lead_utxo_id.tx_hash,
                        &lead_utxo,
                        100_000,
                    )
                })
                .await
                .unwrap();

                if let Some((_key, mining_tx)) = result {
                    let mut block = Block::new(0, prev_block_hash);
                    block.transactions.push(mining_tx);

                    if block_sender.send(block).await.is_err() {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        });

        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("Discovered a new peer: {peer_id}");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic: t })) => {
                        if t == topic.hash() {
                            println!("Peer {peer_id} subscribed to our topic, publishing GetMaxSupply");
                            let msg = NetworkMessage::Request(NetworkRequest::GetMaxSupply);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                eprintln!("Failed to publish GetMaxSupply: {:?}", e);
                            }
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let msg: NetworkMessage = bincode::deserialize(&message.data)?;
                        match msg {
                            NetworkMessage::Request(req) => match req {
                                NetworkRequest::GetMaxSupply => {
                                    if let Ok(ledger) = self.ledger.read() {
                                        if let Some(metadata) = ledger.get_last_block_metadata() {
                                            let max_supply = metadata.available_supply;
                                            let response = NetworkMessage::Response(NetworkResponse::MaxSupply(max_supply));
                                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&response)?) {
                                                eprintln!("Failed to publish MaxSupply: {:?}", e);
                                            }
                                        }
                                    }
                                },
                                NetworkRequest::GetBlocks(from_height) => {
                                    match self.ledger.read() {
                                        Ok(lg) => {
                                            // Stream blocks one-by-one, publishing each as a `Block(height, block)` response.
                                            for (idx, block) in lg.get_blocks().skip(from_height as usize).enumerate() {
                                                let height = from_height + idx as u32;
                                                let msg = NetworkMessage::Response(NetworkResponse::Block(height, block));
                                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                                    eprintln!("Failed to publish block for sync: {:?}", e);
                                                    break;
                                                }
                                                // yield to avoid tight flooding loops
                                                tokio::task::yield_now().await;
                                            }
                                        }
                                        Err(_) => eprintln!("Failed to acquire read lock on ledger."),
                                    }
                                },
                                NetworkRequest::Transaction(tx) => {
                                    let mut mp = self.mempool.write().unwrap();
                                    let lg = self.ledger.read().unwrap();
                                    match mp.add(tx, &*lg) {
                                        Ok(_) => println!("New valid transaction added to mempool."),
                                        Err(e) => println!("Failed to add transaction to mempool: {:?}", e),
                                    }
                                },
                            },
                            NetworkMessage::Response(resp) => match resp {
                                NetworkResponse::MaxSupply(supply) => {
                                    if let Ok(ledger) = self.ledger.read() {
                                        if let Some(metadata) = ledger.get_last_block_metadata() {
                                            if supply > metadata.available_supply {
                                                println!("Discovered a peer with a longer chain. Starting sync.");

                                                // record expected starting height and clear any previous pending state
                                                {
                                                    self.expected_sync_height.store(metadata.height + 1, Ordering::SeqCst);
                                                    let mut pending = self.pending_blocks.lock().unwrap();
                                                    pending.clear();
                                                }

                                                let request = NetworkMessage::Request(NetworkRequest::GetBlocks(metadata.height + 1));
                                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&request)?) {
                                                    eprintln!("Failed to publish GetBlocks: {:?}", e);
                                                }
                                            }
                                        }
                                    }
                                },
                                NetworkResponse::Block(height, block) => {
                                    // Buffer or apply streamed block depending on sync state
                                    match self.ledger.write() {
                                        Ok(mut lg) => {
                                            let mut pending_guard = self.pending_blocks.lock().unwrap();
                                            let current = self.expected_sync_height.load(Ordering::SeqCst);
                                            if current == EXPECTED_NONE {
                                                // Not in an explicit syncing session: try to add directly
                                                match lg.add_block(&block) {
                                                    Ok(_) => println!("Added a new block from the network: {}", hex::encode(block.header().hash())),
                                                    Err(e) => eprintln!("Failed to add block from the network: {:?}", e),
                                                }
                                            } else {
                                                // Buffer the block and then attempt to apply any contiguous sequence
                                                pending_guard.insert(height, block);
                                                loop {
                                                    let exp_h = self.expected_sync_height.load(Ordering::SeqCst);
                                                    if exp_h == EXPECTED_NONE { break; }
                                                    if let Some(next_block) = pending_guard.remove(&exp_h) {
                                                        match lg.add_block(&next_block) {
                                                            Ok(_) => {
                                                                println!("Added a new block from the network: {}", hex::encode(next_block.header().hash()));
                                                                self.expected_sync_height.store(exp_h + 1, Ordering::SeqCst);
                                                            }
                                                            Err(e) => {
                                                                eprintln!("Failed to add block from the network: {:?}", e);
                                                                // abort sync on validation error
                                                                self.expected_sync_height.store(EXPECTED_NONE, Ordering::SeqCst);
                                                                pending_guard.clear();
                                                                break;
                                                            }
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => eprintln!("Failed to acquire write lock on ledger."),
                                    }
                                },
                            },
                        }
                    },
                    _ => {}
                },
                Some(mut block) = block_receiver.recv() => {
                    let added_transactions;
                    {
                        let mp = self.mempool.read().unwrap();
                        let mut current_vsize = block.vsize();
                        let mut txs_to_add = Vec::new();

                        for tx in mp.get_transactions() {
                            let tx_vsize = tx.vsize();
                            if current_vsize + tx_vsize <= 1_000_000 {
                                txs_to_add.push(tx);
                                current_vsize += tx_vsize;
                            }
                        }
                        added_transactions = txs_to_add;
                    }
                    block.transactions.extend_from_slice(&added_transactions);

                    let mut lg = self.ledger.write().unwrap();
                    match lg.add_block(&block) {
                        Ok(_) => {
                            println!("Mined a new block {}!", hex::encode(block.header().hash()));

                            let mut mp = self.mempool.write().unwrap();
                            let added_tx_hashes = added_transactions.iter().map(|tx| tx.hash());
                            mp.remove_transactions(added_tx_hashes);

                            // Publish the single newly-mined block as a streamed Block message.
                            // `get_last_block_metadata` returns Option<BlockMetadata>.
                            let height = lg.get_last_block_metadata().map(|metadata| metadata.height).unwrap_or(0);
                            let msg = NetworkMessage::Response(NetworkResponse::Block(height, block));
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                eprintln!("Failed to publish block: {:?}", e);
                            }
                        }
                        Err(_) => {},
                    }
                }
            }
        }
    }
}
