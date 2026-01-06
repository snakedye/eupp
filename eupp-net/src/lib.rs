pub mod behavior;
pub mod mempool;
pub mod protocol;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::mempool::Mempool;
use crate::protocol::{NetworkMessage, NetworkRequest, NetworkResponse};
use eupp_core::Hash;
use eupp_core::ledger::Ledger;
use eupp_core::{VirtualSize, block::Block, miner};
use libp2p::{SwarmBuilder, futures::StreamExt, gossipsub, mdns, swarm::SwarmEvent};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock, atomic::Ordering};
use tokio::{sync::mpsc, time::Duration};

pub struct EuppNode<L: Ledger, M: Mempool> {
    ledger: Arc<RwLock<L>>,
    mempool: Arc<RwLock<M>>,

    // In-memory sync state for assembling streamed blocks
    is_syncing: Arc<AtomicBool>,
    pending_blocks: HashMap<Hash, Block>,
}

impl<L: Ledger + Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    pub fn new(ledger: L, mempool: M) -> Self {
        Self {
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            pending_blocks: HashMap::new(),
            is_syncing: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
        let ledger = Arc::clone(&self.ledger);
        let is_synching = Arc::clone(&self.is_syncing);

        // Debounce window in milliseconds to collect MaxSupply responses before choosing the best peer
        const GET_MAX_SUPPLY_DEBOUNCE_MS: u64 = 300;
        // Map peer_id string -> reported max supply
        let mut max_supply_responses: HashMap<String, u32> = HashMap::new();
        // Channel used by timer tasks to notify the main loop that the debounce window expired
        let (debounce_tx, mut debounce_rx) = mpsc::channel::<()>(1);

        // Mining helper task that builds mining transactions and sends new blocks into the channel
        tokio::spawn(async move {
            // Timeout before starting to mine.
            tokio::time::sleep(Duration::from_secs(1)).await;
            loop {
                if is_synching.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let metadata = {
                    let lg = ledger.read().unwrap();
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
                            } else {
                                // Clear previous responses and start debounce timer to collect replies
                                max_supply_responses.clear();
                                let debounce_tx_clone = debounce_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(GET_MAX_SUPPLY_DEBOUNCE_MS)).await;
                                    let _ = debounce_tx_clone.send(()).await;
                                });
                            }
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let msg: NetworkMessage = bincode::deserialize(&message.data)?;
                        // Capture the message source peer id (if present) as a string so we can
                        // target requests/responses to specific peers without flooding everyone.
                        let src: Option<String> = message.source.map(|p| p.to_string());
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
                                NetworkRequest::GetBlocks { from, peer_id } => {
                                    // Only respond to GetBlocks when this node is the intended target (or when no target was specified).
                                    // This prevents many peers from responding to a single GetBlocks request.
                                    let local_id = swarm.local_peer_id().to_string();
                                    let should_respond = match &peer_id {
                                        Some(target) => target == &local_id,
                                        None => true,
                                    };

                                    if should_respond {
                                        match self.ledger.read() {
                                            Ok(lg) => {
                                                let target = lg.get_last_block_metadata().map(|m| m.hash);
                                                // Stream blocks one-by-one, publishing each as a `Block(height, block)` response.
                                                for block in lg.get_blocks().take_while(|block| from != block.header().hash()) {
                                                    // Include the original request's intended recipient so that only that peer applies them.
                                                    let msg = NetworkMessage::Response(NetworkResponse::Block { target, block });
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
                                    // Buffer max supply responses for the debounce window. Use message source as peer id.
                                    if let Some(peer_str) = src {
                                        max_supply_responses.insert(peer_str, supply);
                                    } else {
                                        // If source isn't present, ignore — we need a specific peer to target GetBlocks.
                                    }
                                },

                                NetworkResponse::Block { block, target } => {
                                    // Buffer or apply streamed block depending on sync state
                                    if let Ok(mut lg) = self.ledger.write() {
                                        // If there is no ongoing sync, immediately try to add the block
                                        if !self.is_syncing.load(Ordering::SeqCst) {
                                            if let Ok(_) = lg.add_block(&block) {
                                                println!("<- Recv {}", hex::encode(block.header().hash()));
                                                continue;
                                            }
                                        }
                                        // If adding fails we go in buffered mode
                                        let mut tip = lg.get_last_block_metadata().map(|meta| meta.hash).unwrap();
                                        self.pending_blocks.insert(block.prev_block_hash, block);
                                        // Buffer the block and attempt to apply contiguous sequence
                                        while let Some(next_block) = self.pending_blocks.remove(&tip) {
                                            match lg.add_block(&next_block) {
                                                Ok(_) => {
                                                    tip = next_block.header().hash();
                                                    println!("<- Recv {}", hex::encode(&tip));
                                                    if Some(tip) == target {
                                                        println!("Reached target hash!");
                                                        self.pending_blocks.clear();
                                                        self.is_syncing.store(false, Ordering::SeqCst);
                                                        // We push a new getmaxsupply request to make sure we are up to date after sync
                                                        let msg = NetworkMessage::Request(NetworkRequest::GetMaxSupply);
                                                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                                            eprintln!("Failed to publish GetMaxSupply: {:?}", e);
                                                        } else {
                                                            // Start debounce window to pick the best peer
                                                            max_supply_responses.clear();
                                                            let debounce_tx_clone = debounce_tx.clone();
                                                            tokio::spawn(async move {
                                                                tokio::time::sleep(Duration::from_millis(GET_MAX_SUPPLY_DEBOUNCE_MS)).await;
                                                                let _ = debounce_tx_clone.send(()).await;
                                                            });
                                                        }
                                                        break;
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("Failed to add block from the network: {:?}", e);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                },
                            },
                        }
                    },
                    _ => {}
                },
                // Debounce timer expired: pick the best peer from collected MaxSupply replies and start sync if needed
                Some(_) = debounce_rx.recv() => {
                    // Check if the node is currently syncing. If so, clear the max supply responses and skip further processing.
                    if self.is_syncing.load(Ordering::SeqCst) {
                        max_supply_responses.clear();
                        continue;
                    }

                    // Retrieve the local ledger's supply and hash of the last block. If unavailable, clear responses and skip.
                    let (local_supply, local_hash) = match self.ledger.read().ok().and_then(|lg| lg.get_last_block_metadata()) {
                        Some(meta) => (meta.available_supply, meta.hash),
                        None => {
                            max_supply_responses.clear();
                            continue;
                        }
                    };

                    // Find the peer with the highest reported max supply from the collected responses.
                    if let Some((best_peer, &best_supply)) = max_supply_responses.iter().max_by_key(|&(_, s)| s) {
                        // If the best peer's supply is greater than the local supply, initiate a sync with that peer.
                        if best_supply > local_supply {
                            println!("Selected peer {} with greater supply {} (local {})", best_peer, best_supply, local_supply);
                            self.is_syncing.store(true, Ordering::SeqCst);
                            self.pending_blocks.clear();

                            // Create a GetBlocks request starting from the local hash and targeting the selected peer.
                            let request = NetworkMessage::Request(NetworkRequest::GetBlocks {
                                from: local_hash,
                                peer_id: Some(best_peer.clone()),
                            });
                            // Publish the GetBlocks request to the network. If it fails, reset the syncing state.
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&request)?) {
                                eprintln!("Failed to publish GetBlocks: {:?}", e);
                                self.is_syncing.store(false, Ordering::SeqCst);
                            }
                        }
                    }
                    // Clear the max supply responses after processing.
                    max_supply_responses.clear();
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
                            println!("-> Send {}", hex::encode(block.header().hash()));

                            let mut mp = self.mempool.write().unwrap();
                            let added_tx_hashes = added_transactions.iter().map(|tx| tx.hash());
                            mp.remove_transactions(added_tx_hashes);

                            // Publish the single newly-mined block as a streamed Block message.
                            // `get_last_block_metadata` returns Option<BlockMetadata>.
                            let msg = NetworkMessage::Response(NetworkResponse::Block{ block, target: None });
                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?);
                        }
                        Err(_) => {},
                    }
                }
            }
        }
    }
}
