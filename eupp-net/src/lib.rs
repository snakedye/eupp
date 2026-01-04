pub mod behavior;
pub mod mempool;
pub mod protocol;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::mempool::Mempool;
use crate::protocol::NetworkMessage;
use eupp_core::{VirtualSize, block::Block, ledger::Ledger, miner};
use libp2p::{SwarmBuilder, futures::StreamExt, gossipsub, mdns, swarm::SwarmEvent};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::{sync::mpsc, time::Duration};

pub struct EuppNode<L: Ledger, M: Mempool> {
    ledger: Arc<RwLock<L>>,
    mempool: Arc<RwLock<M>>,
    blocks: Arc<RwLock<Vec<Block>>>,
    is_syncing: Arc<AtomicBool>,
}

impl<L: Ledger + Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    pub fn new(ledger: L, mempool: M, genesis_block: Block) -> Self {
        Self {
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            blocks: Arc::new(RwLock::new(vec![genesis_block])),
            is_syncing: Arc::new(AtomicBool::new(false)),
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
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&message.data, &mut s);
                    gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
                };

                let gossip_config = gossipsub::ConfigBuilder::default()
                    .message_id_fn(message_id_fn)
                    .build()?;

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

        let topic = gossipsub::IdentTopic::new("eupp-mainnet");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let (block_sender, mut block_receiver) = mpsc::channel(10);
        let ledger_clone = Arc::clone(&self.ledger);
        let is_syncing_clone = Arc::clone(&self.is_syncing);

        tokio::spawn(async move {
            loop {
                if is_syncing_clone.load(Ordering::SeqCst) {
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

                            let msg = NetworkMessage::GetMaxSupply;
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                eprintln!("Failed to publish GetMaxSupply: {:?}", e);
                            }
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let msg: NetworkMessage = bincode::deserialize(&message.data)?;
                        match msg {
                            NetworkMessage::GetMaxSupply => {
                                if let Ok(ledger) = self.ledger.read() {
                                    if let Some(metadata) = ledger.get_last_block_metadata() {
                                        let max_supply = metadata.available_supply;
                                        let response = NetworkMessage::MaxSupply(max_supply);
                                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&response)?) {
                                            eprintln!("Failed to publish MaxSupply: {:?}", e);
                                        }
                                    }
                                }
                            },
                            NetworkMessage::MaxSupply(supply) => {
                                if let Ok(ledger) = self.ledger.read() {
                                    if let Some(metadata) = ledger.get_last_block_metadata() {
                                        if supply > metadata.available_supply {
                                            println!("Discovered a peer with a longer chain. Starting sync.");
                                            self.is_syncing.store(true, Ordering::SeqCst);

                                            let request = NetworkMessage::GetBlocks(metadata.height + 1);
                                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&request)?) {
                                                eprintln!("Failed to publish GetBlocks: {:?}", e);
                                            }
                                        }
                                    }
                                }
                            },
                            NetworkMessage::GetBlocks(from_height) => {
                                let blocks = self.blocks.read().unwrap();
                                for block in blocks.iter().skip(from_height as usize) {
                                    let msg = NetworkMessage::Block(block.clone());
                                     if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                        eprintln!("Failed to publish block for sync: {:?}", e);
                                    }
                                }
                                let msg = NetworkMessage::SyncComplete;
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg)?) {
                                    eprintln!("Failed to publish SyncComplete: {:?}", e);
                                }
                            },
                            NetworkMessage::SyncComplete => {
                                println!("Sync complete. Resuming mining.");
                                self.is_syncing.store(false, Ordering::SeqCst);
                            },
                            NetworkMessage::Block(block) => {
                                let mut lg = self.ledger.write().unwrap();
                                match lg.add_block(block.clone()) {
                                    Ok(_) => {
                                        println!("Added a new block from the network: {}", hex::encode(block.header().hash()));
                                        self.blocks.write().unwrap().push(block);
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to add block from the network: {:?}", e);
                                    }
                                }
                            }
                            NetworkMessage::Transaction(tx) => {
                                self.handle_message(NetworkMessage::Transaction(tx)).await;
                            }
                        }
                    }
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
                    match lg.add_block(block.clone()) {
                        Ok(_) => {
                            println!("Mined a new block {}!", hex::encode(block.header().hash()));
                            self.blocks.write().unwrap().push(block.clone());

                            let mut mp = self.mempool.write().unwrap();
                            let added_tx_hashes: Vec<eupp_core::transaction::TransactionHash> = added_transactions.iter().map(|tx| tx.hash()).collect();
                            mp.remove_transactions(added_tx_hashes.into_iter());

                            let msg = NetworkMessage::Block(block);
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

    async fn handle_message(&self, msg: NetworkMessage) {
        match msg {
            NetworkMessage::Transaction(tx) => {
                let mut mp = self.mempool.write().unwrap();
                let lg = self.ledger.read().unwrap();
                match mp.add(tx, &*lg) {
                    Ok(_) => println!("New valid transaction added to mempool."),
                    Err(e) => println!("Failed to add transaction to mempool: {:?}", e),
                }
            }
            _ => {} // Other messages are handled in the run loop
        }
    }
}
