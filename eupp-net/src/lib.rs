pub mod behavior;
pub mod mempool;
pub mod protocol;
pub mod rpc;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::mempool::Mempool;
use crate::protocol::{GossipMessage, SyncRequest, SyncResponse};
use eupp_core::block::BlockError;
use eupp_core::ledger::Ledger;
use eupp_core::transaction::Transaction;
use eupp_core::{Hash, VirtualSize, block::Block, miner};
use eupp_rpc::EuppRpcServer;
use futures::StreamExt;
use libp2p::identity::ed25519::SecretKey;
use libp2p::{
    PeerId, StreamProtocol, SwarmBuilder, gossipsub, mdns,
    request_response::{self, ProtocolSupport},
    swarm::{Swarm, SwarmEvent},
};
use rand::TryRngCore;
use rand::rngs::OsRng;
use rpc::EuppRpcImpl;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::{sync::mpsc, time::Duration};

const BLOCKS_CHUNK_SIZE: usize = 16;

#[derive(Clone, Debug)]
struct PeerSyncState {
    supply: u32,
}

pub struct EuppNode<L: Ledger, M: Mempool> {
    ledger: Arc<RwLock<L>>,
    mempool: Arc<RwLock<M>>,
    secret_key: SecretKey,

    // In-memory sync state
    is_syncing: Arc<AtomicBool>,
    // A map of peers and their last advertised chain tip.
    peers_sync_state: HashMap<PeerId, PeerSyncState>,
    sync_target: Option<PeerId>,
    // The queue of block hashes to be fetched from peers.
    block_fetch_queue: Vec<Hash>,
}

impl<L: Ledger + Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    pub fn new(ledger: L, mempool: M) -> Self {
        Self {
            secret_key: SecretKey::generate(),
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            is_syncing: Arc::new(AtomicBool::new(false)),
            block_fetch_queue: Vec::new(),
            peers_sync_state: HashMap::new(),
            sync_target: None,
        }
    }

    /// Handles incoming gossip messages.
    async fn handle_gossip_message(
        &mut self,
        message: gossipsub::Message,
        swarm: &mut Swarm<EuppBehaviour>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let msg: GossipMessage = bincode::deserialize(&message.data)?;
        match msg {
            GossipMessage::Transaction(tx) => {
                let mut mp = self.mempool.write().unwrap();
                let lg = self.ledger.read().unwrap();
                let tx_hash = tx.hash();
                match mp.add(tx, &*lg) {
                    Ok(_) => println!(
                        "<- Recv Tx {} via gossip, added to mempool.",
                        hex::encode(tx_hash)
                    ),
                    Err(e) => println!("Failed to add transaction from gossip: {:?}", e),
                }
            }
            GossipMessage::NewBlock(block) => {
                if !self.is_syncing.load(Ordering::SeqCst) {
                    let added_res;
                    {
                        let mut lg = self.ledger.write().unwrap();
                        added_res = lg.add_block(&block);
                    }

                    match added_res {
                        Ok(_) => {
                            println!(
                                "<- Recv Block {} via gossip",
                                hex::encode(block.header().hash())
                            );
                            if let Some((peer, _)) = self.find_sync_target() {
                                self.initiate_sync(swarm, peer);
                            }
                        }
                        Err(e) => {
                            println!("Failed to add block from gossip: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles mDNS discovery events.
    fn handle_mdns_event(&mut self, event: mdns::Event, swarm: &mut Swarm<EuppBehaviour>) {
        if let mdns::Event::Discovered(list) = event {
            for (peer_id, _multiaddr) in list {
                println!("Discovered a new peer: {peer_id}");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer_id, SyncRequest::GetChainTip);
            }
        }
    }

    /// Handles request-response protocol events for synchronization.
    async fn handle_sync_event(
        &mut self,
        event: request_response::Event<SyncRequest, SyncResponse>,
        swarm: &mut Swarm<EuppBehaviour>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => match request {
                        SyncRequest::GetChainTip => {
                            let response =
                                self.ledger.read().unwrap().get_last_block_metadata().map(
                                    |metadata| SyncResponse::ChainTip {
                                        hash: metadata.hash,
                                        supply: metadata.available_supply,
                                    },
                                );
                            if let Some(response) = response {
                                if let Err(e) =
                                    swarm.behaviour_mut().sync.send_response(channel, response)
                                {
                                    eprintln!("Failed to send ChainTip response: {:?}", e);
                                }
                            }
                        }
                        SyncRequest::GetBlocksHash { from, to } => {
                            if let Ok(lg) = self.ledger.read() {
                                let iter = match from {
                                    Some(from) => lg.metadata_iter_from(&from),
                                    None => lg.metadata_iter(),
                                };
                                let halt = to
                                    .and_then(|hash| lg.get_block_metadata(&hash))
                                    .map(|meta| meta.prev_block_hash);
                                let hashes = iter
                                    .take_while(|meta| Some(meta.hash) != halt)
                                    .map(|meta| meta.hash)
                                    .collect();
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .sync
                                    .send_response(channel, SyncResponse::BlocksHash(hashes))
                                {
                                    eprintln!("Failed to send BlocksHash response: {:?}", e);
                                }
                            }
                        }
                        SyncRequest::GetBlocks { from, to } => {
                            if let Ok(lg) = self.ledger.read() {
                                let (block_iter, metadata_iter) = match from {
                                    Some(from) => {
                                        (lg.block_iter_from(&from), lg.metadata_iter_from(&from))
                                    }
                                    None => (lg.block_iter(), lg.metadata_iter()),
                                };
                                let halt = to
                                    .and_then(|hash| lg.get_block_metadata(&hash))
                                    .map(|meta| meta.prev_block_hash);
                                let blocks = block_iter
                                    .zip(metadata_iter)
                                    .take_while(|(_, meta)| Some(meta.hash) != halt)
                                    .map(|(block, _)| block)
                                    .collect();

                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .sync
                                    .send_response(channel, SyncResponse::Blocks(blocks))
                                {
                                    eprintln!("Failed to send Blocks response: {:?}", e);
                                }
                            }
                        }
                    },
                    request_response::Message::Response { response, .. } => match response {
                        SyncResponse::ChainTip { supply, .. } => {
                            self.peers_sync_state.insert(peer, PeerSyncState { supply });
                        }
                        SyncResponse::BlocksHash(hashes) => {
                            if hashes.len() <= 1 {
                                println!("Syncing done.");
                                self.is_syncing.store(false, Ordering::SeqCst);
                                self.sync_target = None;
                                return;
                            }
                            self.block_fetch_queue = hashes;
                            // This will start the block fetch process
                            swarm.behaviour_mut().sync.send_request(
                                &peer,
                                SyncRequest::GetBlocks {
                                    from: Some([0; 32]),
                                    to: None,
                                },
                            );
                        }
                        SyncResponse::Blocks(blocks) => {
                            let (is_syncing, sync_peer) =
                                (self.is_syncing.load(Ordering::SeqCst), self.sync_target);
                            if is_syncing && Some(peer) == sync_peer {
                                let mut lg = self.ledger.write().unwrap();
                                for block in blocks.iter().rev() {
                                    match lg.add_block(block) {
                                        Ok(_) => {
                                            println!(
                                                "<- Synced Block {}",
                                                hex::encode(block.header().hash())
                                            );
                                        }
                                        // Terminate sync if there's an invalid proof of chain.
                                        Err(BlockError::ChallengeError) => {
                                            eprintln!("Invalid proof of work!");
                                            self.is_syncing.store(false, Ordering::SeqCst);
                                            self.sync_target = None;
                                            return;
                                        }
                                        _ => {}
                                    }
                                }
                                // If there are no pending blocks, send a request to continue syncing
                                if self.block_fetch_queue.is_empty() {
                                    let to = blocks.first().map(|block| block.header().hash());
                                    swarm.behaviour_mut().sync.send_request(
                                        &peer,
                                        SyncRequest::GetBlocksHash { from: None, to },
                                    );
                                    return;
                                }
                                // If there are pending blocks, send request the next chunk
                                if let Some(chunk) =
                                    self.block_fetch_queue.rchunks(BLOCKS_CHUNK_SIZE).next()
                                {
                                    let from = chunk.first().copied();
                                    let to = chunk.last().copied();
                                    swarm
                                        .behaviour_mut()
                                        .sync
                                        .send_request(&peer, SyncRequest::GetBlocks { from, to });
                                    self.block_fetch_queue.truncate(
                                        self.block_fetch_queue
                                            .len()
                                            .saturating_sub(BLOCKS_CHUNK_SIZE),
                                    );
                                }
                            }
                        }
                    },
                }
            }
            _ => {}
        }
    }

    /// Identifies the best peer to sync with from the known peer states.
    fn find_sync_target(&self) -> Option<(PeerId, PeerSyncState)> {
        let local_supply = self
            .ledger
            .read()
            .ok()
            .and_then(|lg| lg.get_last_block_metadata())
            .map(|m| m.available_supply)
            .unwrap_or(0);

        self.peers_sync_state
            .iter()
            .filter(|(_, state)| state.supply > local_supply)
            .max_by_key(|(_, state)| state.supply)
            .map(|(peer_id, state)| (*peer_id, state.clone()))
    }

    /// Sets the node to syncing state and sends the initial GetBlocks request.
    fn initiate_sync(&mut self, swarm: &mut Swarm<EuppBehaviour>, peer_id: PeerId) {
        println!(
            "Initiating sync with peer {}, starting from their tip",
            peer_id,
        );
        self.is_syncing.store(true, Ordering::SeqCst);
        self.sync_target = Some(peer_id);
        let lg = self.ledger.read().unwrap();
        let to = lg.get_last_block_metadata().map(|meta| meta.hash);

        swarm
            .behaviour_mut()
            .sync
            .send_request(&peer_id, SyncRequest::GetBlocksHash { from: None, to });
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
                    sync: request_response::cbor::Behaviour::new(
                        [(StreamProtocol::new("/eupp/sync/1"), ProtocolSupport::Full)],
                        Default::default(),
                    ),
                })
            })?
            .build();

        let topic = gossipsub::IdentTopic::new("eupp-testnet");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        // Set up channels for mining and rpc
        let (block_sender, mut block_receiver) = mpsc::channel(10);
        let (rpc_tx_sender, mut rpc_tx_receiver) = mpsc::channel(32);

        // Spawn the RPC server
        tokio::spawn(start_rpc_server(Arc::clone(&self.ledger), rpc_tx_sender));

        let ledger = Arc::clone(&self.ledger);
        let is_synching = Arc::clone(&self.is_syncing);
        let mut secret_key = [0; 32];
        secret_key.copy_from_slice(self.secret_key.as_ref());

        println!(
            "(Insecure Warning!) Secret Key: {}",
            hex::encode(secret_key)
        );

        tokio::spawn(async move {
            // Sleep for 6 seconds before starting the loop
            tokio::time::sleep(Duration::from_secs(6)).await;
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
                let start = OsRng.try_next_u64().unwrap() as usize;
                let result = tokio::task::spawn_blocking(move || {
                    miner::build_mining_tx(
                        &secret_key,
                        &prev_block_hash,
                        &lead_utxo_id.tx_hash,
                        &lead_utxo,
                        start..start + 100_000,
                    )
                })
                .await
                .unwrap();
                if let Some((_key, mining_tx)) = result {
                    println!("Mining Transaction: {}", hex::encode(mining_tx.hash()));
                    let mut block = Block::new(0, prev_block_hash);
                    block.transactions.push(mining_tx);
                    if block_sender.send(block).await.is_err() {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        });

        let mut sync_check_interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Mdns(event)) => {
                        self.handle_mdns_event(event, &mut swarm);
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Err(e) = self.handle_gossip_message(message, &mut swarm).await {
                             eprintln!("Failed to handle gossip message: {:?}", e);
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Sync(event)) => {
                        self.handle_sync_event(event, &mut swarm).await;
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Local node listening on: {address}");
                    }
                    _ => {}
                },
                _ = sync_check_interval.tick() => {
                    println!("Sync check interval ticked");
                    if !self.is_syncing.load(Ordering::SeqCst) {
                        if let Some((peer_id, _)) = self.find_sync_target() {
                            self.initiate_sync(&mut swarm, peer_id);
                        }
                    }
                }
                // Handle transactions submitted from the RPC
                Some(tx) = rpc_tx_receiver.recv() => {
                    let mut mp = self.mempool.write().unwrap();
                    let ledger = self.ledger.read().unwrap();
                    match mp.add(tx.clone(), &*ledger) {
                        Ok(_) => {
                            println!("-> Gossiping Tx {} from RPC", hex::encode(tx.hash()));
                            let msg = GossipMessage::Transaction(tx);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg).unwrap()) {
                                eprintln!("Failed to publish RPC tx: {:?}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to add RPC tx to mempool: {:?}", e);
                        }
                    }
                }
                Some(mut block) = block_receiver.recv() => {
                    {
                        let mp = self.mempool.read().unwrap();
                        let current_vsize = block.vsize();
                        let tx_iter = mp.get_transactions().scan(1_000_000 - current_vsize, |acc, tx| {
                            let tx_vsize = tx.vsize();
                            *acc = acc.saturating_sub(tx_vsize);
                            (*acc > 0).then_some(tx)
                        });
                        block.transactions.extend(tx_iter);
                    }

                    let mut lg = self.ledger.write().unwrap();
                    match lg.add_block(&block) {
                        Ok(_) => {
                            println!("-> Send Block via gossip {}", hex::encode(block.header().hash()));

                            let mut mp = self.mempool.write().unwrap();
                            let added_tx_hashes = block.transactions.iter().map(|tx| tx.hash());
                            mp.remove_transactions(added_tx_hashes);

                            let msg = GossipMessage::NewBlock(block);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg).unwrap()) {
                                eprintln!("Failed to publish new block: {:?}", e);
                            }
                        }
                        Err(err) => {
                            eprintln!("Failed to add block to ledger: {:?}", err);
                        }
                    }
                }
            }
        }
    }
}

async fn start_rpc_server<L>(
    ledger: Arc<RwLock<L>>,
    tx_sender: mpsc::Sender<Transaction>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    L: Ledger + Send + Sync + 'static,
{
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("0.0.0.0:0".parse::<SocketAddr>()?)
        .await?;
    let local_addr = server.local_addr()?;
    let rpc_module = EuppRpcImpl::new(ledger, tx_sender);
    let handle = server.start(rpc_module.into_rpc());
    println!("RPC server listening on {}", local_addr);
    handle.stopped().await;
    Ok(())
}
