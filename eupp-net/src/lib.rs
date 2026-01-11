mod behavior;
pub mod mempool;
pub mod protocol;
pub mod rpc;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::mempool::Mempool;
use crate::protocol::{GossipMessage, SyncRequest, SyncResponse};
use eupp_core::block::BlockError;
use eupp_core::ledger::Ledger;
use eupp_core::transaction::{Transaction, TransactionError};
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
use std::sync::{Arc, RwLock};
use tokio::{sync::mpsc, time::Duration};

/// The number of blocks to fetch in a single synchronization chunk.
const BLOCKS_CHUNK_SIZE: usize = 16;

/// Represents the synchronization state of a peer, including its advertised supply.
#[derive(Clone, Debug)]
struct PeerSyncState {
    /// The total supply advertised by the peer.
    supply: u32,
}

#[derive(Debug)]
enum InternalEvent {
    ChainTipTimeout,
}

/// Represents the main node in the Eupp network, managing the ledger, mempool, and networking behavior.
pub struct EuppNode<L: Ledger, M: Mempool> {
    /// The ledger that maintains the blockchain state.
    ledger: Arc<RwLock<L>>,

    /// The mempool that holds transactions waiting to be included in a block.
    mempool: Arc<RwLock<M>>,

    /// The secret key used for cryptographic operations, such as signing transactions or blocks.
    secret_key: SecretKey,

    /// The current peer selected as the synchronization target, if any.
    sync_target: Arc<RwLock<Option<PeerId>>>,

    /// A map that tracks the synchronization state of peers.
    peers_sync_state: HashMap<PeerId, PeerSyncState>,

    /// A queue of block hashes that need to be fetched from peers during synchronization.
    block_fetch_queue: Vec<Hash>,
}

impl<L: Ledger + Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    /// Creates a new instance of `EuppNode` with the given ledger and mempool.
    pub fn new(ledger: L, mempool: M) -> Self {
        Self {
            secret_key: SecretKey::generate(),
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            block_fetch_queue: Vec::new(),
            peers_sync_state: HashMap::new(),
            sync_target: Arc::new(RwLock::new(None)),
        }
    }

    /// Checks if the node is currently in a synchronization state.
    fn is_syncing(&self) -> bool {
        self.sync_target.read().unwrap().is_some()
    }

    /// Handles incoming gossip messages and processes them based on their type.
    async fn handle_gossip_message(
        &mut self,
        message: gossipsub::Message,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
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
                if !self.is_syncing() {
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
                            // After adding a new block from gossip, broadcast a GetChainTip
                            // request so peers can advertise their tips via gossipsub.
                            if let Some((_peer, _)) = self.find_sync_target() {
                                let msg = GossipMessage::GetChainTip;
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic.clone(), bincode::serialize(&msg).unwrap())
                                {
                                    eprintln!("Failed to publish GetChainTip gossip: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("Failed to add block from gossip: {:?}", e);
                        }
                    }
                }
            }
            GossipMessage::GetChainTip => {
                // Respond by publishing our ChainTip via gossipsub.
                if let Some(meta) = self.ledger.read().unwrap().get_last_block_metadata() {
                    let msg = GossipMessage::ChainTip {
                        hash: meta.hash,
                        supply: meta.available_supply,
                    };
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), bincode::serialize(&msg).unwrap())
                    {
                        eprintln!("Failed to publish ChainTip gossip: {:?}", e);
                    }
                }
            }
            GossipMessage::ChainTip {
                hash: _hash,
                supply,
            } => {
                // Record peer's advertised supply for later selection. Use message.source if available.
                if let Some(source) = message.source {
                    self.peers_sync_state
                        .insert(source, PeerSyncState { supply });
                }
            }
        }
        Ok(())
    }

    /// Handles mDNS discovery events.
    fn handle_mdns_event(
        &mut self,
        event: mdns::Event,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) {
        if let mdns::Event::Discovered(list) = event {
            for (peer_id, _multiaddr) in list {
                println!("Discovered a new peer: {peer_id}");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                // Ask peers to advertise their chain tip via gossip.
                let msg = GossipMessage::GetChainTip;
                if let Err(e) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), bincode::serialize(&msg).unwrap())
                {
                    eprintln!("Failed to publish GetChainTip on mdns discovery: {:?}", e);
                }
            }
        }
    }

    /// Handles synchronization events from the request-response protocol.
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
                        SyncResponse::BlocksHash(hashes) => {
                            if hashes.len() <= 1 {
                                println!("Syncing done.");
                                *self.sync_target.write().unwrap() = None;
                                return;
                            }
                            self.block_fetch_queue = hashes;
                            // This will start the block fetch process
                            let _ = swarm.behaviour_mut().sync.send_request(
                                &peer,
                                SyncRequest::GetBlocks {
                                    from: Some([0; 32]),
                                    to: None,
                                },
                            );
                        }
                        SyncResponse::Blocks(blocks) => {
                            let sync_peer = *self.sync_target.read().unwrap();
                            if Some(peer) == sync_peer {
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
                                            *self.sync_target.write().unwrap() = None;
                                            return;
                                        }
                                        _ => {}
                                    }
                                }
                                // If there are no pending blocks, send a request to continue syncing
                                if self.block_fetch_queue.is_empty() {
                                    let to = blocks.first().map(|block| block.header().hash());
                                    let _ = swarm.behaviour_mut().sync.send_request(
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
                                    let _ = swarm
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

    /// Broadcast a GetChainTip over gossipsub and schedule a timeout that will trigger picking
    /// the peer with highest advertised supply and starting the block sync afterwards.
    fn request_chain_tip_and_schedule_timeout(
        &mut self,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
        internal_tx: mpsc::Sender<InternalEvent>,
        timeout: Duration,
    ) {
        println!("Broadcasting GetChainTip request");
        // Clear provisional sync target; we'll select the best peer after tip responses arrive.
        *self.sync_target.write().unwrap() = None;

        // Broadcast GetChainTip over gossipsub
        let msg = GossipMessage::GetChainTip;
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), bincode::serialize(&msg).unwrap())
        {
            eprintln!("Failed to publish GetChainTip gossip: {:?}", e);
        }

        // spawn a background task that will notify the main loop after the timeout
        // so it can choose the peer with highest supply and issue the GetBlocksHash.
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            // best-effort: ignore send errors (channel closed)
            let _ = internal_tx.send(InternalEvent::ChainTipTimeout).await;
        });
    }

    /// Sets the node to syncing state and sends the initial GetBlocksHash request.
    /// This is called after the ChainTip phase completes (or its timeout elapses).
    fn initiate_sync(&mut self, swarm: &mut Swarm<EuppBehaviour>, peer_id: PeerId) {
        println!(
            "Initiating sync with peer {}, starting from their tip",
            peer_id,
        );
        *self.sync_target.write().unwrap() = Some(peer_id);
        let lg = self.ledger.read().unwrap();
        let to = lg.get_last_block_metadata().map(|meta| meta.hash);

        // send_request returns an OutboundRequestId; ignore the return value.
        let _ = swarm
            .behaviour_mut()
            .sync
            .send_request(&peer_id, SyncRequest::GetBlocksHash { from: None, to });
    }

    /// Runs the main event loop for the node, handling network events and synchronization.
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

        // Set up channels for mining and RPC communication
        let (block_sender, mut block_receiver) = mpsc::channel(10);
        let (rpc_tx_sender, mut rpc_tx_receiver) = mpsc::channel(32);

        // Internal channel for notifications like chain tip timeouts
        let (internal_tx, mut internal_rx) = mpsc::channel(8);

        // Spawn the RPC server
        tokio::spawn(start_rpc_server(Arc::clone(&self.ledger), rpc_tx_sender));

        let ledger = Arc::clone(&self.ledger);
        let sync_target_miner = Arc::clone(&self.sync_target);
        let mut secret_key = [0; 32];
        secret_key.copy_from_slice(self.secret_key.as_ref());

        println!(
            "(Insecure Warning!) Secret Key: {}",
            hex::encode(secret_key)
        );

        tokio::spawn(async move {
            // Delay to allow initial setup before starting the loop
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                if sync_target_miner.read().unwrap().is_some() {
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
                    tokio::time::sleep(Duration::from_secs(1)).await; // Retry after a short delay
                    continue;
                };
                let start = OsRng.try_next_u64().unwrap() as usize;
                let result = tokio::task::spawn_blocking(move || {
                    miner::build_mining_tx(
                        &secret_key,
                        &prev_block_hash,
                        &lead_utxo_id.tx_hash,
                        &lead_utxo,
                        start..start + 10_000,
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

        let mut sync_check_interval = tokio::time::interval(Duration::from_secs(7)); // Periodic sync check
        let chain_tip_to_blocks_timeout = Duration::from_secs(3);

        loop {
            // Main event loop
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Mdns(event)) => {
                        self.handle_mdns_event(event, &mut swarm, topic.clone());
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Err(e) = self.handle_gossip_message(message, &mut swarm, topic.clone()).await {
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
                    // Broadcast GetChainTip periodically to gather peer chain tips
                    if !self.is_syncing() {
                        self.request_chain_tip_and_schedule_timeout(
                            &mut swarm,
                            topic.clone(),
                            internal_tx.clone(),
                            chain_tip_to_blocks_timeout,
                        );
                    }
                }
                Some(ev) = internal_rx.recv() => {
                    match ev {
                        InternalEvent::ChainTipTimeout => {
                            // Pick the best peer after gathering chain tips and start syncing
                            if let Some((peer, _)) = self.find_sync_target() {
                                println!("ChainTip gathering complete, initiating sync with {}", peer);
                                self.initiate_sync(&mut swarm, peer);
                            }
                        }
                    }
                }
                // Process transactions submitted via RPC
                Some(tx) = rpc_tx_receiver.recv() => {
                    let mut mp = self.mempool.write().unwrap();
                    let ledger = self.ledger.read().unwrap();
                    match mp.add(tx.clone(), &*ledger) {
                        Ok(_) => {
                            println!("-> Gossiping Tx {} from RPC", hex::encode(tx.hash()));
                            let msg = GossipMessage::Transaction(tx); // Broadcast transaction via gossip
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
                        let remaining = 1_000_000usize.saturating_sub(block.vsize());
                        let selected = mp.get_transactions().scan(remaining, |remaining, tx| { // Select transactions for the block
                            let tx_vsize = tx.vsize();
                            *remaining = remaining.saturating_sub(tx_vsize);
                            (*remaining > 0).then(|| tx)
                        });
                        block.transactions.extend(selected);
                    }

                    let mut lg = self.ledger.write().unwrap();
                    match lg.add_block(&block) {
                        Ok(_) => {
                            println!("-> Send Block via gossip {}", hex::encode(block.header().hash()));

                            let mut mp = self.mempool.write().unwrap();
                            let added_tx_hashes = block.transactions.iter().map(|tx| tx.hash());
                            mp.remove_transactions(added_tx_hashes);

                            let msg = GossipMessage::NewBlock(block); // Broadcast new block via gossip
                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bincode::serialize(&msg).unwrap());
                        }
                        Err(BlockError::TransactionError(TransactionError::InvalidOutput(output))) => {
                            let mut mp = self.mempool.write().unwrap();
                            mp.remove_transactions([output.tx_hash]);
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
