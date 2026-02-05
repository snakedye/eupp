mod behavior;
pub mod config;
pub mod mempool;
pub mod protocol;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::config::Config;
use crate::mempool::Mempool;
use crate::protocol::{
    GossipMessage, NetworkInfo, RpcRequest, RpcResponse, SyncRequest, SyncResponse,
};
use eupp_core::block::{BlockError, BlockHeader, MAX_BLOCK_SIZE};
use eupp_core::ledger::{Indexer, IndexerExt, LedgerExt};
use eupp_core::transaction::{Transaction, TransactionError};
use eupp_core::{VirtualSize, block::Block, miner};

use futures::StreamExt;
use libp2p::{
    PeerId, StreamProtocol, SwarmBuilder, gossipsub, mdns,
    request_response::{self, ProtocolSupport},
    swarm::{Swarm, SwarmEvent},
};
use rand::TryRngCore;
use rand::rngs::OsRng;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::{sync::mpsc, time::Duration};
/// Represents the synchronization state of a peer, including its advertised supply.
#[derive(Clone, Debug)]
struct PeerSyncState {
    /// The total supply advertised by the peer.
    supply: u64,
}

#[derive(Debug)]
enum InternalEvent {
    ChainTipTimeout,
}

/// Represents a full node in the Eupp network.
type RpcResponder = tokio::sync::oneshot::Sender<RpcResponse>;
type RpcRequestMessage = (RpcRequest, RpcResponder);

#[derive(Clone)]
pub struct RpcClient {
    inner: tokio::sync::mpsc::Sender<RpcRequestMessage>,
}

impl RpcClient {
    /// Create a new RPC client that can send `RpcRequest` and await a `RpcResponse`.
    fn new(sender: tokio::sync::mpsc::Sender<RpcRequestMessage>) -> Self {
        Self { inner: sender }
    }

    /// Send a request and await the response.
    pub async fn request(&self, req: RpcRequest) -> Option<RpcResponse> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner.send((req, tx)).await.ok()?;
        rx.await.ok()
    }
}

/// Represents a full node in the Eupp network.
pub struct EuppNode<L, M: Mempool> {
    /// The ledger that maintains the blockchain state.
    ledger: Arc<RwLock<L>>,

    /// The mempool that holds transactions waiting to be included in a block.
    mempool: Arc<RwLock<M>>,

    /// The current peer selected as the synchronization target, if any.
    sync_target: Arc<RwLock<Option<PeerId>>>,

    /// A map that tracks the synchronization state of peers.
    peers_sync_state: HashMap<PeerId, PeerSyncState>,

    /// A queue of block hashes that need to be fetched from peers during synchronization.
    block_fetch_queue: Vec<BlockHeader>,

    /// Node configuration
    config: Config,

    /// Internal RPC server sender.
    rpc: tokio::sync::mpsc::Sender<RpcRequestMessage>,
}

impl<L: Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<L, M> {
    /// Creates a new instance of `EuppNode` with the given ledger and mempool.
    pub fn new(config: Config, ledger: L, mempool: M) -> Self {
        // Create an initial internal RPC channel sender so the node always has a valid sender.
        // The receiver will be created again in `run` and the sender replaced, which is fine —
        // this provides a usable sender immediately after construction.
        let (rpc_tx, _rpc_rx) = mpsc::channel::<RpcRequestMessage>(8);

        Self {
            config,
            ledger: Arc::new(RwLock::new(ledger)),
            mempool: Arc::new(RwLock::new(mempool)),
            block_fetch_queue: Vec::new(),
            peers_sync_state: HashMap::new(),
            sync_target: Arc::new(RwLock::new(None)),
            rpc: rpc_tx,
        }
    }

    /// Checks if the node is currently in a synchronization state.
    pub fn rpc_client(&self) -> RpcClient {
        // Return a client handle that shares the internal RPC sender.
        RpcClient::new(self.rpc.clone())
    }

    fn is_syncing(&self) -> bool {
        self.sync_target.read().unwrap().is_some()
    }

    /// Sets the node to syncing state and sends the initial GetBlocksHash request.
    /// This is called after the ChainTip phase completes (or its timeout elapses).
    fn initiate_sync(&mut self, swarm: &mut Swarm<EuppBehaviour>, peer_id: PeerId)
    where
        L: Indexer,
    {
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
            .send_request(&peer_id, SyncRequest::GetBlockHeaders { from: None, to });
    }

    /// Identifies the best peer to sync with from the known peer states.
    fn find_sync_target(&self) -> Option<(PeerId, PeerSyncState)>
    where
        L: Indexer,
    {
        let lg = self.ledger.read().ok()?;
        let local_supply = lg
            .get_last_block_metadata()
            .map(|m| m.available_supply)
            .unwrap_or(0);

        self.peers_sync_state
            .iter()
            .filter(|(_, state)| state.supply > local_supply)
            .max_by_key(|(_, state)| state.supply)
            .map(|(peer_id, state)| (*peer_id, state.clone()))
    }

    /// Handles incoming gossip messages and processes them based on their type.
    async fn handle_gossip_message(
        &mut self,
        message: gossipsub::Message,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        L: Indexer,
    {
        let msg: GossipMessage = bincode::deserialize(&message.data)?;
        match msg {
            GossipMessage::Transaction(tx) => {
                let mut mp = self.mempool.write().unwrap();
                let lg = self.ledger.read().unwrap();
                let tx_hash = tx.hash();
                if let Ok(_) = mp.add(tx, &*lg) {
                    println!(
                        "<- Recv Tx {} via gossip, added to mempool.",
                        hex::encode(tx_hash)
                    );
                }
            }
            GossipMessage::NewBlock(block) => {
                if !self.is_syncing() {
                    let added_res;
                    {
                        let mut lg = self.ledger.write().unwrap();
                        added_res = lg.add_block(&block);
                    }

                    if let Ok(_) = added_res {
                        println!(
                            "<- Recv Block {} via gossip",
                            hex::encode(block.header().hash())
                        );
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
                    let _ = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), bincode::serialize(&msg).unwrap());
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
                let _ = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), bincode::serialize(&msg).unwrap());
            }
        }
    }

    /// Handles synchronization events from the request-response protocol.
    async fn handle_sync_event(
        &mut self,
        event: request_response::Event<SyncRequest, SyncResponse>,
        swarm: &mut Swarm<EuppBehaviour>,
    ) where
        L: Indexer,
    {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => match request {
                        SyncRequest::GetBlockHeaders { from, to } => {
                            if let Ok(lg) = self.ledger.read() {
                                let iter = match from {
                                    Some(from) => lg.metadata_from(&from),
                                    None => lg.metadata(),
                                };
                                let halt = to
                                    .and_then(|hash| lg.get_block_metadata(&hash))
                                    .map(|meta| meta.prev_block_hash);
                                let headers = iter
                                    .take_while(|meta| Some(meta.hash) != halt)
                                    .map(|meta| meta.header())
                                    .collect();
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .sync
                                    .send_response(channel, SyncResponse::BlockHeaders(headers))
                                {
                                    eprintln!("Failed to send BlocksHash response: {:?}", e);
                                }
                            }
                        }
                        SyncRequest::GetBlocks { from, to } => {
                            if let Ok(lg) = self.ledger.read() {
                                if let Some(lg) = lg.as_ledger() {
                                    let (block_iter, metadata_iter) = match from {
                                        Some(from) => {
                                            (lg.blocks_from(&from), lg.metadata_from(&from))
                                        }
                                        None => (lg.blocks(), lg.metadata()),
                                    };
                                    let halt = to
                                        .and_then(|hash| lg.get_block_metadata(&hash))
                                        .map(|meta| meta.prev_block_hash);
                                    let blocks = block_iter
                                        .zip(metadata_iter)
                                        .take_while(|(_, meta)| Some(meta.hash) != halt)
                                        .map(|(block, _)| block.into_owned())
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
                        }
                    },
                    request_response::Message::Response { response, .. } => match response {
                        SyncResponse::BlockHeaders(headers) => {
                            if headers.len() <= 1 {
                                println!("Syncing done.");
                                *self.sync_target.write().unwrap() = None;
                                return;
                            }
                            self.block_fetch_queue = headers;
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
                                        // Terminate sync if there's an invalid proof of work.
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
                                        SyncRequest::GetBlockHeaders { from: None, to },
                                    );
                                    return;
                                }
                                // If there are pending blocks, send request the next chunk
                                if let Some(chunk) = self
                                    .block_fetch_queue
                                    .rchunks(self.config.block_chunk_size)
                                    .next()
                                {
                                    let from = chunk.first().map(|h| h.hash());
                                    let to = chunk.last().map(|h| h.hash());
                                    let _ = swarm
                                        .behaviour_mut()
                                        .sync
                                        .send_request(&peer, SyncRequest::GetBlocks { from, to });
                                    self.block_fetch_queue.truncate(
                                        self.block_fetch_queue
                                            .len()
                                            .saturating_sub(self.config.block_chunk_size),
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

    /// Handles incoming internal RPC requests.
    async fn handle_rpc_event(
        &mut self,
        request: RpcRequest,
        responder: tokio::sync::oneshot::Sender<RpcResponse>,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) where
        L: Indexer,
    {
        match request {
            RpcRequest::GetNetworkInfo => {
                if let Ok(lg) = self.ledger.read() {
                    let info = lg
                        .get_last_block_metadata()
                        .map(|meta| NetworkInfo {
                            tip_hash: meta.hash,
                            tip_height: meta.height as u64,
                            available_supply: meta.available_supply,
                            peers: swarm
                                .connected_peers()
                                .map(|peer_id| peer_id.to_base58())
                                .collect(),
                            cummulative_difficulty: meta.cumulative_work.bits(),
                        })
                        .unwrap_or_default();

                    let _ = responder.send(RpcResponse::NetworkInfo(info));
                } else {
                    // Best-effort: drop response on lock failure
                    let _ = responder.send(RpcResponse::NetworkInfo(Default::default()));
                }
            }
            RpcRequest::GetConfirmations { tx_hash } => {
                if let Ok(lg) = self.ledger.read() {
                    let tip_metadata = lg.get_last_block_metadata();
                    let tx_block_hash = lg.get_transaction_block_hash(&tx_hash);
                    let confirmations = match (tip_metadata, tx_block_hash) {
                        (Some(tip), Some(block_hash)) => {
                            let block_metadata = lg.get_block_metadata(&block_hash).unwrap();
                            tip.height.saturating_sub(block_metadata.height) as u64
                        }
                        _ => 0u64,
                    };
                    let _ = responder.send(RpcResponse::Confirmations(confirmations));
                } else {
                    let _ = responder.send(RpcResponse::Confirmations(0));
                }
            }
            RpcRequest::GetUtxos { query } => {
                if let Ok(lg) = self.ledger.read() {
                    let outputs = lg.query_utxos(&query).collect();
                    let _ = responder.send(RpcResponse::Utxos(outputs));
                } else {
                    let _ = responder.send(RpcResponse::Utxos(Vec::new()));
                }
            }
            RpcRequest::SendRawTransaction { tx } => {
                // Attempt to add to local mempool, then gossip.
                let tx_hash = tx.hash();
                println!("-> Gossiping Tx {} from RPC", hex::encode(tx_hash));
                let mut mempool = self.mempool.write().unwrap();
                let lg = self.ledger.read().unwrap();
                match mempool.add(tx.clone(), &*lg) {
                    Ok(_) => {
                        let msg = GossipMessage::Transaction(tx);
                        let _ = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), bincode::serialize(&msg).unwrap());
                        let _ = responder.send(RpcResponse::TransactionHash(tx_hash));
                    }
                    Err(e) => {
                        eprintln!("Failed to add transaction to mempool: {:?}", e);
                        // Return an empty/failed response if desired; using TransactionHash([0;32]) is not appropriate.
                        // For now, send back an empty hash to indicate failure (caller should handle).
                        let _ = responder.send(RpcResponse::TransactionHash([0; 32]));
                    }
                }
            }
        }
    }

    /// Handle a mined block: select mempool transactions, attempt to add to ledger,
    /// remove included txs from mempool, and gossip the new block.
    fn handle_mined_block(
        &mut self,
        mut block: Block,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) where
        L: Indexer,
    {
        {
            let mp = self.mempool.read().unwrap();
            let remaining = MAX_BLOCK_SIZE.saturating_sub(block.vsize());
            let selected = mp.get_transactions().scan(remaining, |remaining, tx| {
                // Select transactions for the block
                let tx_vsize = tx.vsize();
                *remaining = remaining.saturating_sub(tx_vsize);
                (*remaining > 0).then(|| tx.into_owned())
            });
            block.transactions.extend(selected);
        }

        let mut lg = self.ledger.write().unwrap();
        loop {
            match lg.add_block(&block) {
                Ok(_) => {
                    println!(
                        "-> Send Block via gossip {}",
                        hex::encode(block.header().hash())
                    );

                    // Remove transactions included in the block from the mempool
                    let mut mp = self.mempool.write().unwrap();
                    let added_tx_hashes = block.transactions.iter().map(Transaction::hash);
                    mp.remove_transactions(added_tx_hashes);

                    // Broadcast new block via gossip
                    let msg = GossipMessage::NewBlock(block);
                    let _ = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), bincode::serialize(&msg).unwrap());
                    break;
                }
                Err(BlockError::TransactionError(TransactionError::InvalidOutput(output_id)))
                | Err(BlockError::TransactionError(TransactionError::DoubleSpend(output_id))) => {
                    // Remove offending transaction from the mempool
                    let mut mp = self.mempool.write().unwrap();
                    mp.remove_transactions([output_id.tx_hash]);
                }
                Err(err) => {
                    // Clear mempool on other errors and log
                    self.mempool.write().unwrap().clear();
                    eprintln!("Failed to add block to ledger: {:?}", err);
                    break;
                }
            }
        }
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
        // println!("Broadcasting GetChainTip request");
        // Clear provisional sync target; we'll select the best peer after tip responses arrive.
        *self.sync_target.write().unwrap() = None;

        // Broadcast GetChainTip over gossipsub
        let msg = GossipMessage::GetChainTip;
        let _ = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), bincode::serialize(&msg).unwrap());

        // spawn a background task that will notify the main loop after the timeout
        // so it can choose the peer with highest supply and issue the GetBlocksHash.
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            // best-effort: ignore send errors (channel closed)
            let _ = internal_tx.send(InternalEvent::ChainTipTimeout).await;
        });
    }

    /// Runs the main event loop for the node, handling network events and synchronization.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>>
    where
        L: Indexer,
    {
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
        // Use configured port if present, otherwise bind to an ephemeral port (0)
        let listen_addr = match self.config.port {
            Some(p) => format!("/ip4/0.0.0.0/tcp/{}", p),
            None => "/ip4/0.0.0.0/tcp/0".to_string(),
        };
        swarm.listen_on(listen_addr.parse()?)?;

        // Set up channels for mining communication
        let (block_tx, mut block_rx) = mpsc::channel(1);

        // Internal channel for notifications like chain tip timeouts
        let (internal_tx, mut internal_rx) = mpsc::channel(8);

        // Internal RPC channel (internal request/response)
        let (rpc_tx, mut rpc_rx) = mpsc::channel::<RpcRequestMessage>(8);
        // Store sender in node so other components can create RpcClient instances.
        self.rpc = rpc_tx.clone();

        let ledger = Arc::clone(&self.ledger);
        let sync_target_miner = Arc::clone(&self.sync_target);
        let secret_key = self.config.secret_key();

        // Spawn mining loop only if mining is enabled in the config
        if self.config.mining {
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
                        let mut block = Block::new(0, prev_block_hash);
                        block.transactions.push(mining_tx);
                        if block_tx.send(block).await.is_err() {
                            break;
                        }
                    }
                    tokio::task::yield_now().await;
                }
            });
        }

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
                Some(block) = block_rx.recv() => {
                    self.handle_mined_block(block, &mut swarm, topic.clone());
                }
                Some((request, responder)) = rpc_rx.recv() => {
                    // Handle internal RPC requests (this will respond via the oneshot responder)
                    self.handle_rpc_event(request, responder, &mut swarm, topic.clone()).await;
                }
                _ = sync_check_interval.tick() => {
                    // Broadcast GetChainTip periodically to gather peer chain tips
                    self.request_chain_tip_and_schedule_timeout(
                        &mut swarm,
                        topic.clone(),
                        internal_tx.clone(),
                        chain_tip_to_blocks_timeout,
                    );
                }
            }
        }
    }
}
