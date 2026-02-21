mod behavior;
mod config;
mod mempool;
pub mod protocol;

use crate::behavior::{EuppBehaviour, EuppBehaviourEvent};
use crate::protocol::{
    BlockSummary, GossipMessage, NodeInfo, RpcError, RpcRequest, RpcResponse, SyncRequest,
    SyncResponse,
};
pub use config::Config;
use const_hex as hex;
use ethnum::U256;
use eupp_core::{
    ledger::{Indexer, IndexerExt, Ledger, LedgerExt, Query},
    *,
};
pub use mempool::*;

use libp2p::futures::StreamExt;
use libp2p::{
    PeerId, StreamProtocol, SwarmBuilder, gossipsub, mdns,
    request_response::{self, ProtocolSupport},
    swarm::{Swarm, SwarmEvent},
};
use tracing::{debug, error, info};

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;
use tokio::sync::mpsc;

/// Represents the synchronization state of a peer, including its advertised supply.
#[derive(Clone, Debug)]
struct PeerSyncState {
    /// The cumulative work advertised by the peer.
    cumulative_work: U256,
}

/// Represents a full node in the Eupp network.
type RpcResponder = tokio::sync::oneshot::Sender<Result<RpcResponse, RpcError>>;
type RpcRequestMessage = (RpcRequest, RpcResponder);

/// An RPC client to interact with the [`EuppNode`].
#[derive(Clone)]
pub struct RpcClient {
    inner: tokio::sync::mpsc::Sender<RpcRequestMessage>,
}

/// An handle to the synchronization state of the [`EuppNode`].
pub struct SyncHandle(Weak<RwLock<Option<PeerId>>>);

impl SyncHandle {
    pub fn is_syncing(&self) -> bool {
        self.0
            .upgrade()
            .map_or(false, |lock| lock.read().unwrap().is_some())
    }
}

impl RpcClient {
    /// Create a new RPC client that can send `RpcRequest` and await a `RpcResponse`.
    fn new(sender: tokio::sync::mpsc::Sender<RpcRequestMessage>) -> Self {
        Self { inner: sender }
    }

    /// Send a request and await the response.
    async fn request(&self, req: RpcRequest) -> Result<RpcResponse, RpcError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner
            .send((req, tx))
            .await
            .map_err(|_| RpcError::ChannelClosed)?;
        rx.await.map_err(|_| RpcError::ChannelClosed)?
    }

    /// Return basic node info (tip hash, height, available supply).
    pub async fn get_node_info(&self) -> Result<NodeInfo, RpcError> {
        match self.request(RpcRequest::GetNetworkInfo).await? {
            RpcResponse::NetworkInfo(info) => Ok(info),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Return confirmations for a given transaction hash.
    pub async fn get_confirmations(&self, tx_hash: TransactionHash) -> Result<u64, RpcError> {
        match self
            .request(RpcRequest::GetConfirmations { tx_hash })
            .await?
        {
            RpcResponse::Confirmations(conf) => Ok(conf),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Query UTXOs matching `Query`.
    pub async fn get_outputs(&self, query: Query) -> Result<Vec<(OutputId, Output)>, RpcError> {
        match self.request(RpcRequest::GetOutputs { query }).await? {
            RpcResponse::Outputs(outputs) => Ok(outputs),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Broadcast a raw transaction to the network.
    pub async fn broadcast_transaction(
        &self,
        tx: Transaction,
    ) -> Result<TransactionHash, RpcError> {
        match self
            .request(RpcRequest::BroadcastTransaction { tx })
            .await?
        {
            RpcResponse::TransactionHash(hash) => Ok(hash),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Broadcast a mined block to the network.
    pub async fn broadcast_block(&self, block: Block) -> Result<(), RpcError> {
        match self.request(RpcRequest::BroadcastBlock { block }).await? {
            RpcResponse::Ok => Ok(()),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Fetch a block header by its hash.
    pub async fn get_block_by_hash(&self, hash: Hash) -> Result<BlockSummary, RpcError> {
        match self.request(RpcRequest::GetBlockByHash { hash }).await? {
            RpcResponse::BlockSummary(summary) => Ok(summary),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Fetch a block header by a transaction hash.
    pub async fn get_block_by_tx_hash(
        &self,
        tx_hash: TransactionHash,
    ) -> Result<BlockSummary, RpcError> {
        match self
            .request(RpcRequest::GetBlockByTxHash { tx_hash })
            .await?
        {
            RpcResponse::BlockSummary(summary) => Ok(summary),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }

    /// Fetch the transactions in the mempool.
    pub async fn get_mempool(&self) -> Result<Vec<Transaction>, RpcError> {
        match self.request(RpcRequest::GetMempool).await? {
            RpcResponse::Transactions(txs) => Ok(txs),
            resp => Err(RpcError::UnexpectedResponse(resp)),
        }
    }
}

/// Represents a full node in the Eupp network.
pub struct EuppNode<I, M: Mempool> {
    /// The indexer that maintains the blockchain state.
    indexer: Arc<RwLock<I>>,

    /// The mempool that holds transactions waiting to be included in a block.
    mempool: Arc<RwLock<M>>,

    /// The current peer selected as the synchronization target, if any.
    sync_target: Arc<RwLock<Option<PeerId>>>,

    /// A map that tracks the synchronization state of peers.
    peers_sync_state: HashMap<PeerId, PeerSyncState>,

    /// A queue of block hashes that need to be fetched from peers during synchronization.
    block_fetch_queue: Vec<BlockHeader>,

    /// Node configuration.
    config: Config,
}

impl<I: Send + Sync + 'static, M: Mempool + Send + Sync + 'static> EuppNode<I, M> {
    /// Creates a new instance of `EuppNode` with the given ledger and mempool.
    pub fn new(config: Config, indexer: I, mempool: M) -> Self {
        Self {
            config,
            indexer: Arc::new(RwLock::new(indexer)),
            mempool: Arc::new(RwLock::new(mempool)),
            block_fetch_queue: Vec::new(),
            peers_sync_state: HashMap::new(),
            sync_target: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns true if the node is currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_target.read().unwrap().is_some()
    }

    /// Returns an handle to the synchronization state of the Eupp node.
    pub fn sync_handle(&self) -> SyncHandle {
        SyncHandle(Arc::downgrade(&self.sync_target))
    }

    /// Requests the chain tip from peers and initiates synchronization if a suitable peer is found.
    fn request_chain_tip(&mut self, swarm: &mut Swarm<EuppBehaviour>, topic: gossipsub::IdentTopic)
    where
        I: Indexer,
    {
        // Clear provisional sync target; we'll select the best peer after tip responses arrive.
        self.sync_target.write().unwrap().take();
        if let Some((peer_id, _)) = self.find_sync_target() {
            info!(
                peer_id = %peer_id,
                "ChainTip gathering complete, initiating sync",
            );
            self.initiate_sync(swarm, peer_id);
        }

        // Broadcast GetChainTip over gossipsub if there's a peer connected
        let msg = GossipMessage::GetChainTip;
        if let Err(err) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), postcard::to_allocvec(&msg).unwrap())
        {
            debug!(?err, "Failed to publish GetChainTip via gossip");
        }
    }

    /// Identifies the best peer to sync with from the known peer states.
    fn find_sync_target(&self) -> Option<(PeerId, PeerSyncState)>
    where
        I: Indexer,
    {
        let idxer = self.indexer.read().ok()?;
        let local_work = idxer
            .get_last_block_metadata()
            .map(|m| m.cumulative_work)
            .unwrap_or_default();

        self.peers_sync_state
            .iter()
            .filter(|(_, state)| state.cumulative_work > local_work)
            .max_by_key(|(_, state)| state.cumulative_work)
            .map(|(peer_id, state)| (*peer_id, state.clone()))
    }

    /// Sets the node to syncing state and sends the initial GetBlocksHash request.
    fn initiate_sync(&mut self, swarm: &mut Swarm<EuppBehaviour>, peer_id: PeerId)
    where
        I: Indexer,
    {
        info!(
            peer_id = %peer_id,
            "Initiating sync with peer, starting from their tip",
        );
        *self.sync_target.write().unwrap() = Some(peer_id);
        let idxer = self.indexer.read().unwrap();
        let to = idxer.get_last_block_metadata().map(|meta| meta.hash);

        // send_request returns an OutboundRequestId; ignore the return value.
        debug!(peer_id = %peer_id, "Sending GetBlockHeaders request to peer");
        swarm
            .behaviour_mut()
            .sync
            .send_request(&peer_id, SyncRequest::GetBlockHeaders { from: None, to });
    }

    /// Handles incoming gossip messages and processes them based on their type.
    async fn handle_gossip_message(
        &mut self,
        message: gossipsub::Message,
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        I: Indexer + TryAsRef<dyn Ledger>,
    {
        let msg: GossipMessage = postcard::from_bytes(&message.data)?;
        match msg {
            GossipMessage::Transaction(tx) => {
                let mut mp = self.mempool.write().unwrap();
                let idxer = self.indexer.read().unwrap();
                let tx_hash = tx.hash();

                match mp.add(tx, &*idxer) {
                    Ok(_) => {
                        info!(
                            tx_hash = %hex::encode(tx_hash),
                            "<- Recv Tx via gossip, added to mempool",
                        );
                    }
                    Err(err) => {
                        debug!(
                            tx_hash = %hex::encode(tx_hash),
                            error = ?err,
                            "Failed to add gossiped tx to mempool",
                        );
                    }
                }
            }
            GossipMessage::NewBlock(block) => {
                if !self.is_syncing() {
                    let added_res;
                    {
                        let mut idxer = self.indexer.write().unwrap();
                        added_res = idxer.add_block(&block);
                    }

                    match added_res {
                        Ok(_) => {
                            info!(
                                block_hash = %hex::encode(block.header().hash()),
                                "<- Recv Block via gossip",
                            );
                        }
                        Err(err) => {
                            error!(
                                block_hash = %hex::encode(block.header().hash()),
                                error = ?err,
                                "Failed to add gossiped block",
                            );
                        }
                    }
                }
            }
            GossipMessage::GetChainTip => {
                // Respond by publishing our ChainTip via gossipsub.
                if let Some(lg) = self
                    .indexer
                    .read()
                    .ok()
                    .filter(|idxer| idxer.try_as_ref().is_some())
                {
                    if let Some(meta) = lg.get_last_block_metadata() {
                        let msg = GossipMessage::ChainTip {
                            hash: meta.hash,
                            cumulative_work: meta.cumulative_work,
                        };
                        if let Err(err) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), postcard::to_allocvec(&msg).unwrap())
                        {
                            debug!(?err, "Failed to publish ChainTip via gossip");
                        }
                    }
                }
            }
            GossipMessage::ChainTip {
                hash: _hash,
                cumulative_work,
            } => {
                if let Some(source) = message.source {
                    self.peers_sync_state
                        .insert(source, PeerSyncState { cumulative_work });
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
                info!(peer_id = %peer_id, "Discovered a new peer");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                // Ask peers to advertise their chain tip via gossip.
                let msg = GossipMessage::GetChainTip;
                if let Err(err) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), postcard::to_allocvec(&msg).unwrap())
                {
                    debug!(?err, "Failed to publish GetChainTip to new peer via gossip");
                }
            }
        }
    }

    /// Handles synchronization events from the request-response protocol.
    async fn handle_sync_event(
        &mut self,
        event: request_response::Event<SyncRequest, SyncResponse>,
        swarm: &mut Swarm<EuppBehaviour>,
    ) where
        I: Indexer + TryAsRef<dyn Ledger>,
    {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => match request {
                        SyncRequest::GetBlockHeaders { from, to } => {
                            if let Ok(indexer) = self.indexer.read() {
                                let iter = match from {
                                    Some(from) => indexer.metadata_from(&from),
                                    None => indexer.metadata(),
                                };
                                let halt = to
                                    .and_then(|hash| indexer.get_block_metadata(&hash))
                                    .map(|meta| meta.prev_block_hash);
                                let headers: Vec<_> = iter
                                    .take_while(|meta| Some(meta.hash) != halt)
                                    .map(|meta| meta.header())
                                    .collect();
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .sync
                                    .send_response(channel, SyncResponse::BlockHeaders(headers))
                                {
                                    error!("Failed to send BlocksHash response: {:?}", e);
                                }
                            }
                        }
                        SyncRequest::GetBlocks { from, to } => {
                            if let Ok(idxer) = self.indexer.read() {
                                if let Some(lg) = (*idxer).try_as_ref() {
                                    debug!(
                                        from = from.map(hex::encode),
                                        to = to.map(hex::encode),
                                        "Sending Blocks",
                                    );
                                    let from = from
                                        .or_else(|| {
                                            idxer.get_last_block_metadata().map(|meta| meta.hash)
                                        })
                                        .unwrap_or_default(); // The hash of a non-existent block in the index
                                    let (block_iter, metadata_iter) =
                                        (lg.blocks_from(&from), idxer.metadata_from(&from));
                                    let halt = to
                                        .and_then(|hash| idxer.get_block_metadata(&hash))
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
                                        error!("Failed to send Blocks response: {:?}", e);
                                    }
                                }
                            }
                        }
                    },
                    request_response::Message::Response { response, .. } => match response {
                        SyncResponse::BlockHeaders(headers) => {
                            if headers.len() <= 1 {
                                info!("Syncing done.");
                                *self.sync_target.write().unwrap() = None;
                                return;
                            }
                            self.block_fetch_queue = headers;
                            // This will start the block fetch process
                            debug!(peer = %peer, "Sending initial GetBlocks request to peer");
                            swarm.behaviour_mut().sync.send_request(
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
                                let mut idxer = self.indexer.write().unwrap();
                                for block in blocks.iter().rev() {
                                    match idxer.add_block(block) {
                                        Ok(_) => {
                                            info!(
                                                block_hash = %hex::encode(block.header().hash()),
                                                "<- Synced Block",
                                            );
                                        }
                                        Err(err) => {
                                            error!("Failed to add block: {}", err);
                                            *self.sync_target.write().unwrap() = None;
                                            return;
                                        }
                                    }
                                }
                                // If there are no pending blocks, send a request to continue syncing
                                if self.block_fetch_queue.is_empty() {
                                    let to = blocks.first().map(|block| block.header().hash());
                                    debug!(peer = %peer, "Sending GetBlockHeaders request to continue sync");
                                    swarm.behaviour_mut().sync.send_request(
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
                                    debug!(peer = %peer, "Sending GetBlocks request for next chunk");
                                    swarm
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
        swarm: &mut Swarm<EuppBehaviour>,
        topic: gossipsub::IdentTopic,
    ) -> Result<RpcResponse, RpcError>
    where
        I: Indexer,
    {
        match request {
            RpcRequest::GetBlockByHash { hash: block_hash } => {
                let idxer = self.indexer.read().map_err(|_| RpcError::LockError)?;
                let block_metadata = idxer.get_block_metadata(&block_hash).ok_or_else(|| {
                    RpcError::BadRequest("Block not found for the given hash".into())
                })?;
                Ok(RpcResponse::BlockSummary(block_metadata.into()))
            }
            RpcRequest::GetBlockByTxHash { tx_hash } => {
                let idxer = self.indexer.read().map_err(|_| RpcError::LockError)?;
                let block_hash = idxer.get_block_from_transaction(&tx_hash).ok_or_else(|| {
                    RpcError::BadRequest("Block not found for the given transaction hash".into())
                })?;
                let block_metadata = idxer.get_block_metadata(&block_hash).ok_or_else(|| {
                    RpcError::BadRequest("Block metadata not found for the given hash".into())
                })?;
                Ok(RpcResponse::BlockSummary(block_metadata.into()))
            }
            RpcRequest::GetNetworkInfo => {
                let idxer = self.indexer.read().map_err(|_| RpcError::LockError)?;
                let info = idxer
                    .get_last_block_metadata()
                    .map(|meta| NodeInfo {
                        tip_hash: meta.hash,
                        tip_height: meta.height as u64,
                        available_supply: meta.available_supply,
                        peers: swarm
                            .connected_peers()
                            .map(|peer_id| peer_id.to_base58())
                            .collect(),
                        cummulative_difficulty: meta.cumulative_work.to_le_bytes(),
                    })
                    .unwrap_or_default();

                Ok(RpcResponse::NetworkInfo(info))
            }
            RpcRequest::GetConfirmations { tx_hash } => {
                let idxer = self.indexer.read().map_err(|_| RpcError::LockError)?;
                let tip_metadata = idxer.get_last_block_metadata();
                let tx_block_hash = idxer.get_block_from_transaction(&tx_hash);
                let confirmations = match (tip_metadata, tx_block_hash) {
                    (Some(tip), Some(block_hash)) => {
                        let block_metadata = idxer.get_block_metadata(&block_hash).unwrap();
                        tip.height.saturating_sub(block_metadata.height) as u64
                    }
                    _ => 0u64,
                };
                Ok(RpcResponse::Confirmations(confirmations))
            }
            RpcRequest::GetOutputs { query } => {
                let idxer = self.indexer.read().map_err(|_| RpcError::LockError)?;
                let outputs = idxer.query_outputs(&query);
                Ok(RpcResponse::Outputs(outputs))
            }
            RpcRequest::GetMempool => {
                let mp = self.mempool.read().map_err(|_| RpcError::LockError)?;
                let mempool = mp.get_transactions().map(|tx| tx.into_owned());
                Ok(RpcResponse::Transactions(mempool.collect()))
            }
            RpcRequest::BroadcastBlock { block } => {
                let mut indexer = self.indexer.write().map_err(|_| RpcError::LockError)?;
                match indexer.add_block(&block) {
                    Ok(_) => {
                        info!(
                            block_hash = %hex::encode(block.header().hash()),
                            "-> Send Block via gossip",
                        );

                        // Remove transactions included in the block from the mempool
                        let mut mp = self.mempool.write().unwrap();
                        let added_tx_hashes = block.transactions.iter().map(Transaction::hash);
                        mp.remove_transactions(added_tx_hashes);

                        // Broadcast new block via gossip
                        let msg = GossipMessage::NewBlock(block);
                        if let Err(err) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), postcard::to_allocvec(&msg).unwrap())
                        {
                            debug!(?err, "Failed to publish NewBlock via gossip");
                        }
                        Ok(RpcResponse::Ok)
                    }
                    Err(err) => {
                        // Clear mempool on other errors and log
                        self.mempool.write().unwrap().clear();
                        Err(RpcError::BadRequest(err.to_string()))
                    }
                }
            }
            RpcRequest::BroadcastTransaction { tx } => {
                // Attempt to add to local mempool, then gossip.
                let tx_hash = tx.hash();
                let mut mempool = self.mempool.write().unwrap();
                let idxer = self.indexer.read().unwrap();
                match mempool.add(tx.clone(), &*idxer) {
                    Ok(_) => {
                        let msg = GossipMessage::Transaction(tx);
                        if let Err(err) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), postcard::to_allocvec(&msg).unwrap())
                        {
                            debug!(?err, "Failed to publish Transaction via gossip");
                        }
                        info!(tx_hash = %hex::encode(tx_hash), "-> Gossiping Tx from RPC");
                        Ok(RpcResponse::TransactionHash(tx_hash))
                    }
                    Err(e) => Err(RpcError::BadRequest(format!(
                        "Failed to add transaction to mempool: {:?}",
                        e
                    ))),
                }
            }
        }
    }

    /// Runs the main event loop for the node, handling network events and synchronization.
    pub async fn run<F>(mut self, f: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(RpcClient),
        I: Indexer + TryAsRef<dyn Ledger>,
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

        let topic = gossipsub::IdentTopic::new(self.config.network_name());
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        let listen_addr = match self.config.p2p_port {
            Some(port) => format!("/ip4/0.0.0.0/tcp/{}", port),
            None => "/ip4/0.0.0.0/tcp/0".to_string(),
        };
        swarm.listen_on(listen_addr.parse()?)?;

        // RPC client channel
        let (rpc_tx, mut rpc_rx) = mpsc::channel::<RpcRequestMessage>(8);
        f(RpcClient::new(rpc_tx));

        let mut sync_check_interval = tokio::time::interval(Duration::from_secs(5)); // Periodic sync check

        loop {
            // Main event loop
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Mdns(event)) => {
                        self.handle_mdns_event(event, &mut swarm, topic.clone());
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Err(e) = self.handle_gossip_message(message, &mut swarm, topic.clone()).await {
                             error!("Failed to handle gossip message: {:?}", e);
                        }
                    },
                    SwarmEvent::Behaviour(EuppBehaviourEvent::Sync(event)) => {
                        self.handle_sync_event(event, &mut swarm).await;
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(address = %address, "Local node listening on");
                    }
                    _ => {}
                },
                Some((request, responder)) = rpc_rx.recv() => {
                    let result = self.handle_rpc_event(request, &mut swarm, topic.clone()).await;
                    if let Err(_) = responder.send(result) {
                        error!("Failed to send RPC response: receiver dropped");
                    }
                }
                _ = sync_check_interval.tick() => {
                    // Broadcast GetChainTip periodically to gather peer chain tips
                    self.request_chain_tip(
                        &mut swarm,
                        topic.clone(),
                    );
                }
            }
        }
    }
}
