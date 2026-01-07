use eupp_core::Hash;
use eupp_core::block::Block;
use eupp_core::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// Messages broadcast over gossipsub for all peers to see.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GossipMessage {
    /// Broadcast a transaction to peers.
    Transaction(Transaction),
    /// A new block has been mined.
    NewBlock(Block),
}

/// Requests sent directly to a peer for synchronization purposes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncRequest {
    /// Ask a peer for their current chain tip (latest block hash and total supply).
    GetChainTip,

    /// Request a chunk of blocks starting from a given hash.
    GetBlocks {
        // from: Option<Hash>,
        to: Option<Hash>,
    },
}

/// Responses sent directly back to a peer for a `SyncRequest`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncResponse {
    /// The peer's current chain tip.
    ChainTip { hash: Hash, supply: u32 },

    /// A chunk of blocks in response to `GetBlocks`.
    Blocks(Vec<Block>),
}
