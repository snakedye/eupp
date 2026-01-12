use eupp_core::block::Block;
use eupp_core::transaction::Transaction;
use eupp_core::{Hash, block::BlockHeader};
use serde::{Deserialize, Serialize};

/// Messages broadcast over gossipsub for all peers to see.
///
/// We now use gossip for chain-tip advertising:
/// - `GossipMessage::GetChainTip` is a broadcast request asking peers to advertise
///   their current chain tip via gossip.
/// - `GossipMessage::ChainTip` is a broadcast containing a peer's current tip hash
///   and total supply. This replaces the previous `SyncResponse::ChainTip` which
///   was sent via the request-response protocol.
///
/// Peers still use the request-response protocol for direct sync operations:
/// `GetBlocks` / `GetBlocksHash` and `Blocks` / `BlocksHash`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GossipMessage {
    /// Broadcast a transaction to peers.
    Transaction(Transaction),

    /// A new block has been mined.
    NewBlock(Block),

    /// Broadcast a request asking peers to advertise their current chain tip.
    /// Nodes receiving this message should respond by publishing a `ChainTip`
    /// message over gossipsub (not via request-response).
    GetChainTip,

    /// Advertise the peer's current chain tip: latest block hash and total supply.
    ChainTip { hash: Hash, supply: u64 },
}

/// Requests sent directly to a peer for synchronization purposes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncRequest {
    /// Request a chunk of blocks in a given range.
    GetBlock {
        from: Option<Hash>,
        to: Option<Hash>,
    },

    /// Request the header of blocks in a given range.
    GetBlockHeader {
        from: Option<Hash>,
        to: Option<Hash>,
    },
}

/// Responses sent directly back to a peer for a `SyncRequest`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncResponse {
    /// A chunk of blocks in response to `GetBlocks`.
    Blocks(Vec<Block>),

    /// A chunk of block header in response to `GetBlocksHash`.
    BlockHeaders(Vec<BlockHeader>),
}
