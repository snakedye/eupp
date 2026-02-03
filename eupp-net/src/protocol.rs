use eupp_core::block::Block;
use eupp_core::transaction::{Output, OutputId, Transaction, TransactionHash};
use eupp_core::{Hash, block::BlockHeader, ledger::Query};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// The hash of the current tip block.
    pub tip_hash: Hash,
    /// The height of the current tip block.
    pub tip_height: u64,
    /// The currently available supply of coins.
    pub available_supply: u64,
}

/// Messages broadcast over gossipsub for all peers to see.
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
    GetBlocks {
        from: Option<Hash>,
        to: Option<Hash>,
    },

    /// Request the header of blocks in a given range.
    GetBlockHeaders {
        from: Option<Hash>,
        to: Option<Hash>,
    },
}

/// Responses sent directly back to a peer for a `SyncRequest`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncResponse {
    /// A chunk of blocks in response to `GetBlocks`.
    Blocks(Vec<Block>),

    /// A chunk of block headers in response to `GetBlockHeaders`.
    BlockHeaders(Vec<BlockHeader>),
}

/// RPC requests sent directly to a peer (over libp2p request/response).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RpcRequest {
    /// Return basic network info (tip hash, height, available supply).
    GetNetworkInfo,

    /// Return confirmations for a given transaction hash.
    GetConfirmations { tx_hash: TransactionHash },

    /// Query UTXOs matching `Query`.
    GetUtxos { query: Query },

    /// Broadcast a raw transaction to the network.
    /// Expect a `TransactionHash` in the response on success.
    SendRawTransaction { tx: Transaction },
}

/// RPC responses for `RpcRequest`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RpcResponse {
    /// Response to `GetNetworkInfo`.
    NetworkInfo(NetworkInfo),

    /// Response to `GetConfirmations`.
    Confirmations(u64),

    /// All matched UTXOs in one response: pairs of (OutputId, Output).
    Utxos(Vec<(OutputId, Output)>),

    /// Response to `SendRawTransaction` containing the hash of the broadcasted transaction.
    TransactionHash(TransactionHash),
}
