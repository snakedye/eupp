use eupp_core::{ledger::Query, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// The hash of the current tip block.
    pub tip_hash: Hash,
    /// The height of the current tip block.
    pub tip_height: u64,
    /// The currently available supply of coins.
    pub available_supply: u64,
    /// The list of connected peers.
    pub peers: Vec<String>,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// The cummulative difficulty of the blockchain in the amount of bits used.
    pub cummulative_difficulty: [u8; 32],
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

/// RPC requests sent directly to a peer.
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
    BroadcastTransaction { tx: Transaction },

    /// Broadcast a mined block to the network.
    BroadcastBlock { block: Block },

    /// Fetch a block header by its hash.
    GetBlockByHash { block_hash: Hash },

    /// Fetch a block header by a transaction hash.
    GetBlockByTxHash { tx_hash: TransactionHash },
}

/// RPC responses for `RpcRequest`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RpcResponse {
    /// Success.
    Ok,

    /// Detailed network information.
    NetworkInfo(NetworkInfo),

    /// The number of confirmations for a given transaction hash.
    Confirmations(u64),

    /// All matched UTXOs in one response: pairs of (OutputId, Output).
    Utxos(Vec<(OutputId, Output)>),

    /// The hash of the broadcasted transaction.
    TransactionHash(TransactionHash),

    /// All transactions currently in the mempool.
    Transactions(Vec<Transaction>),

    /// The block header for a given block hash or transaction hash.
    BlockHeader(BlockHeader),
}

/// Errors returned by [`RpcClient::request`].
#[derive(Debug)]
pub enum RpcError {
    /// The internal channel is closed (node shut down or receiver dropped).
    ChannelClosed,
    /// A shared lock (e.g. ledger or mempool) could not be acquired.
    LockError,
    /// Unexpected response from the RPC server.
    UnexpectedResponse(RpcResponse),
    /// The request was malformed.
    BadRequest(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ChannelClosed => write!(f, "RPC channel closed"),
            RpcError::LockError => write!(f, "failed to acquire internal lock"),
            RpcError::UnexpectedResponse(resp) => write!(f, "unexpected response: {:?}", resp),
            RpcError::BadRequest(err) => write!(f, "bad request: {}", err),
        }
    }
}

impl std::error::Error for RpcError {}
