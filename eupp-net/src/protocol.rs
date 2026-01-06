use eupp_core::transaction::Transaction;
use eupp_core::{Hash, block::Block};
use serde::{Deserialize, Serialize};

/// Requests sent on the network.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkRequest {
    /// Broadcast a transaction to peers.
    Transaction(Transaction),

    /// Ask peers for their current maximum available supply (handshake / chain tip summary).
    GetMaxSupply,

    /// Request blocks starting from the given height (inclusive).
    /// Optionally target the request to a specific peer by providing their peer id as a string.
    /// If `peer_id` is `None`, this is a broadcast request (existing behavior).
    GetBlocks {
        from: Hash,              // starting block hash (non-inclusive)
        peer_id: Option<String>, // optional target peer id as string
    },
}

/// Responses sent on the network.
///
/// Keeping responses separate makes it clearer which messages are replies
/// and which are initiating requests.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkResponse {
    /// Reply with the maximum available supply observed by the peer.
    MaxSupply(u32),

    /// Reply with a single block and its target (preferred for streaming/ordered delivery).
    Block {
        /// The hash of the last block in the sequence.
        target: Option<Hash>,
        /// The block sent
        block: Block,
    },
}

/// Top-level message wrapper that explicitly separates requests and responses.
///
/// This preserves a single exported type while still providing strong
/// separation between request and response kinds. Callers can match on
/// `NetworkMessage::Request` / `NetworkMessage::Response` and then further
/// match the inner enums.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Request(NetworkRequest),
    Response(NetworkResponse),
}
