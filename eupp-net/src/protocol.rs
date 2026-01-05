use eupp_core::block::Block;
use eupp_core::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// Requests sent on the network.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkRequest {
    /// Broadcast a transaction to peers.
    Transaction(Transaction),

    /// Ask peers for their current maximum available supply (handshake / chain tip summary).
    GetMaxSupply,

    /// Request blocks starting from the given height (inclusive).
    GetBlocks(u32), // from height
}

/// Responses sent on the network.
///
/// Keeping responses separate makes it clearer which messages are replies
/// and which are initiating requests.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkResponse {
    /// Reply with the maximum available supply observed by the peer.
    MaxSupply(u32),

    /// Reply with a single block and its height (preferred for streaming/ordered delivery).
    /// Receivers should buffer out-of-order `Block` messages and attempt to apply any
    /// contiguous sequence starting at the expected height when possible.
    Block(u32, Block),
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
