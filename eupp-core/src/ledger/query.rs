use serde::{Deserialize, Serialize};

use crate::Hash;

/// A query for UTXOs on the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Query {
    /// Set of commitment hashes to include in the query.
    Addresses(Vec<Hash>),
    /// Transaction ID to include in the query.
    TransactionID(Hash),
}

impl Query {
    /// Creates a new empty `Query` with no starting hash and no addresses.
    pub fn new() -> Query {
        Self::Addresses(Vec::new())
    }
}
