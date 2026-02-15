use serde::{Deserialize, Serialize};

use crate::Hash;
use std::collections::HashSet;

/// A query for UTXOs on the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// Optional hash indicating the starting point for the query.
    pub to: Option<Hash>,
    /// Set of commitment hashes to include in the query.
    pub addresses: HashSet<Hash>,
    /// The transaction ID
    pub tx_id: Option<Hash>,
}

impl Query {
    /// Creates a new empty `Query` with no starting hash and no addresses.
    pub fn new() -> Query {
        Self {
            to: None,
            tx_id: None,
            addresses: HashSet::new(),
        }
    }

    /// Adds an address (commitment hash) to the query.
    pub fn with_address(mut self, address: Hash) -> Self {
        self.addresses.insert(address);
        self
    }

    /// Returns an optional reference to the starting hash for the query, if set.
    pub fn from(&self) -> Option<&Hash> {
        self.to.as_ref()
    }

    /// Returns a reference to the set of addresses (commitment hashes) in the query.
    pub fn addresses(&self) -> &HashSet<Hash> {
        &self.addresses
    }
}
