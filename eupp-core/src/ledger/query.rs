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
}

impl Query {
    pub fn new() -> Query {
        Self {
            to: None,
            addresses: HashSet::new(),
        }
    }
    pub fn with_address(mut self, address: Hash) -> Self {
        self.addresses.insert(address);
        self
    }
    pub fn from(&self) -> Option<&Hash> {
        self.to.as_ref()
    }
    pub fn addresses(&self) -> &HashSet<Hash> {
        &self.addresses
    }
}
