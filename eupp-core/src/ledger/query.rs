use serde::{Deserialize, Serialize};

use crate::Hash;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    pub addresses: HashSet<Hash>,
}

impl Query {
    pub fn new() -> Query {
        Self {
            addresses: HashSet::new(),
        }
    }
    pub fn with_address(mut self, address: Hash) -> Self {
        self.addresses.insert(address);
        self
    }
}
