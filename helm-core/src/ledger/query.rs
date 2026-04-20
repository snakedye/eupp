use serde::{Deserialize, Serialize};

use crate::{Hash, Output, OutputId, deserialize_arr, deserialize_hashes_from_hex, serialize_hashes_to_hex, serialize_to_hex};

/// A query for UTXOs on the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Query {
    /// Set of commitment hashes to include in the query.
    Addresses(
        #[serde(
            serialize_with = "serialize_hashes_to_hex",
            deserialize_with = "deserialize_hashes_from_hex"
        )]
        Vec<Hash>,
    ),
    /// Transaction ID to include in the query.
    TransactionID(
        #[serde(serialize_with = "serialize_to_hex", deserialize_with = "deserialize_arr")] Hash,
    ),
}

impl Query {
    /// Creates a new empty `Query` with no starting hash and no addresses.
    pub fn new() -> Query {
        Self::Addresses(Vec::new())
    }
}

/// An entry representing an output on the blockchain, including its unique ID and the output details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry {
    pub id: OutputId,
    pub output: Output,
}

impl From<(OutputId, Output)> for OutputEntry {
    fn from((id, output): (OutputId, Output)) -> Self {
        Self { id, output }
    }
}
