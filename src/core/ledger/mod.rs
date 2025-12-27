mod in_mem;

pub use self::in_mem::InMemoryLedger;
use super::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId},
};

#[derive(Debug, Clone)]
/// Represents metadata for a block in the ledger.
pub struct BlockMetadata {
    /// The unique identifier of this block
    pub hash: Hash,

    /// Pointer to the parent for traversing the tree
    pub prev_block_hash: Hash,

    /// The vertical position in the chain (Genesis = 0)
    pub height: u32,

    /// The MAS Metric: Sum of all rewards from Genesis to this block.
    pub available_supply: u32,

    /// The MAS Metric: Sum of all locked rewards from Genesis to this block.
    pub locked_supply: u32,
}

pub trait Ledger {
    /// Adds a new block to the ledger.
    /// Returns an error if the block is invalid or cannot be added.
    fn add_block(&mut self, block: Block) -> Result<(), BlockError>;

    /// Retrieves metadata for a block identified by its hash.
    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata>;

    /// Fetches an unspent transaction output (UTXO) by its identifier.
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output>;

    /// Retrieves metadata for the most recently added block in the ledger.
    fn get_last_block_metadata(&self) -> Option<BlockMetadata>;

    /// Retrieves all unspent transaction outputs (UTXOs) associated with a transaction.
    fn get_tx_utxos(&self, tx_id: &Hash) -> impl Iterator<Item = Output>;
}
