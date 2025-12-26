mod in_mem;

pub use self::in_mem::InMemoryLedger;
use super::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId},
};

#[derive(Debug, Clone)]
pub struct BlockMetadata {
    /// The unique identifier of this block
    pub hash: Hash,

    /// Pointer to the parent for traversing the tree
    pub prev_block_hash: Hash,

    /// The vertical position in the chain (Genesis = 0)
    pub height: u64,

    /// The MAS Metric: Sum of all rewards from Genesis to this block.
    pub available_supply: u64,

    /// The MAS Metric: Sum of all locked rewards from Genesis to this block.
    pub locked_supply: u64,
}

pub trait Ledger {
    fn add_block(&mut self, block: Block) -> Result<(), BlockError>;
    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata>;
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output>;
    fn get_last_block_metadata(&self) -> Option<BlockMetadata>;
}
