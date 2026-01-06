mod in_mem;

pub use in_mem::{FullInMemoryLedger, InMemoryIndexer};

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

    /// The output id of the lead utxo
    pub lead_utxo: OutputId,
}

/// An Indexer provides optimized views of the blockchain state.
/// This includes the UTXO set and block metadata needed for validation.
pub trait Indexer {
    /// Applies a block to the indexer's state (UTXOs, Metadata, etc.).
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError>;

    /// Retrieves metadata for a block identified by its hash.
    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata>;

    /// Fetches an unspent transaction output (UTXO) by its identifier.
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output>;

    /// Fetches the block hash of a UTXO by its identifier.
    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash>;

    /// Retrieves metadata for the most recently added block.
    fn get_last_block_metadata(&self) -> Option<BlockMetadata>;
}

/// A Ledger represents the authoritative archival store of blocks.
/// It extends Indexer to provide access to full block data.
pub trait Ledger: Indexer {
    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: &Hash) -> Option<Block>;

    /// Returns an iterator over blocks starting from the tip to oldest.
    fn get_blocks(&self) -> impl Iterator<Item = Block>;

    /// Returns an iterator over blocks starting from a given hash.
    ///
    /// Like `get_blocks()`, but starts from the given hash.
    fn get_blocks_from(&self, start_hash: &Hash) -> impl Iterator<Item = Block>;
}
