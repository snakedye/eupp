/*! This module provides the foundational structures and traits for managing and interacting
with a blockchain ledger. It includes definitions for block metadata, iterators for traversing
the blockchain, and traits for indexing and accessing blockchain data.

# Key Components

- `BlockMetadata`: Represents metadata for a block in the ledger, including its hash, height,
  cumulative work, and other properties.
- `BlockIter` and `BlockMetadataIter`: Iterators for traversing blocks and block metadata
  from the tip of the chain to the genesis block.
- `Indexer` and `Ledger` Traits: Define the interfaces for indexing and accessing blockchain
  data, including UTXOs, block metadata, and full block data.

# Traits

- `Indexer`: Provides optimized views of the blockchain state, such as the UTXO set and block
  metadata. It includes methods for adding blocks, querying UTXOs, and retrieving block metadata.
- `Ledger`: Extends the `Indexer` trait to include access to full block data and iterators
  over blocks.

# Iterators

- `BlockIter`: Iterates over full blocks in the blockchain, starting from the tip.
- `BlockMetadataIter`: Iterates over block metadata, starting from the tip.

This module is designed to be extensible and provides the building blocks for implementing
custom blockchain indexing and ledger systems.
*/

mod in_mem;
mod iter;
mod query;
pub use iter::{BlockIter, BlockMetadataIter};

use std::borrow::Cow;

use ethnum::U256;
pub use in_mem::InMemoryIndexer;
pub use query::Query;
use serde::{Deserialize, Serialize};

use crate::block::BlockHeader;

use super::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Represents metadata for a block in the ledger.
pub struct BlockMetadata {
    /// The block's version
    pub version: u8,

    /// The unique identifier of this block
    pub hash: Hash,

    /// Pointer to the parent for traversing the tree
    pub prev_block_hash: Hash,

    /// The vertical position in the chain (Genesis = 0)
    pub height: u32,

    /// The MAS Metric: Sum of all rewards from Genesis to this block.
    pub available_supply: u64,

    /// The `OutputId` of the lead output
    pub lead_output: OutputId,

    /// The cumulative work on this blockchain.
    pub cumulative_work: U256,

    /// The merkle root of the transaction tree.
    pub merkle_root: Hash,

    /// The position of the block in the ledger.
    pub cursor: Option<Cursor>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Cursor {
    /// The position of the block in the ledger.
    pub pos: usize,
    /// The length of the block.
    pub len: usize,
}

impl BlockMetadata {
    /// Return a `BlockHeader`.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: self.version,
            prev_block_hash: self.prev_block_hash,
            merkle_root: self.merkle_root,
        }
    }
    /// Return the locked supply on the blockchain.
    pub fn locked_supply(&self, indexer: &impl Indexer) -> u64 {
        indexer
            .get_utxo(&self.lead_output)
            .map_or(0, |utxo| utxo.amount)
    }
}

/// An Indexer provides optimized views of the blockchain state.
/// This includes the UTXO set and block metadata needed for validation.
pub trait Indexer {
    /// Applies a block to the indexer's state (UTXOs, Metadata, etc.).
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError>;

    /// Retrieves metadata for a block identified by its hash.
    fn get_block_metadata(&'_ self, hash: &Hash) -> Option<Cow<'_, BlockMetadata>>;

    /// Retrieves the hash of block at the top of the blockchain.
    fn get_tip(&'_ self) -> Option<Hash>;

    /// Checks if a transaction output is spent.
    fn is_utxo_spent(&self, output_id: &OutputId) -> bool {
        self.get_utxo(output_id).is_none()
    }

    /// Fetches an unspent transaction output (UTXO) by its identifier.
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output>;

    /// Returns an iterator over all UTXOs matching the given query.
    fn query_utxos(&self, query: &Query) -> Vec<(OutputId, Output)>;

    /// Fetches the block hash of a UTXO by its identifier.
    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash>;

    /// Retrieves metadata for the most recently added block.
    fn get_last_block_metadata(&'_ self) -> Option<Cow<'_, BlockMetadata>> {
        self.get_tip()
            .and_then(|hash| self.get_block_metadata(&hash))
    }

    /// Retrieves the hash of the block containing the given transaction.
    fn get_transaction_block_hash(
        &self,
        tx_hash: &super::transaction::TransactionHash,
    ) -> Option<Hash> {
        self.get_utxo_block_hash(&OutputId::new(*tx_hash, 0))
    }
}

pub trait IndexerExt: Indexer {
    /// Returns an iterator over the block metadata starting from the most recently added block
    /// and traversing back to the genesis block.
    fn metadata(&self) -> BlockMetadataIter<'_, Self> {
        BlockMetadataIter {
            current_hash: self.get_tip().unwrap_or_default(),
            indexer: self,
        }
    }

    /// Returns an iterator over the block metadata starting from a specific block hash
    /// and traversing back to the genesis block.
    fn metadata_from(&self, hash: &Hash) -> BlockMetadataIter<'_, Self> {
        BlockMetadataIter {
            current_hash: *hash,
            indexer: self,
        }
    }
}

impl<T: Indexer + ?Sized> IndexerExt for T {}

// Implementation moved to `iter.rs`

/// A Ledger represents the authoritative archival store of blocks.
/// It extends Indexer to provide access to full block data.
pub trait Ledger: Indexer {
    /// Retrieves a full block by its hash.
    fn get_block(&'_ self, hash: &Hash) -> Option<Cow<'_, Block>>;
}

/// A trait for converting an object into a `Ledger`.
pub trait LedgerView {
    /// The associated type representing a `Ledger` reference.
    type Ledger<'a>: Ledger + 'a
    where
        Self: 'a;

    /// Converts the current object into a `Ledger`.
    fn as_ledger<'a>(&'a self) -> Option<&'a Self::Ledger<'a>> {
        None
    }
}

pub trait LedgerExt: Ledger {
    /// Returns an iterator over blocks starting from the tip to oldest.
    fn blocks(&'_ self) -> BlockIter<'_, Self>
    where
        Self: Indexer,
    {
        BlockIter {
            current_hash: self.get_tip().unwrap_or_default(),
            ledger: self,
        }
    }

    /// Returns an iterator over blocks starting from a given hash.
    fn blocks_from(&'_ self, hash: &Hash) -> BlockIter<'_, Self> {
        BlockIter {
            current_hash: *hash,
            ledger: self,
        }
    }
}

impl<T: Ledger + ?Sized> LedgerExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockLedger {
        blocks: HashMap<Hash, Block>,
        metadata: HashMap<Hash, BlockMetadata>,
    }

    impl Indexer for MockLedger {
        fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
            let hash = block.header().hash();
            let lead_output = OutputId::new([0; 32], 0);
            self.blocks.insert(hash, block.clone());
            self.metadata.insert(
                hash,
                BlockMetadata {
                    version: block.version,
                    hash,
                    prev_block_hash: block.prev_block_hash,
                    merkle_root: [0; 32],
                    height: 0,
                    cumulative_work: U256::MIN,
                    available_supply: 0,
                    cursor: None,
                    lead_output,
                },
            );
            Ok(())
        }

        fn get_block_metadata(&'_ self, hash: &Hash) -> Option<Cow<'_, BlockMetadata>> {
            self.metadata.get(hash).map(Cow::Borrowed)
        }

        fn get_utxo(&self, _output_id: &OutputId) -> Option<Output> {
            None
        }

        fn query_utxos(&self, _query: &Query) -> Vec<(OutputId, Output)> {
            unimplemented!()
        }

        fn get_utxo_block_hash(&self, _output_id: &OutputId) -> Option<Hash> {
            None
        }

        fn get_tip(&'_ self) -> Option<Hash> {
            None
        }

        fn get_last_block_metadata(&'_ self) -> Option<Cow<'_, BlockMetadata>> {
            self.metadata.values().next().map(Cow::Borrowed)
        }
    }

    impl Ledger for MockLedger {
        fn get_block(&'_ self, hash: &Hash) -> Option<Cow<'_, Block>> {
            self.blocks.get(hash).map(Cow::Borrowed)
        }
    }

    #[test]
    fn test_block_iter() {
        let mut mock = MockLedger::default();
        let genesis_hash = Hash::default();
        let block = Block::new(0, genesis_hash);
        let block_hash = block.header().hash();
        mock.add_block(&block).unwrap();

        let mut iter = mock.blocks_from(&block_hash);
        assert_eq!(iter.next().unwrap().header().hash(), block_hash);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_block_metadata_iter() {
        let mut mock = MockLedger::default();
        let block_hash = [1; 32];
        let metadata = BlockMetadata {
            version: 0,
            hash: block_hash,
            prev_block_hash: [0; 32],
            height: 0,
            available_supply: 0,
            merkle_root: [0; 32],
            cumulative_work: U256::MIN,
            lead_output: OutputId::new([0; 32], 0),
            cursor: None,
        };
        mock.metadata.insert(block_hash, metadata);

        let mut iter = mock.metadata_from(&block_hash);
        assert_eq!(iter.next().unwrap().hash, block_hash);
        assert_eq!(iter.next(), None);
    }
}
