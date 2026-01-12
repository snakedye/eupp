mod in_mem;
mod query;

pub use in_mem::{FullInMemoryLedger, InMemoryIndexer};
pub use query::Query;

use crate::block::BlockHeader;

use super::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId},
};

#[derive(Debug, Clone, PartialEq)]
/// Represents metadata for a block in the ledger.
pub struct BlockMetadata {
    /// The unique identifier of this block
    pub hash: Hash,

    /// Pointer to the parent for traversing the tree
    pub prev_block_hash: Hash,

    /// The vertical position in the chain (Genesis = 0)
    pub height: u32,

    /// The MAS Metric: Sum of all rewards from Genesis to this block.
    pub available_supply: u64,

    /// The MAS Metric: Sum of all locked rewards from Genesis to this block.
    pub locked_supply: u64,

    /// The output id of the lead utxo
    pub lead_utxo: OutputId,

    /// The merkle root of the transaction tree.
    pub merkle_root: Hash,
}

#[derive(Clone, Copy)]
/// Iterator over the blockchain from the tip to genesis.
pub struct BlockIter<'a, L: ?Sized> {
    current_hash: Hash,
    ledger: &'a L,
}

#[derive(Clone, Copy)]
/// Iterator over the blockchain metadata from the tip to genesis.
pub struct BlockMetadataIter<'a, I: ?Sized> {
    current_hash: Hash,
    indexer: &'a I,
}

impl BlockMetadata {
    /// Return a `BlockHeader`.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: 0,
            prev_block_hash: self.prev_block_hash,
            merkle_root: self.merkle_root,
        }
    }
}

impl<'a, I: Indexer> Iterator for BlockMetadataIter<'a, I> {
    type Item = BlockMetadata;

    fn next(&mut self) -> Option<Self::Item> {
        self.indexer
            .get_block_metadata(&self.current_hash)
            .inspect(|block| self.current_hash = block.prev_block_hash)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let height = self
            .indexer
            .metadata_iter()
            .next()
            .map(|meta| meta.height as usize);
        (height.unwrap_or_default(), height)
    }
}

/// An Indexer provides optimized views of the blockchain state.
/// This includes the UTXO set and block metadata needed for validation.
pub trait Indexer {
    /// Applies a block to the indexer's state (UTXOs, Metadata, etc.).
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError>;

    /// Retrieves metadata for a block identified by its hash.
    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata>;

    /// Checks if a transaction output is spent.
    fn is_utxo_spent(&self, output_id: &OutputId) -> bool {
        self.get_utxo(output_id).is_none()
    }

    /// Fetches an unspent transaction output (UTXO) by its identifier.
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output>;

    fn get_utxos(&self, query: &Query) -> Vec<(OutputId, Output)>;

    /// Fetches the block hash of a UTXO by its identifier.
    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash>;

    /// Retrieves metadata for the most recently added block.
    fn get_last_block_metadata(&self) -> Option<BlockMetadata>;

    /// Retrieves the hash of the block containing the given transaction.
    fn get_transaction_block_hash(
        &self,
        tx_hash: &super::transaction::TransactionHash,
    ) -> Option<Hash> {
        self.get_utxo_block_hash(&OutputId::new(*tx_hash, 0))
    }

    fn metadata_iter(&self) -> BlockMetadataIter<'_, Self> {
        BlockMetadataIter {
            current_hash: self
                .get_last_block_metadata()
                .map(|meta| meta.hash)
                .unwrap_or_default(),
            indexer: self,
        }
    }

    fn metadata_iter_from(&self, hash: &Hash) -> BlockMetadataIter<'_, Self> {
        BlockMetadataIter {
            current_hash: *hash,
            indexer: self,
        }
    }
}

impl<'a, L: Ledger> Iterator for BlockIter<'a, L> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        self.ledger
            .get_block(&self.current_hash)
            .inspect(|block| self.current_hash = block.prev_block_hash)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let height = self
            .ledger
            .metadata_iter()
            .next()
            .map(|meta| meta.height as usize);
        (height.unwrap_or_default(), height)
    }
}

/// A Ledger represents the authoritative archival store of blocks.
/// It extends Indexer to provide access to full block data.
pub trait Ledger: Indexer {
    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: &Hash) -> Option<Block>;

    /// Returns an iterator over blocks starting from the tip to oldest.
    fn block_iter(&self) -> BlockIter<Self> {
        BlockIter {
            current_hash: self
                .get_last_block_metadata()
                .map(|meta| meta.hash)
                .unwrap_or_default(),
            ledger: self,
        }
    }

    /// Returns an iterator over blocks starting from a given hash.
    fn block_iter_from(&self, hash: &Hash) -> BlockIter<Self> {
        BlockIter {
            current_hash: *hash,
            ledger: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockIterator {
        blocks: HashMap<Hash, Block>,
        metadata: HashMap<Hash, BlockMetadata>,
    }

    impl Indexer for MockIterator {
        fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
            let hash = block.header().hash();
            let lead_utxo = OutputId::new([0; 32], 0);
            self.blocks.insert(hash, block.clone());
            self.metadata.insert(
                hash,
                BlockMetadata {
                    hash,
                    prev_block_hash: block.prev_block_hash,
                    merkle_root: [0; 32],
                    height: 0,
                    available_supply: 0,
                    locked_supply: 0,
                    lead_utxo,
                },
            );
            Ok(())
        }

        fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata> {
            self.metadata.get(hash).cloned()
        }

        fn get_utxo(&self, _output_id: &OutputId) -> Option<Output> {
            None
        }

        fn get_utxos(&self, _query: &Query) -> Vec<(OutputId, Output)> {
            vec![]
        }

        fn get_utxo_block_hash(&self, _output_id: &OutputId) -> Option<Hash> {
            None
        }

        fn get_last_block_metadata(&self) -> Option<BlockMetadata> {
            self.metadata.values().last().cloned()
        }
    }

    impl Ledger for MockIterator {
        fn get_block(&self, hash: &Hash) -> Option<Block> {
            self.blocks.get(hash).cloned()
        }
    }

    #[test]
    fn test_block_iter() {
        let mut mock = MockIterator::default();
        let genesis_hash = Hash::default();
        let block = Block::new(0, genesis_hash);
        let block_hash = block.header().hash();
        mock.add_block(&block).unwrap();

        let mut iter = mock.block_iter_from(&block_hash);
        assert_eq!(iter.next().unwrap().header().hash(), block_hash);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_block_metadata_iter() {
        let mut mock = MockIterator::default();
        let block_hash = [1; 32];
        let metadata = BlockMetadata {
            hash: block_hash,
            prev_block_hash: [0; 32],
            height: 0,
            available_supply: 0,
            merkle_root: [0; 32],
            locked_supply: 0,
            lead_utxo: OutputId::new([0; 32], 0),
        };
        mock.metadata.insert(block_hash, metadata);

        let mut iter = mock.metadata_iter_from(&block_hash);
        assert_eq!(iter.next().unwrap().hash, block_hash);
        assert_eq!(iter.next(), None);
    }
}
