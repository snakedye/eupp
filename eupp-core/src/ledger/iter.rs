use std::borrow::Cow;

use super::{BlockMetadata, Indexer, IndexerExt, Ledger};
use crate::Hash;
use crate::block::Block;

/// Iterator over the blockchain from the tip to genesis.
#[derive(Clone, Copy)]
pub struct BlockIter<'a, L: ?Sized> {
    pub current_hash: Hash,
    pub ledger: &'a L,
}

/// Iterator over the blockchain metadata from the tip to genesis.
#[derive(Clone, Copy)]
pub struct BlockMetadataIter<'a, I: ?Sized> {
    pub current_hash: Hash,
    pub indexer: &'a I,
}

impl<'a, I: Indexer + ?Sized> Iterator for BlockMetadataIter<'a, I> {
    type Item = Cow<'a, BlockMetadata>;

    fn next(&mut self) -> Option<Self::Item> {
        self.indexer
            .get_block_metadata(&self.current_hash)
            .inspect(|meta| self.current_hash = meta.prev_block_hash)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let height = self
            .indexer
            .metadata()
            .next()
            .map(|meta| meta.height as usize);
        (height.unwrap_or_default(), height)
    }
}

impl<'a, I: Indexer + ?Sized> ExactSizeIterator for BlockMetadataIter<'a, I> {
    fn len(&self) -> usize {
        self.indexer
            .metadata()
            .next()
            .map(|meta| meta.height as usize)
            .unwrap_or(0)
    }
}

impl<'a, L: Ledger + ?Sized> Iterator for BlockIter<'a, L> {
    type Item = Cow<'a, Block>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ledger
            .get_block(&self.current_hash)
            .inspect(|block| self.current_hash = block.prev_block_hash)
    }
}

impl<'a, L: Ledger + ?Sized + Indexer> ExactSizeIterator for BlockIter<'a, L> {
    fn len(&self) -> usize {
        self.ledger
            .get_last_block_metadata()
            .map(|meta| meta.height as usize)
            .unwrap_or(0)
    }
}
