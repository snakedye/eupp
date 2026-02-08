use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
};

use ethnum::U256;

use crate::{
    Hash,
    block::{Block, BlockError},
    ledger::{IndexerExt, LedgerView},
    mask_difficulty,
    transaction::{Output, OutputId, TransactionError},
};

#[derive(Clone)]
pub(crate) struct UtxoEntry {
    pub block_hash: Hash,
    pub output: Output,
}

use super::{BlockMetadata, Indexer, Ledger};

type BlockMap = HashMap<Hash, Block>;

/// Represents an in-memory implementation of a blockchain `Indexer`.
pub struct InMemoryIndexer<T = ()> {
    /// Block metadata index
    block_index: HashMap<Hash, BlockMetadata>,

    // The complete set of unspent transaction outputs (UTXOs)
    utxo_set: BTreeMap<OutputId, UtxoEntry>,

    /// Points to the block with the Maximum Accumulated Supply (MAS)
    tip: Hash,

    blocks: T,
}

impl Default for InMemoryIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryIndexer {
    pub fn new() -> Self {
        InMemoryIndexer {
            block_index: HashMap::new(),
            utxo_set: BTreeMap::new(),
            tip: Hash::default(),
            blocks: (),
        }
    }
}

impl<T: 'static> InMemoryIndexer<T> {
    pub fn to_ledger(self) -> InMemoryIndexer<BlockMap> {
        InMemoryIndexer {
            block_index: self.block_index,
            utxo_set: self.utxo_set,
            tip: self.tip,
            blocks: BlockMap::new(),
        }
    }

    fn apply_block_to_utxo_set(
        &mut self,
        block: &Block,
        metadata: &BlockMetadata,
    ) -> Result<(), BlockError> {
        let block_hash = metadata.hash;

        // Check for double spending within the block
        let mut spent_utxos = HashSet::new();
        for input in block
            .transactions
            .iter()
            .flat_map(|txs| txs.inputs.iter())
            // We skip the coinbase transaction's first input
            .skip(1)
        {
            let output_id = input.output_id;
            if spent_utxos.contains(&output_id) {
                return Err(BlockError::TransactionError(
                    TransactionError::InvalidOutput(output_id),
                ));
            }
            spent_utxos.insert(output_id);
        }
        // Remove spent UTXOs
        for output_id in spent_utxos.iter() {
            if self.utxo_set.remove(output_id).is_none() {
                return Err(BlockError::TransactionError(
                    TransactionError::InvalidOutput(*output_id),
                ));
            }
        }

        // Add new UTXOs
        for (i, tx_id, output) in block.transactions.iter().flat_map(|tx| {
            let tx_id = tx.hash();
            tx.outputs
                .iter()
                .enumerate()
                .map(move |(i, output)| (i, tx_id, output))
        }) {
            self.utxo_set.insert(
                OutputId::new(tx_id, i as u8),
                UtxoEntry {
                    block_hash,
                    output: output.clone(),
                },
            );
        }
        Ok(())
    }

    /// Removes all block metadata and UTXOs from the indexer that are descendants of `root`.
    ///
    /// This is typically used to "uproot" a forked branch from the canonical chain, cleaning up
    /// any blocks and UTXOs that are no longer part of the main chain after a reorganization.
    fn uproot(&mut self, tip: &Hash, root: &Hash) {
        let blocks = self
            .metadata_from(tip)
            .map(|meta| meta.hash)
            .take_while(|hash| hash != root)
            .collect::<HashSet<_>>();

        for block in &blocks {
            self.block_index.remove(block);
        }

        self.utxo_set
            .retain(|_, entry| blocks.contains(&entry.block_hash));
    }

    fn block_map(&mut self) -> Option<&mut BlockMap>
    where
        T: Any,
    {
        let blocks = &mut self.blocks as &mut dyn Any;
        blocks.downcast_mut::<BlockMap>()
    }
}

impl<T: 'static> Indexer for InMemoryIndexer<T> {
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
        // Initialize variables
        let height;
        let available_supply;
        let prev_block = self.block_index.get(&block.prev_block_hash);
        let prev_locked_supply = prev_block.map_or(0, |meta| meta.locked_supply(self));
        let prev_cumulative_work = prev_block.map_or(U256::MIN, |meta| meta.cumulative_work);
        let locked_supply = block.lead_output().map_or(0, |utxo| utxo.amount);
        let block_difficulty = prev_block
            .and_then(|meta| self.get_output(&meta.lead_output))
            .and_then(|utxo| utxo.mask().copied())
            .as_ref()
            .map_or(0, mask_difficulty);
        let block_work = U256::new(1) << block_difficulty as usize;

        // Get the previous block metadata
        if !self.block_index.is_empty() {
            let prev_block = prev_block.ok_or(BlockError::InvalidBlockHash(format!(
                "Previous block hash not found: {}",
                hex::encode(&block.prev_block_hash)
            )))?;

            let reward = prev_locked_supply - locked_supply;
            available_supply = prev_block.available_supply + reward;

            // Check that the lead output belongs to the previous block
            block
                .prev_lead_output()
                .filter(|output_id| *output_id == &prev_block.lead_output)
                .ok_or_else(|| {
                    BlockError::TransactionError(TransactionError::InvalidOutput(
                        prev_block.lead_output,
                    ))
                })?;

            // Update height
            height = prev_block.height + 1;
        // We make an exception for the genesis block, which has no previous block.
        } else {
            height = 0;
            available_supply = 0;
        }

        let header = block.header();
        let metadata = BlockMetadata {
            version: header.version,
            hash: header.hash(),
            prev_block_hash: header.prev_block_hash,
            lead_output: OutputId::new(block.transactions[0].hash(), 0),
            merkle_root: header.merkle_root,
            cumulative_work: prev_cumulative_work + block_work,
            cursor: None,
            available_supply,
            height,
        };

        // Verify the block
        block.verify(self)?;

        // Update the UTXO Set (Spend inputs, add new outputs)
        self.apply_block_to_utxo_set(&block, &metadata)?;

        let current_prev_metadata = self.block_index.get(&self.tip);

        // Update Tip if this chain is now heavier or if there's no block for the tip
        if self.block_index.get(&self.tip).is_none()
            || metadata.cumulative_work
                > current_prev_metadata
                    .map(|meta| meta.cumulative_work)
                    .unwrap_or_default()
        {
            if let Some(root) = current_prev_metadata
                .map(|meta| meta.prev_block_hash)
                .filter(|hash| block.prev_block_hash.eq(hash))
            {
                self.uproot(&self.tip.clone(), &root);
            }
            // Update the tip to the new metadata hash.
            self.tip = metadata.hash;
        }

        if let Some(block_map) = self.block_map() {
            block_map.insert(metadata.hash, block.clone());
        }
        self.block_index.insert(metadata.hash, metadata);

        Ok(())
    }

    fn get_block_metadata(&'_ self, hash: &Hash) -> Option<Cow<'_, BlockMetadata>> {
        self.block_index.get(hash).map(Cow::Borrowed)
    }

    fn get_output(&self, output_id: &OutputId) -> Option<Output> {
        self.utxo_set
            .get(output_id)
            .map(|entry| entry.output.clone())
    }

    fn query_outputs<'a>(&'a self, query: &'a super::Query) -> Vec<(OutputId, Output)> {
        // This is to only fetch UTXOs in the canonical branch.
        let blocks: HashSet<_> = self
            .metadata()
            .map(|meta| meta.hash)
            .take_while(|hash| Some(hash) != query.to.as_ref())
            .collect();
        self.utxo_set
            .iter()
            .filter(move |(_, entry)| {
                let addresses = query.addresses();
                addresses.contains(&entry.output.commitment) && blocks.contains(&entry.block_hash)
            })
            .map(|(id, entry)| (*id, entry.output))
            .collect()
    }

    fn get_tip(&'_ self) -> Option<Hash> {
        Some(self.tip)
    }

    fn get_block_from_output(&self, output_id: &OutputId) -> Option<Hash> {
        self.utxo_set.get(output_id).map(|entry| entry.block_hash)
    }
}

impl<T: 'static> LedgerView for InMemoryIndexer<T> {
    type Ledger<'a>
        = InMemoryIndexer<BlockMap>
    where
        Self: 'a;
    fn as_ledger<'a>(&'a self) -> Option<&'a Self::Ledger<'a>> {
        (self as &dyn Any).downcast_ref()
    }
}

impl Ledger for InMemoryIndexer<BlockMap> {
    fn get_block(&'_ self, hash: &Hash) -> Option<Cow<'_, Block>> {
        self.blocks.get(hash).map(Cow::Borrowed)
    }
}
