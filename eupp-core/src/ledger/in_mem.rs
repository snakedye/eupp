use std::collections::{BTreeMap, HashMap};

use crate::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId, TransactionError},
};

#[derive(Clone)]
pub(crate) struct UtxoEntry {
    pub block_hash: Hash,
    pub output: Output,
}

use super::{BlockMetadata, Indexer, Ledger};

/// Represents an in-memory implementation of a blockchain `Indexer`.
pub struct InMemoryIndexer {
    /// Block metadata index
    pub(crate) block_index: HashMap<Hash, BlockMetadata>,

    // The complete set of unspent transaction outputs (UTXOs)
    pub(crate) utxo_set: BTreeMap<OutputId, UtxoEntry>,

    /// Points to the block with the Maximum Accumulated Supply (MAS)
    pub(crate) tip: Hash,
}

/// Represents an in-memory implementation of a blockchain `Ledger`.
pub struct FullInMemoryLedger {
    indexer: InMemoryIndexer,
    blocks: HashMap<Hash, Block>,
    // Map height to hash for the get_blocks_from implementation
    height_to_hash: BTreeMap<u32, Hash>,
}

impl InMemoryIndexer {
    pub fn new() -> Self {
        InMemoryIndexer {
            block_index: HashMap::new(),
            utxo_set: BTreeMap::new(),
            tip: Hash::default(),
        }
    }

    fn apply_block_to_utxo_set(&mut self, block: &Block) -> Result<(), BlockError> {
        let block_hash = block.header().hash();
        for tx in &block.transactions {
            // Remove spent UTXOs
            for input in &tx.inputs {
                let output_id = input.output_id;
                if self.utxo_set.remove(&output_id).is_none() {
                    return Err(BlockError::TransactionError(
                        TransactionError::InvalidOutput(output_id),
                    ));
                }
            }
            // Add new UTXOs
            let tx_id = tx.hash();
            for (i, output) in tx.outputs.iter().enumerate() {
                self.utxo_set.insert(
                    OutputId::new(tx_id, i as u8),
                    UtxoEntry {
                        block_hash,
                        output: output.clone(),
                    },
                );
            }
        }
        Ok(())
    }
}

impl Indexer for InMemoryIndexer {
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
        // Initialize variables
        let height;
        let total_supply;
        let prev_locked_supply = self
            .block_index
            .get(&block.prev_block_hash)
            .map(|meta| meta.locked_supply)
            .unwrap_or_default();
        let locked_supply = block
            .lead_utxo()
            .map(|utxo| utxo.amount)
            .unwrap_or_default();

        // Get the previous block metadata
        if !self.block_index.is_empty() {
            let prev_meta = self.block_index.get(&block.prev_block_hash).ok_or(
                BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&block.prev_block_hash)
                )),
            )?;

            let reward = prev_locked_supply - locked_supply;
            total_supply = prev_meta.available_supply + reward;

            // Update height
            height = prev_meta.height + 1;
        // We make an exception for the genesis block, which has no previous block.
        } else {
            height = 0;
            total_supply = 0;
        }

        let metadata = BlockMetadata {
            hash: block.header().hash(),
            prev_block_hash: block.prev_block_hash,
            available_supply: total_supply,
            lead_utxo: OutputId::new(block.transactions[0].hash(), 0),
            locked_supply,
            height,
        };

        // Verify the block
        block.verify(self)?;

        // Update the UTXO Set (Spend inputs, add new outputs)
        self.apply_block_to_utxo_set(&block)?;

        // Update Tip if this chain is now heavier
        if total_supply
            >= self
                .block_index
                .get(&self.tip)
                .map(|meta| meta.available_supply)
                .unwrap_or(0)
        {
            // Update the tip to the new metadata hash.
            self.tip = metadata.hash;
        }

        self.block_index.insert(metadata.hash, metadata);
        Ok(())
    }

    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata> {
        self.block_index.get(hash).cloned()
    }

    fn get_utxo(&self, output_id: &OutputId) -> Option<Output> {
        self.utxo_set
            .get(output_id)
            .map(|entry| entry.output.clone())
    }

    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash> {
        self.utxo_set.get(output_id).map(|entry| entry.block_hash)
    }

    fn get_last_block_metadata(&self) -> Option<BlockMetadata> {
        self.block_index.get(&self.tip).cloned()
    }
}

impl FullInMemoryLedger {
    pub fn new() -> Self {
        FullInMemoryLedger {
            indexer: InMemoryIndexer::new(),
            blocks: HashMap::new(),
            height_to_hash: BTreeMap::new(),
        }
    }
}

impl Indexer for FullInMemoryLedger {
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
        self.indexer.add_block(block)?;
        let hash = block.header().hash();
        self.blocks.insert(hash, block.clone());

        if let Some(meta) = self.indexer.get_block_metadata(&hash) {
            self.height_to_hash.insert(meta.height, hash);
        }
        Ok(())
    }

    fn get_block_metadata(&self, hash: &Hash) -> Option<BlockMetadata> {
        self.indexer.get_block_metadata(hash)
    }

    fn get_utxo(&self, output_id: &OutputId) -> Option<Output> {
        self.indexer.get_utxo(output_id)
    }

    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash> {
        self.indexer.get_utxo_block_hash(output_id)
    }

    fn get_last_block_metadata(&self) -> Option<BlockMetadata> {
        self.indexer.get_last_block_metadata()
    }
}

impl Ledger for FullInMemoryLedger {
    fn get_block(&self, hash: &Hash) -> Option<Block> {
        self.blocks.get(hash).cloned()
    }

    fn get_blocks(&self) -> impl Iterator<Item = Block> {
        self.height_to_hash
            .values()
            .filter_map(move |hash| self.get_block(hash))
    }
}
