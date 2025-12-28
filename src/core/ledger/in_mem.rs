use std::collections::{BTreeMap, HashMap};

use blake2::Blake2s256;

use crate::core::{
    Hash,
    block::{Block, BlockError},
    transaction::{Output, OutputId, TransactionError},
};

use super::{BlockMetadata, Ledger};

pub struct InMemoryLedger {
    /// Block metadata index
    pub block_index: HashMap<Hash, BlockMetadata>,

    // The complete set of unspent transaction outputs (UTXOs)
    pub utxo_set: BTreeMap<OutputId, Output>,

    /// Points to the block with the Maximum Accumulated Supply (MAS)
    ///
    /// This is the main branch of the blockchain.
    pub tip: Hash,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        InMemoryLedger {
            block_index: HashMap::new(),
            utxo_set: BTreeMap::new(),
            tip: Hash::default(),
        }
    }

    fn apply_block_to_utxo_set(&mut self, block: &Block) -> Result<(), BlockError> {
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
            let tx_id = tx.hash::<Blake2s256>();
            for (i, output) in tx.outputs.iter().enumerate() {
                self.utxo_set
                    .insert(OutputId::new(tx_id, i), output.clone());
            }
        }
        Ok(())
    }
}

impl Ledger for InMemoryLedger {
    fn add_block(&mut self, block: Block) -> Result<(), BlockError> {
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
        if self.block_index.len() > 1 {
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
            hash: block.header().hash::<Blake2s256>(),
            prev_block_hash: block.prev_block_hash,
            available_supply: total_supply,
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
        self.utxo_set.get(output_id).copied()
    }

    fn get_last_block_metadata(&self) -> Option<BlockMetadata> {
        self.block_index.get(&self.tip).cloned()
    }
}
