use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
};

use u256::U256;

use crate::{
    Hash,
    block::{Block, BlockError},
    mask_difficulty,
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
    block_index: HashMap<Hash, BlockMetadata>,

    // The complete set of unspent transaction outputs (UTXOs)
    utxo_set: BTreeMap<OutputId, UtxoEntry>,

    /// Points to the block with the Maximum Accumulated Supply (MAS)
    tip: Hash,
}

/// Represents an in-memory implementation of a blockchain `Ledger`.
pub struct FullInMemoryLedger {
    indexer: InMemoryIndexer,
    blocks: HashMap<Hash, Block>,
}

impl InMemoryIndexer {
    pub fn new() -> Self {
        InMemoryIndexer {
            block_index: HashMap::new(),
            utxo_set: BTreeMap::new(),
            tip: Hash::default(),
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
                return Err(BlockError::TransactionError(TransactionError::DoubleSpend(
                    output_id,
                )));
            }
            spent_utxos.insert(output_id);
        }
        // Remove spent UTXOs
        for output_id in spent_utxos.iter() {
            self.utxo_set.remove(output_id);
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

    fn uproot(&mut self, tip: &Hash, root: &Hash) {
        let blocks = self
            .metadata_iter_from(tip)
            .map(|meta| meta.hash)
            .take_while(|hash| hash != root)
            .collect::<HashSet<_>>();

        for block in &blocks {
            self.block_index.remove(block);
        }

        self.utxo_set
            .retain(|_, entry| blocks.contains(&entry.block_hash));
    }
}

impl Indexer for InMemoryIndexer {
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
        // Initialize variables
        let height;
        let available_supply;
        let prev_block = self.block_index.get(&block.prev_block_hash);
        let prev_locked_supply = prev_block.map_or(0, |meta| meta.locked_supply);
        let prev_cumulative_work = prev_block.map_or(U256::zero(), |meta| meta.cumulative_work);
        let locked_supply = block.lead_utxo().map_or(0, |utxo| utxo.amount);
        let block_difficulty = prev_block
            .and_then(|meta| self.get_utxo(&meta.lead_utxo))
            .and_then(|utxo| utxo.mask().copied())
            .as_ref()
            .map_or(0, mask_difficulty);
        let block_work = U256::from(1) << block_difficulty as usize;

        // Get the previous block metadata
        if !self.block_index.is_empty() {
            let prev_meta = self.block_index.get(&block.prev_block_hash).ok_or(
                BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&block.prev_block_hash)
                )),
            )?;

            let reward = prev_locked_supply - locked_supply;
            available_supply = prev_meta.available_supply + reward;

            // Update height
            height = prev_meta.height + 1;
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
            lead_utxo: OutputId::new(block.transactions[0].hash(), 0),
            merkle_root: header.merkle_root,
            cumulative_work: prev_cumulative_work + block_work,
            available_supply,
            locked_supply,
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
                    .unwrap_or(U256::zero())
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

        self.block_index.insert(metadata.hash, metadata);
        Ok(())
    }

    fn get_block_metadata(&self, hash: &Hash) -> Option<Cow<BlockMetadata>> {
        self.block_index.get(hash).map(Cow::Borrowed)
    }

    fn get_utxo(&self, output_id: &OutputId) -> Option<Output> {
        self.utxo_set
            .get(output_id)
            .map(|entry| entry.output.clone())
    }

    fn query_utxos<'a>(
        &'a self,
        query: &'a super::Query,
    ) -> Box<dyn Iterator<Item = (OutputId, Output)> + 'a> {
        // This is to only fetch UTXOs in the canonical branch.
        let blocks: HashSet<_> = self
            .metadata_iter()
            .map(|meta| meta.hash)
            .take_while(|hash| Some(hash) != query.to.as_ref())
            .collect();
        Box::new(
            self.utxo_set
                .iter()
                .filter(move |(_, entry)| {
                    let addresses = query.addresses();
                    addresses.contains(&entry.output.commitment)
                        && blocks.contains(&entry.block_hash)
                })
                .map(|(id, entry)| (*id, entry.output)),
        )
    }

    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash> {
        self.utxo_set.get(output_id).map(|entry| entry.block_hash)
    }

    fn get_last_block_metadata(&self) -> Option<Cow<BlockMetadata>> {
        self.block_index.get(&self.tip).map(Cow::Borrowed)
    }
}

impl FullInMemoryLedger {
    pub fn new() -> Self {
        FullInMemoryLedger {
            indexer: InMemoryIndexer::new(),
            blocks: HashMap::new(),
        }
    }
}

impl Indexer for FullInMemoryLedger {
    fn add_block(&mut self, block: &Block) -> Result<(), BlockError> {
        self.indexer.add_block(block)?;
        let hash = block.header().hash();
        self.blocks.insert(hash, block.clone());
        Ok(())
    }

    fn get_block_metadata(&self, hash: &Hash) -> Option<Cow<BlockMetadata>> {
        self.indexer.get_block_metadata(hash)
    }

    fn get_utxo(&self, output_id: &OutputId) -> Option<Output> {
        self.indexer.get_utxo(output_id)
    }

    fn query_utxos<'a>(
        &'a self,
        query: &'a super::Query,
    ) -> Box<dyn Iterator<Item = (OutputId, Output)> + 'a> {
        self.indexer.query_utxos(query)
    }

    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash> {
        self.indexer.get_utxo_block_hash(output_id)
    }

    fn get_last_block_metadata(&self) -> Option<Cow<BlockMetadata>> {
        self.indexer.get_last_block_metadata()
    }
}

impl Ledger for FullInMemoryLedger {
    fn get_block(&self, hash: &Hash) -> Option<Cow<Block>> {
        self.blocks.get(hash).map(Cow::Borrowed)
    }
}
