use std::{
    any::Any,
    borrow::{Borrow, Cow},
    collections::HashSet,
    path::Path,
    usize,
};

use ethnum::U256;
use eupp_core::{
    Hash,
    block::{Block, BlockError},
    ledger::{BlockMetadata, Cursor, IndexerExt, Ledger, LedgerView},
    mask_difficulty,
    transaction::{Output, OutputId, TransactionError},
};
use redb::{
    Key, MultimapTable, MultimapTableDefinition, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, Table, TableDefinition, Value,
};

use crate::fs::{FileBlockStore, LedgerError};

const TIP_KEY: &str = "tip";

const RECOVERY_TABLE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("recovery_table");
const METADATA_TABLE: TableDefinition<Hash, BlockMetadataValue> =
    TableDefinition::new("block_index");
const UTXO_TABLE: TableDefinition<OutputKey, OutputValue> = TableDefinition::new("utxo_set");
const TRANSACTION_TABLE: TableDefinition<Hash, Hash> = TableDefinition::new("transaction_table");
const ADDRESS_TABLE: MultimapTableDefinition<Hash, OutputKey> =
    MultimapTableDefinition::new("address_table");

#[derive(Debug)]
struct BlockMetadataValue;
#[derive(Debug)]
struct OutputValue;
#[derive(Debug)]
struct OutputKey;

impl Value for BlockMetadataValue {
    type SelfType<'a>
        = BlockMetadata
    where
        Self: 'a;
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;
    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        serde_json::to_vec(value).unwrap()
    }
    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        serde_json::from_slice(data).unwrap()
    }
    fn fixed_width() -> Option<usize> {
        None
    }
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("BlockMetadata")
    }
}

impl Value for OutputValue {
    type SelfType<'a>
        = Output
    where
        Self: 'a;
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;
    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        serde_json::to_vec(value).unwrap()
    }
    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        serde_json::from_slice(data).unwrap()
    }
    fn fixed_width() -> Option<usize> {
        None
    }
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("Output")
    }
}

impl Value for OutputKey {
    type SelfType<'a>
        = OutputId
    where
        Self: 'a;
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;
    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        serde_json::to_vec(value).unwrap()
    }
    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        serde_json::from_slice(data).unwrap()
    }
    fn fixed_width() -> Option<usize> {
        None
    }
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("Output")
    }
}

impl Key for OutputKey {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        let out_1 = serde_json::de::from_slice::<OutputId>(data1);
        let out_2 = serde_json::de::from_slice::<OutputId>(data2);
        out_1
            .ok()
            .zip(out_2.ok())
            .map(|(out_1, out_2)| out_1.cmp(&out_2))
            .unwrap()
    }
}

pub struct RedbIndexer<T = ()> {
    tip: Option<Hash>,
    db: redb::Database,
    addresses: HashSet<Hash>,
    fs: T,
}

impl RedbIndexer {
    pub fn new(db: redb::Database) -> Self {
        RedbIndexer {
            db,
            tip: Default::default(),
            addresses: HashSet::new(),
            fs: (),
        }
    }
}

impl<T: AsRef<Path>> From<T> for RedbIndexer {
    fn from(path: T) -> Self {
        let db = redb::Database::create(path).unwrap();
        let tip = RedbIndexer::<()>::recover_tip(&db);

        RedbIndexer {
            db,
            tip,
            addresses: HashSet::new(),
            fs: (),
        }
    }
}

impl<Fs> RedbIndexer<Fs> {
    pub fn with_fs(
        self,
        path: impl AsRef<Path>,
    ) -> Result<RedbIndexer<FileBlockStore>, LedgerError> {
        let fs = FileBlockStore::new(path.as_ref())?;
        Ok(RedbIndexer {
            tip: self.tip,
            db: self.db,
            addresses: self.addresses,
            fs,
        })
    }
    fn recover_tip(db: &redb::Database) -> Option<Hash> {
        let read_tx = db.begin_read().unwrap();
        let recovery_table = read_tx.open_table(RECOVERY_TABLE).ok()?;
        recovery_table
            .get(TIP_KEY)
            .ok()
            .flatten()
            .map(|tip| tip.value().try_into().ok())
            .flatten()
    }
    pub fn add_address(&mut self, address: Hash) {
        self.addresses.insert(address);
    }
    fn get<'a, K, V, F, U, T>(
        &self,
        table: &T,
        key: impl Borrow<K::SelfType<'a>>,
        f: F,
    ) -> Option<U>
    where
        K: Key + 'static,
        V: Value + 'static,
        T: ReadableTable<K, V>,
        for<'f> F: FnOnce(V::SelfType<'f>) -> U,
    {
        table.get(key).ok().flatten().map(|value| f(value.value()))
    }
    fn write_block_to_utxo_set(
        &mut self,
        utxo_set: &mut Table<OutputKey, OutputValue>,
        tx_table: &mut Table<Hash, Hash>,
        address_table: &mut MultimapTable<Hash, OutputKey>,
        block: &Block,
    ) -> Result<(), BlockError> {
        // We keep the previous block's lead UTXO
        let mut prev_lead_output = None;

        // Check for double spending within the block
        for (i, input) in block
            .transactions
            .iter()
            .flat_map(|txs| txs.inputs.iter())
            .enumerate()
        {
            let output_id = input.output_id();
            let spent_output = utxo_set
                .remove(output_id)
                .map_err(|err| BlockError::Other(err.to_string()))?;
            match spent_output {
                Some(output) => {
                    if i == 0 {
                        prev_lead_output = Some((output_id, output.value()))
                    }
                }
                None => {
                    return Err(BlockError::TransactionError(
                        TransactionError::InvalidOutput(output_id),
                    ));
                }
            }
        }

        // We re-insert the lead UTXO to allow for forks
        if let Some((prev_lead_utxo, prev_lead_output)) = prev_lead_output {
            utxo_set
                .insert(prev_lead_utxo, prev_lead_output)
                .map_err(|err| BlockError::Other(err.to_string()))?;
        }

        let block_hash = block.header().hash();
        // Add new UTXOs
        for (i, tx_id, output) in block.transactions.iter().flat_map(|tx| {
            let tx_id = tx.hash();
            tx.outputs
                .iter()
                .enumerate()
                .map(move |(i, output)| (i, tx_id, output))
        }) {
            let output_id = OutputId::new(tx_id, i as u8);

            if self.addresses.contains(&output.commitment) {
                address_table
                    .insert(output.commitment, output_id.clone())
                    .map_err(|err| BlockError::Other(err.to_string()))?;
            }

            utxo_set
                .insert(output_id, output)
                .map_err(|err| BlockError::Other(err.to_string()))?;

            tx_table
                .insert(tx_id, block_hash)
                .map_err(|err| BlockError::Other(err.to_string()))?;
        }
        Ok(())
    }
    fn get_fs(&self) -> Option<&FileBlockStore>
    where
        Fs: Any,
    {
        let fs = &self.fs as &dyn Any;
        fs.downcast_ref::<FileBlockStore>()
    }
}

impl<T: 'static> eupp_core::ledger::Indexer for RedbIndexer<T> {
    fn add_block(&mut self, block: &eupp_core::block::Block) -> Result<(), BlockError> {
        let write_tx = self.db.begin_write().unwrap();

        {
            let mut utxo_set = write_tx.open_table(UTXO_TABLE).unwrap();
            let mut tx_table = write_tx.open_table(TRANSACTION_TABLE).unwrap();
            let mut address_table = write_tx.open_multimap_table(ADDRESS_TABLE).unwrap();
            let mut metadata_table = write_tx.open_table(METADATA_TABLE).unwrap();
            let mut recovery_table = write_tx.open_table(RECOVERY_TABLE).unwrap();

            let cursor;
            let height;
            let available_supply;
            let prev_block = self.get(&metadata_table, &block.prev_block_hash, |metadata| metadata);
            let prev_locked_supply = prev_block
                .as_ref()
                .map_or(0, |meta| meta.locked_supply(self));
            let prev_cumulative_work = prev_block
                .as_ref()
                .map_or(U256::MIN, |meta| meta.cumulative_work);
            let locked_supply = block.lead_output().map_or(0, |utxo| utxo.amount);
            let block_difficulty = prev_block
                .as_ref()
                .and_then(|meta| self.get_utxo(&meta.lead_output))
                .and_then(|utxo| utxo.mask().copied())
                .as_ref()
                .map_or(0, mask_difficulty);
            let block_work = U256::new(1) << block_difficulty as usize;

            if !metadata_table.is_empty().unwrap() {
                let prev_meta = prev_block.ok_or(BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&block.prev_block_hash)
                )))?;

                let reward = prev_locked_supply.saturating_sub(locked_supply);
                available_supply = prev_meta.available_supply + reward;

                // Update height
                height = prev_meta.height + 1;
            } else {
                height = 0;
                available_supply = 0;
            }

            // Set the cursor to read the block
            cursor = self
                .get_fs()
                .and_then(|fs| fs.append_block(block).ok())
                .map(|(pos, len)| Cursor {
                    pos: pos as usize,
                    len,
                });

            let header = block.header();
            let metadata = BlockMetadata {
                version: header.version,
                hash: header.hash(),
                prev_block_hash: header.prev_block_hash,
                lead_output: OutputId::new(block.transactions[0].hash(), 0),
                merkle_root: header.merkle_root,
                cumulative_work: prev_cumulative_work + block_work,
                available_supply,
                height,
                cursor,
            };

            // Verify the block
            block.verify(self)?;

            // Update the UTXO Set (Spend inputs, add new outputs)
            self.write_block_to_utxo_set(&mut utxo_set, &mut tx_table, &mut address_table, &block)?;

            let current_prev_metadata = self
                .tip
                .as_ref()
                .and_then(|tip| self.get(&metadata_table, tip, |metadata| metadata));

            // Update Tip if this chain is now heavier or if there's no block for the tip
            if self.get_tip().is_none()
                || metadata.cumulative_work
                    > current_prev_metadata
                        .map(|meta| meta.cumulative_work)
                        .unwrap_or_default()
            {
                // Update the tip to the new metadata hash.
                self.tip = Some(metadata.hash);
                recovery_table
                    .insert(TIP_KEY, metadata.hash.to_vec())
                    .map_err(|err| BlockError::Other(err.to_string()))?;
            }

            metadata_table
                .insert(metadata.hash, metadata)
                .map_err(|err| BlockError::Other(err.to_string()))?;
        }

        write_tx
            .commit()
            .map_err(|err| BlockError::Other(err.to_string()))
    }
    fn get_block_metadata(&'_ self, hash: &Hash) -> Option<Cow<'_, BlockMetadata>> {
        let read_tx = self.db.begin_read().ok()?;
        let table = read_tx.open_table(METADATA_TABLE).ok()?;
        self.get(&table, hash, Cow::Owned)
    }
    fn get_tip(&'_ self) -> Option<Hash> {
        self.tip
    }
    fn get_utxo(&self, output_id: &OutputId) -> Option<Output> {
        let read_tx = self.db.begin_read().ok()?;
        let table = read_tx.open_table(UTXO_TABLE).ok()?;
        self.get(&table, output_id, |output| output)
    }
    fn query_utxos(&self, query: &eupp_core::ledger::Query) -> Vec<(OutputId, Output)> {
        let read_tx = self.db.begin_read().unwrap();
        let address_table = read_tx.open_multimap_table(ADDRESS_TABLE).unwrap();
        let utxo_table = read_tx.open_table(UTXO_TABLE).unwrap();

        let addresses = if query.addresses().is_empty() {
            &self.addresses
        } else {
            query.addresses()
        };

        addresses
            .iter()
            .filter_map(|address| address_table.get(address).ok())
            .flat_map(|values| values)
            .filter_map(|value| value.ok())
            .map(|output_id| output_id.value())
            .filter_map(|output_id| {
                utxo_table
                    .get(output_id)
                    .ok()
                    .map(move |value| (output_id, value.unwrap().value()))
            })
            .collect()
    }
    fn get_utxo_block_hash(&self, output_id: &OutputId) -> Option<Hash> {
        let read_tx = self.db.begin_read().ok()?;
        let table = read_tx.open_table(TRANSACTION_TABLE).ok()?;
        self.get(&table, output_id.tx_hash, |hash| hash)
    }
}

impl<T: Any> LedgerView for RedbIndexer<T> {
    type Ledger<'a>
        = RedbIndexer<FileBlockStore>
    where
        Self: 'a;

    fn as_ledger<'a>(&'a self) -> Option<&'a Self::Ledger<'a>> {
        (self as &dyn Any).downcast_ref::<RedbIndexer<FileBlockStore>>()
    }
}

impl Ledger for RedbIndexer<FileBlockStore> {
    fn get_block(&'_ self, hash: &Hash) -> Option<Cow<'_, Block>> {
        let mut iter = self.metadata_from(hash);
        if let Some(cursor) = iter.next().and_then(|metadata| metadata.cursor) {
            self.fs
                .get_block(cursor.pos as u64, cursor.len)
                .ok()
                .map(Cow::Owned)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use eupp_core::block::Block;
    use eupp_core::block::BlockError;
    use eupp_core::ledger::{Indexer, Query};
    use eupp_core::transaction::TransactionError;
    use eupp_core::transaction::sighash;
    use eupp_core::transaction::{Input, Output, OutputId, Transaction};
    use redb::Database;
    use redb::backends::InMemoryBackend;

    fn create_db() -> Database {
        Database::builder()
            .create_with_backend(InMemoryBackend::new())
            .unwrap()
    }

    #[test]
    fn no_tip() {
        let db = create_db();
        let indexer = RedbIndexer::new(db);

        assert_eq!(indexer.get_tip(), None)
    }

    #[test]
    fn add_genesis_and_get_utxo() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        // Create a simple genesis block containing a single funding transaction
        let pk = [0u8; 32];
        let data = [12u8; 32];
        let output = Output::new_v1(100, &pk, &data);
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![output],
        };
        let funding_txid = funding_tx.hash();

        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);

        // Adding the genesis block should succeed
        indexer.add_block(&block).expect("add genesis");

        // The UTXO should now be present
        let utxo_id = OutputId::new(funding_txid, 0);
        let maybe = indexer.get_utxo(&utxo_id);
        assert_eq!(maybe, Some(output));
    }

    #[test]
    fn address_indexing_and_query() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        // We'll index a specific commitment as an address
        let output = Output::new_v1(42, &[7u8; 32], &[0u8; 32]);
        let address = output.commitment;
        indexer.add_address(address);

        // Create a block with an output that has this commitment
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![output],
        };
        let txid = tx.hash();
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(tx);

        indexer.add_block(&block).expect("add block");

        // Query with an empty Query should return indexed addresses (the indexer stores added addresses)
        let q = Query::new();
        let res = indexer.query_utxos(&q);
        // We expect at least one UTXO for our address
        assert!(
            res.iter()
                .any(|(id, out)| id.tx_hash == txid && out.commitment == address)
        );
    }

    #[test]
    fn get_utxo_block_hash_is_recorded() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        let tx = Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v0(11, &[1u8; 32], &[2u8; 32])],
        };
        let txid = tx.hash();
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(tx);

        indexer.add_block(&block).expect("add block");

        let utxo_id = OutputId::new(txid, 0);
        let block_hash = block.header().hash();

        let maybe = indexer.get_utxo_block_hash(&utxo_id);
        assert_eq!(maybe, Some(block_hash));
    }

    #[test]
    fn get_block_metadata() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        // Create a simple genesis block containing a single funding transaction
        let pk = [0u8; 32];
        let data = [12u8; 32];
        let output = Output::new_v0(100, &pk, &data);
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![output],
        };
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);

        // Adding the genesis block should succeed
        indexer.add_block(&block).expect("add genesis");

        // Retrieve the block metadata
        let block_hash = block.header().hash();
        let metadata = indexer.get_block_metadata(&block_hash);

        // Ensure metadata is present and matches the block
        assert!(metadata.is_some());
        let metadata = metadata.unwrap();
        assert_eq!(metadata.hash, block_hash);
        assert_eq!(metadata.height, 0);
        assert_eq!(metadata.prev_block_hash, [0u8; 32]);
    }

    #[test]
    fn detect_double_spend_within_block() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        // Build and add the first block
        let data = [0u8; 32];
        let out1 = Output::new_v0(100, &data, &data);
        let tx1 = Transaction {
            inputs: vec![],
            outputs: vec![out1],
        };
        let tx_hash = tx1.hash();
        let mut block1 = Block::new(0, [0u8; 32]);
        block1.transactions.push(tx1);
        indexer.add_block(&block1).expect("add block1");

        // Build and add a second block that points to the first (so metadata iterator yields a next cursor)
        let out2 = Output::new_v0(99, &data, &data);
        let output_id = OutputId::new(tx_hash, 0);
        let sighash = sighash([&output_id; 2], [&out2]);
        let input = Input::new_unsigned(output_id).sign(&[0; 32], sighash);
        let tx2 = Transaction {
            inputs: vec![input; 2],
            outputs: vec![out2],
        };
        let mut block2 = Block::new(0, block1.header().hash());
        block2.transactions.push(tx2);
        let res = indexer.add_block(&block2);

        match res {
            Err(BlockError::TransactionError(TransactionError::InvalidOutput(_))) => {}
            other => panic!("expected invalid output error, got: {:?}", other),
        }
    }

    #[test]
    fn get_block_via_fs() {
        // This test exercises the FileBlockStore integration: we attach a FileBlockStore to the
        // indexer, add two blocks (so the first block has a 'next' cursor) and then retrieve the
        // first block through the indexer's Ledger implementation.
        let db = create_db();

        // create a temporary file for the ledger
        let mut path = std::env::temp_dir();
        path.push("eupp-db-indexer-get-block-test.dat");
        // ensure clean
        let _ = std::fs::remove_file(&path);

        let mut indexer = RedbIndexer::new(db).with_fs(&path).unwrap();

        // Build and add the first block
        let data = [0u8; 32];
        let out1 = Output::new_v0(100, &data, &data);
        let tx1 = Transaction {
            inputs: vec![],
            outputs: vec![out1],
        };
        let tx_hash = tx1.hash();
        let mut block1 = Block::new(0, [0u8; 32]);
        block1.transactions.push(tx1);
        indexer.add_block(&block1).expect("add block1");

        // Build and add a second block that points to the first (so metadata iterator yields a next cursor)
        let out2 = Output::new_v0(99, &data, &data);
        let output_id = OutputId::new(tx_hash, 0);
        let sighash = sighash([&output_id], [&out2]);
        let input = Input::new_unsigned(output_id).sign(&[0; 32], sighash);
        let tx2 = Transaction {
            inputs: vec![input],
            outputs: vec![out2],
        };
        let mut block2 = Block::new(0, block1.header().hash());
        block2.transactions.push(tx2);
        indexer.add_block(&block2).expect("add block2");

        // Retrieve block1 through the Ledger interface implemented by the indexer
        let hash1 = block1.header().hash();
        let maybe = indexer.get_block(&hash1);
        assert!(
            maybe.is_some(),
            "expected to retrieve block via fs-backed ledger"
        );
        let read_block = maybe.unwrap();
        assert_eq!(read_block.header().hash(), hash1);

        // cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn add_multiple_blocks_and_get_tip() {
        let db = create_db();
        let mut indexer = RedbIndexer::new(db);

        // Create and add the first block
        let data = [0u8; 32];
        let out1 = Output::new_v0(100, &data, &data);
        let tx1 = Transaction {
            inputs: vec![],
            outputs: vec![out1],
        };
        let tx1_hash = tx1.hash();
        let mut block1 = Block::new(0, [0u8; 32]);
        block1.transactions.push(tx1);
        indexer.add_block(&block1).expect("add block1");

        // Create and add the second block
        let out2 = Output::new_v0(99, &data, &data);
        let output_id = OutputId::new(tx1_hash, 0);
        let sighash1 = sighash([&output_id], [&out2]);
        let input = Input::new_unsigned(output_id).sign(&[0; 32], sighash1);
        let tx2 = Transaction {
            inputs: vec![input],
            outputs: vec![out2],
        };
        let tx2_hash = tx2.hash();
        let mut block2 = Block::new(0, block1.header().hash());
        block2.transactions.push(tx2);
        indexer.add_block(&block2).expect("add block2");

        // Create and add the third block
        let out3 = Output::new_v0(98, &data, &data);
        let output_id = OutputId::new(tx2_hash, 0);
        let sighash2 = sighash([&output_id], [&out3]);
        let input = Input::new_unsigned(output_id).sign(&[0; 32], sighash2);
        let tx3 = Transaction {
            inputs: vec![input],
            outputs: vec![out3],
        };
        let mut block3 = Block::new(0, block2.header().hash());
        block3.transactions.push(tx3);
        indexer.add_block(&block3).expect("add block3");

        // Get the tip and verify it matches the hash of the third block
        let tip = indexer.get_tip();
        assert_eq!(tip, Some(block3.header().hash()));
    }
}
