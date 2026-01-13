use eupp_core::ledger::Indexer;
use eupp_core::transaction::{Transaction, TransactionError, TransactionHash};
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug)]
pub enum MempoolError {
    TransactionExists,
    VerificationFailed(TransactionError),
}

pub trait Mempool: Send + Sync {
    fn add<L: Indexer>(&mut self, tx: Transaction, indexer: &L) -> Result<(), MempoolError>;
    fn get_transactions(&self) -> impl Iterator<Item = Cow<Transaction>>;
    fn remove_transactions(&mut self, tx_hashes: impl IntoIterator<Item = TransactionHash>);
    fn clear(&mut self) {
        let txs: Vec<_> = self.get_transactions().map(|tx| tx.hash()).collect();
        self.remove_transactions(txs);
    }
}

pub struct SimpleMempool {
    pub pending: HashMap<TransactionHash, Transaction>,
}

impl SimpleMempool {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }
}

impl Mempool for SimpleMempool {
    fn add<L: Indexer>(&mut self, tx: Transaction, indexer: &L) -> Result<(), MempoolError> {
        let hash = tx.hash();
        if self.pending.contains_key(&hash) {
            return Err(MempoolError::TransactionExists);
        }
        tx.verify(indexer)
            .map_err(MempoolError::VerificationFailed)?;
        self.pending.insert(hash, tx);
        Ok(())
    }

    fn get_transactions(&self) -> impl Iterator<Item = Cow<Transaction>> {
        self.pending.values().map(Cow::Borrowed)
    }

    fn remove_transactions(&mut self, tx_hashes: impl IntoIterator<Item = TransactionHash>) {
        for hash in tx_hashes {
            self.pending.remove(&hash);
        }
    }

    fn clear(&mut self) {
        self.pending.clear();
    }
}
