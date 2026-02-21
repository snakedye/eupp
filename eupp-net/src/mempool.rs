use eupp_core::ledger::Indexer;
use eupp_core::{Transaction, TransactionError, TransactionHash};
use std::borrow::Cow;
use std::collections::HashMap;

/// Error type for mempool operations.
#[derive(Debug)]
pub enum MempoolError {
    /// Transaction already exists in the mempool.
    Duplicate,
    /// Transaction verification failed.
    FailedVerification(TransactionError),
}

/// Trait for mempools, providing basic transaction management.
pub trait Mempool: Send + Sync {
    /// Add a transaction to the mempool after verification.
    fn add<L: Indexer>(&mut self, tx: Transaction, indexer: &L) -> Result<(), MempoolError>;
    /// Returns an iterator over transactions currently in the mempool.
    fn get_transactions(&'_ self) -> impl Iterator<Item = Cow<'_, Transaction>>;
    /// Removes transactions from the mempool by their hashes.
    fn remove_transactions(&mut self, tx_hashes: impl IntoIterator<Item = TransactionHash>);
    /// Clears all transactions from the mempool.
    fn clear(&mut self);
}

#[derive(Default)]
/// A simple in-memory mempool implementation.
pub struct SimpleMempool {
    pending: HashMap<TransactionHash, Transaction>,
}

impl Mempool for SimpleMempool {
    fn add<L: Indexer>(&mut self, tx: Transaction, indexer: &L) -> Result<(), MempoolError> {
        let hash = tx.hash();
        if self.pending.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        tx.verify(indexer)
            .map_err(MempoolError::FailedVerification)?;
        self.pending.insert(hash, tx);
        Ok(())
    }

    fn get_transactions(&'_ self) -> impl Iterator<Item = Cow<'_, Transaction>> {
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
