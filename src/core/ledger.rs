use std::collections::HashMap;

use blake2::Blake2s256;
use sha2::Digest;

use super::{
    block::Block,
    transaction::{Transaction, TransactionId},
};

pub struct Ledger {
    chain: Vec<Block>,
    lookup: HashMap<TransactionId, Cursor>,
}

struct Cursor {
    block_index: usize,
    transaction_index: usize,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            chain: Vec::new(),
            lookup: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) {
        for (index, transaction) in block.transactions.iter().enumerate() {
            self.lookup.insert(
                transaction.hash(&mut Blake2s256::new()).unwrap(), // Revisit after
                Cursor {
                    block_index: self.chain.len(),
                    transaction_index: index,
                },
            );
        }
        self.chain.push(block);
    }

    pub fn get_block(&self, index: usize) -> Option<&Block> {
        self.chain.get(index)
    }

    pub fn get_transaction(&self, id: &TransactionId) -> Option<&Transaction> {
        self.lookup.get(id).and_then(|cursor| {
            self.chain
                .get(cursor.block_index)
                .and_then(|block| block.transactions.get(cursor.transaction_index))
        })
    }
}
