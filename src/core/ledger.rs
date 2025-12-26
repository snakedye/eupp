use std::collections::HashMap;

use blake2::Blake2s256;

use super::{
    Hash,
    block::Block,
    transaction::{Transaction, TransactionHash},
};

pub struct Ledger {
    pub chain: Vec<Block>,
    pub tx_lookup: HashMap<TransactionHash, TxCursor>,
    pub block_lookup: HashMap<Hash, BlockCursor>,
}

struct TxCursor {
    block_index: usize,
    transaction_index: usize,
}

struct BlockCursor {
    block_index: usize,
    total_supply: u64,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            chain: Vec::new(),
            tx_lookup: HashMap::new(),
            block_lookup: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) {
        let block_hash = block.header().hash::<Blake2s256>();
        let block_index = self.chain.len();
        for (index, transaction) in block.transactions.iter().enumerate() {
            self.tx_lookup.insert(
                transaction.hash::<Blake2s256>(),
                TxCursor {
                    block_index,
                    transaction_index: index,
                },
            );
        }
        let last_block_supply =
            self.block_lookup
                .get(&block.previous_block_hash)
                .map(|prev_block_cursor| {
                    prev_block_cursor.total_supply + block.transactions[0].outputs[0].amount
                });
        self.block_lookup.insert(
            block_hash,
            BlockCursor {
                block_index,
                total_supply: last_block_supply.unwrap_or(0),
            },
        );
        self.chain.push(block);
    }

    pub fn get_block(&self, hash: &Hash) -> Option<&Block> {
        self.block_lookup
            .get(hash)
            .and_then(|cursor| self.chain.get(cursor.block_index))
    }

    /// Return the current chain length (number of blocks).
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    pub fn get_transaction(&self, id: &TransactionHash) -> Option<&Transaction> {
        self.tx_lookup.get(id).and_then(|cursor| {
            self.chain
                .get(cursor.block_index)
                .and_then(|block| block.transactions.get(cursor.transaction_index))
        })
    }

    pub fn get_block_supply(&self, hash: &Hash) -> Option<u64> {
        self.block_lookup
            .get(hash)
            .map(|cursor| cursor.total_supply)
    }
}
