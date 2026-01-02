use crate::miner::mining_solution;

use super::{
    Hash, VirtualSize, calculate_reward,
    ledger::Ledger,
    matches_mask,
    transaction::{Output, Transaction, TransactionHash},
};
use blake2::{Blake2s256, Digest};

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub version: u8,
    pub prev_block_hash: Hash,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: u8,
    pub prev_block_hash: Hash,
    pub merkle_root: Hash,
}

#[derive(Debug, Clone, PartialEq)]
/// Represents errors that can occur when validating blocks.
pub enum BlockError {
    InvalidBlockHash(String),
    InvalidBlockSize(usize),
    ChallengeError,
    InvalidVersion(u8),
    SupplyError { min: u32, actual: u32 },
    TransactionError(super::transaction::TransactionError),
}

impl VirtualSize for Block {
    fn vsize(&self) -> usize {
        1 + self.prev_block_hash.len()
            + self.transactions.iter().map(|tx| tx.vsize()).sum::<usize>()
    }
}

impl BlockHeader {
    /// Returns the hash of the block header.
    pub fn hash<T: Digest>(&self) -> Hash {
        let mut buf = [0u8; 32];
        let mut hasher = T::new();

        Digest::update(&mut hasher, &[self.version as u8]);
        Digest::update(&mut hasher, &self.prev_block_hash);
        Digest::update(&mut hasher, &self.merkle_root);

        buf.as_mut().copy_from_slice(hasher.finalize().as_ref());
        buf
    }
}

impl Block {
    pub fn new(version: u8, prev_block_hash: Hash) -> Self {
        Self {
            version,
            prev_block_hash,
            transactions: Vec::new(),
        }
    }

    /// Returns the header of the block.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: self.version,
            prev_block_hash: self.prev_block_hash,
            merkle_root: self.merkle_root(),
        }
    }

    pub fn verify<L: Ledger>(&self, ledger: &L) -> Result<(), BlockError> {
        // We only check if there's a previous block
        // Otherwise this block is the genesis block and we don't need to verify it
        if ledger.get_last_block_metadata().is_some() {
            let prev_block_hash = self.prev_block_hash;

            // Verify the previous block hash
            ledger
                .get_block_metadata(&prev_block_hash)
                .ok_or(BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&self.prev_block_hash)
                )))?;

            // Verify the challenge
            let input = self
                .transactions
                .first()
                .and_then(|tx| tx.inputs.first())
                .unwrap();
            let lead_utxo = ledger.get_utxo(&input.output_id).unwrap();
            let mask = &lead_utxo.commitment;
            let solution = mining_solution(&input.public_key, &self.prev_block_hash);
            if !matches_mask(&mask, &solution) {
                return Err(BlockError::ChallengeError);
            }

            // Verify the new supply ie supply preservation
            let new_supply = self
                .transactions
                .first()
                .and_then(|tx| tx.outputs.first())
                .map(|o| o.amount)
                .unwrap_or_default();
            let old_supply = lead_utxo.amount;
            let max_reward = calculate_reward(mask);
            let min_supply = old_supply.saturating_sub(max_reward);
            if new_supply < min_supply || new_supply > old_supply {
                return Err(BlockError::SupplyError {
                    min: min_supply,
                    actual: new_supply,
                });
            }

            // Verify that the new lead utxo is v1 only
            let new_lead_output = self.transactions.first().and_then(|tx| tx.outputs.first());
            if let Some(output) = new_lead_output {
                if !matches!(output.version, super::transaction::Version::V0) {
                    return Err(BlockError::InvalidVersion(output.version as u8));
                }
            }
        }

        let vsize = self.vsize();
        // Check if the block virtual size exceeds 1 megabyte
        if vsize > 1_000_000 {
            return Err(BlockError::InvalidBlockSize(vsize));
        }

        self.transactions
            .iter()
            .try_for_each(|tx| tx.verify(ledger).map_err(BlockError::TransactionError))
    }

    /// Returns the lead (mint) UTXO if present.
    pub fn lead_utxo(&self) -> Option<&Output> {
        self.transactions.first().and_then(|tx| tx.outputs.first())
    }

    /// Returns the merkle root of the transactions in the block.
    pub(crate) fn merkle_root(&self) -> TransactionHash {
        merkle_root::<Blake2s256>(&self.transactions)
    }
}

// This is a non-standard implementation of the Merkle root algorithm.
fn merkle_root<D>(transactions: &[Transaction]) -> TransactionHash
where
    D: Digest,
{
    let hash;
    match transactions.len() {
        0 => hash = [0; 32],
        1 => hash = transactions[0].hash::<D>(),
        _ => {
            let mut hasher = D::new();
            let (a, b) = transactions.split_at(transactions.len() / 2);
            let (merkle_root_a, merkle_root_b) = (merkle_root::<D>(a), merkle_root::<D>(b));
            hasher.update(&merkle_root_a);
            hasher.update(&merkle_root_b);
            hash = hasher.finalize().as_slice().try_into().unwrap();
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PublicKey,
        ledger::InMemoryLedger,
        transaction::{Input, OutputId},
    };

    fn genesis_block(mask: [u8; 32]) -> Block {
        let prev_block_hash = [0; 32];
        let mut block = Block::new(0, prev_block_hash);
        block.transactions.push(Transaction::new(
            vec![],
            vec![Output {
                version: crate::transaction::Version::V0,
                amount: calculate_reward(&mask),
                data: [0; 32],
                commitment: mask, // this is the mask challenge
            }],
        ));
        block
    }

    fn mining_transaction(new_supply: u32, tx_hash: Hash, public_key: PublicKey) -> Transaction {
        let output_id = OutputId::new(tx_hash, 0);
        let mut transaction = Transaction::new(vec![], vec![]);
        transaction
            .inputs
            .push(Input::new(output_id, public_key, [0; 64]));
        transaction.outputs.push(Output {
            version: crate::transaction::Version::V0,
            amount: new_supply,
            data: [0; 32],
            commitment: [0; 32], // this is the mask challenge
        });
        transaction
    }

    fn new_ledger(public_key: PublicKey) -> (InMemoryLedger, Transaction) {
        let mut ledger = InMemoryLedger::new();
        let genesis_block = genesis_block([0; 32]);
        let new_supply = genesis_block.transactions[0].outputs[0].amount;
        let prev_tx_hash = genesis_block.transactions[0].hash::<Blake2s256>();
        let mining_transaction = mining_transaction(new_supply, prev_tx_hash, public_key);
        ledger.add_block(genesis_block.clone()).unwrap();
        (ledger, mining_transaction)
    }

    #[test]
    fn test_block_with_invalid_prev_block_hash() {
        let (ledger, mining_transaction) = new_ledger([0; 32]);

        let mut block = Block::new(1, [1; 32]); // Invalid prev_block_hash
        block.transactions.push(mining_transaction);

        let result = block.verify(&ledger);
        match result {
            Err(BlockError::InvalidBlockHash(_)) => (),
            e => panic!("Expected BlockError::InvalidBlockHash, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_invalid_challenge() {
        let mut ledger = InMemoryLedger::new();
        let genesis_block = genesis_block([1; 32]);
        let genesis_block_hash = genesis_block.header().hash::<Blake2s256>();
        let first_tx_hash = genesis_block.transactions[0].hash::<Blake2s256>();
        ledger.add_block(genesis_block.clone()).unwrap();

        let mut block = Block::new(1, genesis_block_hash);
        let transaction = mining_transaction(1, first_tx_hash, [0; 32]);
        block.transactions.push(transaction); // Invalid challenge

        let result = block.verify(&ledger);
        assert_eq!(result, Err(BlockError::ChallengeError));
    }

    #[test]
    fn test_block_with_valid_challenge() {
        let mut ledger = InMemoryLedger::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash::<Blake2s256>();
        ledger.add_block(genesis_block.clone()).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash::<Blake2s256>());
        let transaction = mining_transaction(1, first_tx_hash, [1; 32]);
        block.transactions.push(transaction);

        let result = block.verify(&ledger);
        match result {
            Ok(()) | Err(BlockError::TransactionError(_)) => (),
            e => panic!("Expected Ok or BlockError::TransactionError, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_reward_above_max_reward() {
        let mut ledger = InMemoryLedger::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash::<Blake2s256>();
        ledger.add_block(genesis_block.clone()).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash::<Blake2s256>());
        let transaction = mining_transaction(2, first_tx_hash, [1; 32]);
        block.transactions.push(transaction);

        let result = block.verify(&ledger);
        match result {
            Err(BlockError::SupplyError { .. }) => (),
            e => panic!("Expected BlockError::RewardError, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_invalid_lead_utxo_version() {
        let mut ledger = InMemoryLedger::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash::<Blake2s256>();
        ledger.add_block(genesis_block.clone()).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash::<Blake2s256>());
        let mut transaction = mining_transaction(1, first_tx_hash, [1; 32]);
        transaction.outputs[0].version = crate::transaction::Version::V1; // Invalid version
        block.transactions.push(transaction);

        let result = block.verify(&ledger);
        match result {
            Err(BlockError::InvalidVersion(_)) => (),
            e => panic!("Expected BlockError::InvalidVersion, got {:?}", e),
        }
    }

    #[test]
    fn test_block_header_hash() {
        let block = genesis_block([0; 32]);
        let header = block.header();
        let hash = header.hash::<Blake2s256>();

        // Ensure the hash is not empty and has the expected length
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0; 32]);

        // Verify that the hash changes if the header changes
        let mut modified_header = header.clone();
        modified_header.version = 89;
        let modified_hash = modified_header.hash::<Blake2s256>();
        assert_ne!(hash, modified_hash);
    }
}
