/*!
This module defines the structure and validation logic for blocks in a blockchain.

A block is a fundamental unit in the blockchain, containing a list of transactions,
a reference to the previous block, and a header with metadata. The module also includes
utilities for calculating Merkle roots, verifying Merkle proofs, and validating blocks
against various rules.

# Key Components

- `Block`: Represents a block in the blockchain, containing transactions and metadata.
- `BlockHeader`: Contains metadata about the block, such as its version, previous block hash, and Merkle root.
- `BlockError`: Enumerates possible errors that can occur during block validation.
- `Leaf` and `Direction`: Represent nodes in the Merkle tree and their direction (left or right).

# Features

- Block validation, including checks for:
  - Validity of the previous block hash.
  - Correctness of the mining challenge.
  - Supply preservation and reward limits.
  - Transaction validity.
- Calculation of Merkle roots and proofs for transactions.
- Utilities for verifying Merkle proofs.

# Usage

This module is designed to be used in a blockchain implementation where blocks are
validated and added to the chain. It assumes the presence of an `Indexer` trait for
accessing blockchain data and a `Transaction` structure for representing transactions.
*/

use crate::miner::mining_solution;

use super::{
    Hash, VirtualSize, calculate_reward,
    ledger::Indexer,
    matches_mask,
    transaction::{Output, Transaction, TransactionHash},
};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// The maximum block size in vbytes.
pub const MAX_BLOCK_SIZE: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A block in the blockchain.
pub struct Block {
    /// The version of the block, used to indicate protocol changes.
    pub version: u8,
    /// The hash of the previous block in the blockchain.
    pub prev_block_hash: Hash,
    /// A list of transactions included in the block.
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The header of a block, offering an overview of the block.
pub struct BlockHeader {
    /// The version of the block, used to indicate protocol changes.
    pub version: u8,
    /// The hash of the previous block in the blockchain.
    pub prev_block_hash: Hash,
    /// The Merkle root of the transactions in the block.
    pub merkle_root: Hash,
}

/// Represents errors that can occur when validating blocks.
#[derive(Debug, Clone, PartialEq)]
/// Represents errors that can occur when validating blocks.
pub enum BlockError {
    /// The previous block hash is invalid or not found.
    InvalidBlockHash(String),
    /// The block size exceeds the maximum allowed size.
    InvalidBlockSize(usize),
    /// The mining challenge was not solved correctly.
    ChallengeError,
    /// The lead UTXO version is invalid.
    InvalidVersion(u8),
    /// The supply in the block is outside the allowed range.
    SupplyError { min: u64, actual: u64 },
    /// An error occurred in one of the block's transactions.
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
    pub fn hash(&self) -> Hash {
        let mut hasher = Blake2s256::new();

        hasher.update(&[self.version as u8]);
        hasher.update(&self.prev_block_hash);
        hasher.update(&self.merkle_root);

        hasher.finalize().into()
    }
    /// Verifies a transaction using its Merkle proof.
    pub fn verify_transaction_with_proof(&self, proof: &[Leaf]) -> Option<()> {
        verify_proof(&self.merkle_root, proof)
    }
}

impl Block {
    /// Create a new `Block`.
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

    /// Verifies that the `Block` is valid.
    pub fn verify<L: Indexer>(&self, indexer: &L) -> Result<(), BlockError> {
        // We only check if there's a previous block
        // Otherwise this block is the genesis block and we don't need to verify it
        if indexer.get_last_block_metadata().is_some() {
            let prev_block_hash = self.prev_block_hash;

            // Verify the previous block hash
            let _ = indexer.get_block_metadata(&prev_block_hash).ok_or(
                BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&self.prev_block_hash)
                )),
            )?;

            // Verify the challenge
            let input = self
                .transactions
                .first()
                .and_then(|tx| tx.inputs.first())
                .unwrap();
            let this_lead_utxo = &self.transactions[0].outputs[0];
            let prev_lead_utxo =
                indexer
                    .get_utxo(&input.output_id)
                    .ok_or(BlockError::TransactionError(
                        crate::transaction::TransactionError::InvalidOutput(input.output_id),
                    ))?;

            let (mask, nonce) = prev_lead_utxo
                .mask()
                .zip(this_lead_utxo.nonce())
                .ok_or_else(|| BlockError::InvalidVersion(prev_lead_utxo.version as u8))?;
            let solution = mining_solution(&prev_block_hash, &input.public_key, nonce);
            if !matches_mask(mask, &solution) {
                return Err(BlockError::ChallengeError);
            }

            // Verify the new supply ie supply preservation
            let new_supply = self
                .transactions
                .first()
                .and_then(|tx| tx.outputs.first())
                .map(|o| o.amount)
                .unwrap_or_default();
            let fees = self.fees(indexer);
            let old_supply = prev_lead_utxo.amount;
            let max_reward = calculate_reward(mask);
            let max_supply = old_supply + fees;
            let min_supply = old_supply.saturating_sub(max_reward);
            if new_supply < min_supply || new_supply > max_supply {
                return Err(BlockError::SupplyError {
                    min: min_supply,
                    actual: new_supply,
                });
            }

            // We verify the supply preservation on the mining transaction.
            let total_input = self.transactions[0]
                .inputs
                .iter()
                .filter_map(|input| indexer.get_utxo(&input.output_id))
                .map(|output| output.amount)
                .sum();
            let total_output = self.transactions[0]
                .outputs
                .iter()
                .map(|output| output.amount)
                .sum();
            if total_output > total_input + fees {
                return Err(BlockError::TransactionError(
                    crate::transaction::TransactionError::InvalidBalance {
                        total_input,
                        total_output,
                    },
                ));
            }

            // Verify that the new lead utxo is v0 only
            let new_lead_output = self.transactions.first().and_then(|tx| tx.outputs.first());
            if let Some(output) = new_lead_output {
                if !matches!(output.version, super::transaction::Version::V0) {
                    return Err(BlockError::InvalidVersion(output.version as u8));
                }
            }
        }

        let vsize = self.vsize();
        // Check if the block virtual size exceeds 1 megabyte
        if vsize > MAX_BLOCK_SIZE {
            return Err(BlockError::InvalidBlockSize(vsize));
        }

        self.transactions
            .iter()
            .try_for_each(|tx| tx.verify(indexer).map_err(BlockError::TransactionError))
    }

    /// Calculates the total fees.
    pub fn fees<L: Indexer>(&self, indexer: &L) -> u64 {
        self.transactions
            .iter()
            .skip(1) // The mining transaction is not included in the fees calculation.
            .map(|tx| tx.fee(indexer))
            .sum()
    }

    /// Returns the lead (mint) UTXO if present.
    pub fn lead_utxo(&self) -> Option<&Output> {
        self.transactions.first().and_then(|tx| tx.outputs.first())
    }

    /// Returns the merkle root of the transactions in the block.
    pub(crate) fn merkle_root(&self) -> TransactionHash {
        merkle_root(&self.transactions, &mut Vec::new()).1
    }

    /// Returns the merkle proof for a given transaction hash.
    pub fn merkle_proof(&self, tx_hash: &TransactionHash) -> Option<Vec<Leaf>> {
        let mut proof = vec![Leaf::new(*tx_hash)];
        merkle_root(&self.transactions, &mut proof);
        if proof.len() > 1 { Some(proof) } else { None }
    }
}

/// A leaf node in the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Leaf {
    dir: Option<Direction>,
    hash: TransactionHash,
}

/// The direction of a node in the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Direction {
    Left,
    Right,
}

impl Leaf {
    fn new_with_dir(hash: TransactionHash, dir: Direction) -> Self {
        Leaf {
            hash,
            dir: Some(dir),
        }
    }
    pub fn new(hash: TransactionHash) -> Self {
        Leaf { hash, dir: None }
    }
}

/// Computes the Merkle root of a list of transactions and generates a Merkle proof for a specific transaction.
fn merkle_root(transactions: &[Transaction], proof: &mut Vec<Leaf>) -> (bool, TransactionHash) {
    match transactions.len() {
        0 => (false, [0; 32]),
        1 => {
            let hash = transactions[0].hash();
            (
                proof
                    .first()
                    .map(|leaf| hash.eq(&leaf.hash))
                    .unwrap_or_default(),
                hash,
            )
        }
        _ => {
            let mut hasher = Blake2s256::new();
            let (a, b) = transactions.split_at(transactions.len().div_euclid(2));
            let ((found_a, merkle_root_a), (found_b, merkle_root_b)) =
                (merkle_root(a, proof), merkle_root(b, proof));
            hasher.update(&merkle_root_a);
            hasher.update(&merkle_root_b);
            if found_a {
                proof.push(Leaf::new_with_dir(merkle_root_b, Direction::Right));
            } else if found_b {
                proof.push(Leaf::new_with_dir(merkle_root_a, Direction::Left));
            }
            let hash = hasher.finalize().into();
            (found_a || found_b, hash)
        }
    }
}

/// Verify a proof of inclusion for a given root hash and proof.
fn verify_proof(root: &Hash, proof: &[Leaf]) -> Option<()> {
    let calculated_root = proof
        .iter()
        .copied()
        .reduce(|leaf_a, leaf_b| {
            let mut hasher = Blake2s256::new();
            match leaf_b.dir {
                Some(Direction::Right) => {
                    hasher.update(leaf_a.hash);
                    hasher.update(leaf_b.hash);
                }
                Some(Direction::Left) => {
                    hasher.update(leaf_b.hash);
                    hasher.update(leaf_a.hash);
                }
                None => {}
            }
            Leaf::new(hasher.finalize().into())
        })
        .map(|leaf| leaf.hash)?;
    (calculated_root.eq(root)).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PublicKey,
        ledger::InMemoryIndexer,
        transaction::{Input, OutputId},
    };

    fn genesis_block(mask: [u8; 32]) -> Block {
        let prev_block_hash = [0; 32];
        let mut block = Block::new(0, prev_block_hash);
        block.transactions.push(Transaction::new(
            vec![],
            vec![Output::new_v0(calculate_reward(&mask), &mask, &[0; 32])],
        ));
        block
    }

    fn mining_transaction(new_supply: u64, tx_hash: Hash, public_key: PublicKey) -> Transaction {
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

    fn new_indexer(public_key: PublicKey) -> (InMemoryIndexer, Transaction) {
        let mut indexer = InMemoryIndexer::new();
        let genesis_block = genesis_block([0; 32]);
        let new_supply = genesis_block.transactions[0].outputs[0].amount;
        let prev_tx_hash = genesis_block.transactions[0].hash();
        let mining_transaction = mining_transaction(new_supply, prev_tx_hash, public_key);
        indexer.add_block(&genesis_block).unwrap();
        (indexer, mining_transaction)
    }

    #[test]
    fn test_merkle_proof() {
        use crate::transaction::Transaction;

        // Create 5 dummy transactions
        let transactions: Vec<Transaction> = (0..10)
            .map(|i| Transaction::new(vec![], vec![Output::new_v1(i, &[0; 32], &[0; 32])]))
            .collect();

        // Hash one of the transactions (e.g., the third one)
        let tx_hash_n = transactions[2].hash();
        println!("tx_hash_n: {}", hex::encode(tx_hash_n));

        // Prepare the proof vector
        let mut proof = vec![Leaf::new(tx_hash_n)];

        // Call the merkle_proof function
        let (found, merkle_root) = merkle_root(&transactions, &mut proof);

        assert!(found, "Transaction not found in the merkle tree");

        // Verify the proof
        verify_proof(&merkle_root, &proof).unwrap();
    }

    #[test]
    fn test_block_with_invalid_prev_block_hash() {
        let (indexer, mining_transaction) = new_indexer([0; 32]);

        let mut block = Block::new(1, [1; 32]); // Invalid prev_block_hash
        block.transactions.push(mining_transaction);

        let result = block.verify(&indexer);
        match result {
            Err(BlockError::InvalidBlockHash(_)) => (),
            e => panic!("Expected BlockError::InvalidBlockHash, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_invalid_challenge() {
        let mut indexer = InMemoryIndexer::new();
        let genesis_block = genesis_block([1; 32]);
        let genesis_block_hash = genesis_block.header().hash();
        let first_tx_hash = genesis_block.transactions[0].hash();
        indexer.add_block(&genesis_block).unwrap();

        let mut block = Block::new(1, genesis_block_hash);
        let transaction = mining_transaction(1, first_tx_hash, [0; 32]);
        block.transactions.push(transaction); // Invalid challenge

        let result = block.verify(&indexer);
        assert_eq!(result, Err(BlockError::ChallengeError));
    }

    #[test]
    fn test_block_with_valid_challenge() {
        let mut indexer = InMemoryIndexer::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash();
        indexer.add_block(&genesis_block).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash());
        let transaction = mining_transaction(1, first_tx_hash, [1; 32]);
        block.transactions.push(transaction);

        let result = block.verify(&indexer);
        match result {
            Ok(()) | Err(BlockError::TransactionError(_)) => (),
            e => panic!("Expected Ok or BlockError::TransactionError, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_reward_above_max_reward() {
        let mut indexer = InMemoryIndexer::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash();
        indexer.add_block(&genesis_block).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash());
        let transaction = mining_transaction(2, first_tx_hash, [1; 32]);
        block.transactions.push(transaction);

        let result = block.verify(&indexer);
        match result {
            Err(BlockError::SupplyError { .. }) => (),
            e => panic!("Expected BlockError::RewardError, got {:?}", e),
        }
    }

    #[test]
    fn test_block_with_invalid_lead_utxo_version() {
        let mut indexer = InMemoryIndexer::new();
        let genesis_block = genesis_block([0; 32]);
        let first_tx_hash = genesis_block.transactions[0].hash();
        indexer.add_block(&genesis_block).unwrap();

        let mut block = Block::new(1, genesis_block.header().hash());
        let mut transaction = mining_transaction(1, first_tx_hash, [1; 32]);
        transaction.outputs[0].version = crate::transaction::Version::V1; // Invalid version
        block.transactions.push(transaction);

        let result = block.verify(&indexer);
        match result {
            Err(BlockError::InvalidVersion(_)) => (),
            e => panic!("Expected BlockError::InvalidVersion, got {:?}", e),
        }
    }

    #[test]
    fn test_block_header_hash() {
        let block = genesis_block([0; 32]);
        let header = block.header();
        let hash = header.hash();

        // Ensure the hash is not empty and has the expected length
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0; 32]);

        // Verify that the hash changes if the header changes
        let mut modified_header = header.clone();
        modified_header.version = 89;
        let modified_hash = modified_header.hash();
        assert_ne!(hash, modified_hash);
    }
}
