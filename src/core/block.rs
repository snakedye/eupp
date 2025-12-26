use super::{
    Hash, Version,
    ledger::Ledger,
    transaction::{Output, Transaction, TransactionHash},
};
use blake2::{Blake2s256, Digest};

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub version: Version,
    pub prev_block_hash: Hash,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: Version,
    pub prev_block_hash: Hash,
    pub merkle_root: Hash,
}

#[derive(Debug, Clone)]
/// Represents errors that can occur when validating blocks.
pub enum BlockError {
    InvalidBlockHash(String),
    TransactionError(super::transaction::TransactionError),
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
    pub fn new(version: Version, prev_block_hash: Hash) -> Self {
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
        //
        // Otherwise this block is the genesis block and we don't need to verify it
        if ledger.get_last_block_metadata().is_some() {
            let previous_block = ledger.get_block_metadata(&self.prev_block_hash).ok_or(
                BlockError::InvalidBlockHash(format!(
                    "Previous block hash not found: {}",
                    hex::encode(&self.prev_block_hash)
                )),
            )?;

            if previous_block.hash != self.header().prev_block_hash {
                return Err(BlockError::InvalidBlockHash(
                    "Previous block hash mismatch".to_string(),
                ));
            }
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
