use super::{
    Hash, Version,
    ledger::Ledger,
    transaction::{Transaction, TransactionHash},
};
use blake2::{Blake2s256, Digest};

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub version: Version,
    pub previous_block_hash: Hash,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: Version,
    pub previous_block_hash: Hash,
    pub merkle_root: Hash,
}

impl BlockHeader {
    pub fn hash<T: Digest>(&self) -> Hash {
        let mut buf = [0u8; 32];
        let mut hasher = T::new();

        Digest::update(&mut hasher, &[self.version as u8]);
        Digest::update(&mut hasher, &self.previous_block_hash);
        Digest::update(&mut hasher, &self.merkle_root);

        buf.as_mut().copy_from_slice(hasher.finalize().as_ref());
        buf
    }
}

impl Block {
    pub fn new(version: Version, previous_block_hash: Hash) -> Self {
        Self {
            version,
            previous_block_hash,
            transactions: Vec::new(),
        }
    }

    /// Returns the header of the block.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: self.version,
            previous_block_hash: self.previous_block_hash,
            merkle_root: self.merkle_root(),
        }
    }

    pub fn verify(&self, ledger: &Ledger) -> Result<(), super::transaction::TransactionError> {
        if ledger
            .get_block(&self.previous_block_hash)
            .ok_or(super::transaction::TransactionError::InvalidPreviousBlockHash)?
            .header()
            .hash::<Blake2s256>()
            == self.header().previous_block_hash
        {
            self.transactions
                .iter()
                .try_for_each(|tx| tx.verify(ledger))
        } else {
            Err(super::transaction::TransactionError::InvalidPreviousBlockHash)
        }
    }

    /// Returns the merkle root of the transactions in the block.
    fn merkle_root(&self) -> TransactionHash {
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
