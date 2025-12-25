use super::{ledger::Ledger, transaction::Transaction};
use blake2::{Blake2s256, Digest};
use sha2::digest::FixedOutputReset;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    V1 = 0,
}

pub struct Block {
    pub version: Version,
    pub previous_block_hash: [u8; 32],
    pub timestamp: usize,
    pub transactions: Vec<Transaction>,
}

pub struct BlockHeader {
    pub version: Version,
    pub previous_block_hash: [u8; 32],
    pub timestamp: usize,
    pub merkle_root: [u8; 32],
}

impl BlockHeader {
    fn hash<T: Digest>(&self, mut hasher: T) -> [u8; 32] {
        let mut buf = [0u8; 32];

        Digest::update(&mut hasher, &[self.version as u8]);
        Digest::update(&mut hasher, &self.previous_block_hash);
        Digest::update(&mut hasher, &self.timestamp.to_be_bytes());
        Digest::update(&mut hasher, &self.merkle_root);

        buf.as_mut().copy_from_slice(hasher.finalize().as_ref());
        buf
    }
}

impl Block {
    pub fn new(version: Version, previous_block_hash: [u8; 32], timestamp: usize) -> Self {
        Self {
            version,
            previous_block_hash,
            timestamp,
            transactions: Vec::new(),
        }
    }

    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: self.version,
            previous_block_hash: self.previous_block_hash,
            timestamp: self.timestamp,
            merkle_root: self.merkle_root(),
        }
    }

    pub fn verify(&self, ledger: &Ledger) -> Option<()> {
        let block = ledger.get_block(self.timestamp.saturating_sub(1))?;
        if block.header().hash(Blake2s256::new()) == self.header().previous_block_hash {
            self.transactions
                .iter()
                .try_for_each(|tx| tx.verify(ledger))
                .ok()
        } else {
            None
        }
    }

    fn merkle_root(&self) -> [u8; 32] {
        merkle_root(&mut Blake2s256::new(), &self.transactions)
    }
}

// This is a non-standard implementation of the Merkle root algorithm.
fn merkle_root<D>(hasher: &mut D, transactions: &[Transaction]) -> [u8; 32]
where
    D: Digest + FixedOutputReset,
{
    let mut buf = [0u8; 32];
    match transactions.len() {
        0 => {}
        1 => buf = transactions[0].hash(hasher).unwrap(),
        _ => {
            let (a, b) = transactions.split_at(transactions.len() / 2);
            let (merkle_root_a, merkle_root_b) = (merkle_root(hasher, a), merkle_root(hasher, b));
            Digest::update(hasher, &merkle_root_a);
            Digest::update(hasher, &merkle_root_b);
            buf.copy_from_slice(hasher.finalize_reset().as_ref());
        }
    }
    buf
}
