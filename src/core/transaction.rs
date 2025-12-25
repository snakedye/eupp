use super::{Hash, PublicKey, hash_pubkey, ledger::Ledger};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutputReset;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u8,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

pub type TransactionId = Hash;

pub enum TransactionError {
    InvalidInput,
    InvalidOutput,
    InvalidSignature,
    InvalidPublicKey,
}

impl Transaction {
    pub fn hash<D: Digest + FixedOutputReset>(&self, hasher: &mut D) -> Option<[u8; 32]> {
        Digest::update(hasher, &self.version.to_le_bytes());
        Digest::update(hasher, &self.inputs.len().to_le_bytes());
        for input in &self.inputs {
            Digest::update(hasher, &input.version.to_le_bytes());
            Digest::update(hasher, &input.output_id.transaction_id);
            Digest::update(hasher, &input.output_id.output_index.to_le_bytes());
            Digest::update(hasher, &input.signature);
            Digest::update(hasher, &input.public_key);
        }
        Digest::update(hasher, &self.outputs.len().to_le_bytes());
        for output in &self.outputs {
            Digest::update(hasher, &output.data.to_le_bytes());
            Digest::update(hasher, &output.public_key_hash);
        }

        let mut buf = [0u8; 32];
        buf.copy_from_slice(hasher.finalize_reset().as_ref());
        Some(buf)
    }

    pub fn verify(&self, ledger: &Ledger) -> Result<(), TransactionError> {
        for input in &self.inputs {
            let tx = ledger
                .get_transaction(&input.output_id.transaction_id)
                .ok_or(TransactionError::InvalidInput)?;
            let msg = sighash(Blake2s256::new(), &input.output_id, self.outputs.iter());
            let output = tx
                .outputs
                .get(input.output_id.output_index)
                .ok_or(TransactionError::InvalidOutput)?;
            if !output.verify(&input.public_key) {
                return Err(TransactionError::InvalidOutput);
            }
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&output.public_key_hash)
                .map_err(|_| TransactionError::InvalidPublicKey)?;
            let signature = ed25519_dalek::Signature::from_slice(input.signature.as_bytes())
                .map_err(|_| TransactionError::InvalidSignature)?;
            verifying_key
                .verify_strict(&msg, &signature)
                .map_err(|_| TransactionError::InvalidSignature)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub version: u8,
    pub output_id: OutputId,
    pub signature: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputId {
    pub transaction_id: TransactionId,
    pub output_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub data: u64,
    pub public_key_hash: [u8; 32],
}

impl Output {
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        hash_pubkey::<Blake2s256>(public_key) == self.public_key_hash
    }
}

pub fn sighash<'a, I, D>(mut hasher: D, output_id: &OutputId, outputs: I) -> Hash
where
    D: Digest,
    I: Iterator<Item = &'a Output>,
{
    Digest::update(&mut hasher, &output_id.transaction_id);
    Digest::update(&mut hasher, &output_id.output_index.to_le_bytes());
    for Output {
        data,
        public_key_hash,
    } in outputs
    {
        Digest::update(&mut hasher, &data.to_le_bytes());
        Digest::update(&mut hasher, public_key_hash);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hasher.finalize().as_slice());
    buf
}
