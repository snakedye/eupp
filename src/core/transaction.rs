use super::calculate_reward;
use super::{Hash, PublicKey, Version, create_commitment, ledger::Ledger};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: Version,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

pub type TransactionHash = Hash;

#[derive(Debug)]
pub enum TransactionError {
    /// The referenced transaction was not found in the ledger.
    InvalidInput { txid: Hash },

    /// The referenced output (UTXO) was not found in the given transaction.
    InvalidOutput { txid: Hash, index: usize },

    /// A signature could not be parsed or did not verify.
    InvalidSignature { reason: String },

    /// A public key could not be parsed or otherwise failed validation.
    InvalidPublicKey { reason: String },

    /// Total outputs exceed total inputs.
    InsufficientInputAmount { total_input: u64, total_output: u64 },

    /// Specific coinbase (mint) validation failed (mask/amount rules).
    CoinbaseValidation { reason: String },
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TransactionError::*;
        match self {
            InvalidInput { txid } => write!(f, "Invalid input: referenced txid {:02x?}", txid),
            InvalidOutput { txid, index } => write!(
                f,
                "Invalid output: referenced txid {:02x?} index {}",
                txid, index
            ),
            InvalidSignature { reason } => write!(f, "Invalid signature: {}", reason),
            InvalidPublicKey { reason } => write!(f, "Invalid public key: {}", reason),
            InsufficientInputAmount {
                total_input,
                total_output,
            } => write!(
                f,
                "Insufficient input amount: inputs={} outputs={}",
                total_input, total_output
            ),
            CoinbaseValidation { reason } => write!(f, "Coinbase validation failed: {}", reason),
        }
    }
}

impl error::Error for TransactionError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub version: Version,
    pub output_id: OutputId,
    pub signature: Vec<u8>,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputId {
    pub transaction_id: TransactionHash,
    pub output_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub amount: u64,
    pub data_hash: Hash,
    pub commitment: Hash,
}

impl Transaction {
    /// Creates a new transaction.
    pub fn new(version: Version, inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Self {
            version,
            inputs,
            outputs,
        }
    }

    /// Calculates the hash of the transaction.
    pub fn hash<D: Digest>(&self) -> TransactionHash {
        let mut hasher = D::new();
        hasher.update(&[self.version as u8]);
        hasher.update(&self.inputs.len().to_le_bytes());
        for input in &self.inputs {
            hasher.update(&[input.version as u8]);
            hasher.update(&input.output_id.transaction_id);
            hasher.update(&input.output_id.output_index.to_le_bytes());
            hasher.update(&input.signature);
            hasher.update(&input.public_key);
        }
        hasher.update(&self.outputs.len().to_le_bytes());
        for output in &self.outputs {
            hasher.update(&output.amount.to_le_bytes());
            hasher.update(&output.data_hash);
            hasher.update(&output.commitment);
        }

        hasher.finalize().as_ref().try_into().unwrap()
    }

    /// Verifies the transaction against the ledger.
    pub fn verify(&self, ledger: &Ledger) -> Result<(), TransactionError> {
        let mut total_input_amount: u64 = 0;
        for (i, input) in self.inputs.iter().enumerate() {
            // Lookup referenced transaction
            let tx = ledger
                .get_transaction(&input.output_id.transaction_id)
                .ok_or(TransactionError::InvalidInput {
                    txid: input.output_id.transaction_id,
                })?;

            // Lookup referenced utxo within that transaction
            let utxo = tx.outputs.get(input.output_id.output_index).ok_or(
                TransactionError::InvalidOutput {
                    txid: input.output_id.transaction_id,
                    index: input.output_id.output_index,
                },
            )?;
            total_input_amount = total_input_amount.saturating_add(utxo.amount);

            // Coinbase (mint) specific validation: input index 0 is the lead/mint UTXO
            if i < 1 {
                let mask = &utxo.commitment;
                let max_reward = calculate_reward(mask);
                // Check if the public key matches the mask of the commitment
                if !super::matches_mask(mask, &input.public_key) {
                    return Err(TransactionError::CoinbaseValidation {
                        reason: "public key does not satisfy mint mask".into(),
                    });
                // The new output must have at least the previous amount minus MAX_MINT_AMOUNT.
                } else if self.outputs.get(0).map(|o| o.amount)
                    < Some(utxo.amount.saturating_sub(max_reward))
                {
                    return Err(TransactionError::CoinbaseValidation {
                        reason: format!(
                            "coinbase output too small: got {}, required >= {}",
                            self.outputs.get(0).map(|o| o.amount).unwrap_or(0),
                            utxo.amount.saturating_sub(max_reward)
                        ),
                    });
                }
            // Regular transactions
            } else {
                // Regular UTXO verification: commitment must match provided public key
                if !utxo.verify(&input.public_key) {
                    return Err(TransactionError::InvalidOutput {
                        txid: input.output_id.transaction_id,
                        index: input.output_id.output_index,
                    });
                }
            }

            // Compute sighash and validate signature
            let msg = sighash(Blake2s256::new(), &input.output_id, self.outputs.iter());
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&input.public_key)
                .map_err(|e| TransactionError::InvalidPublicKey {
                    reason: format!("{:?}", e),
                })?;
            let signature =
                ed25519_dalek::Signature::from_slice(&input.signature).map_err(|e| {
                    TransactionError::InvalidSignature {
                        reason: format!("{:?}", e),
                    }
                })?;
            verifying_key.verify_strict(&msg, &signature).map_err(|e| {
                TransactionError::InvalidSignature {
                    reason: format!("{:?}", e),
                }
            })?;
        }

        let total_output_amount: u64 = self.outputs.iter().map(|output| output.amount).sum();
        if total_output_amount > total_input_amount {
            return Err(TransactionError::InsufficientInputAmount {
                total_input: total_input_amount,
                total_output: total_output_amount,
            });
        }
        Ok(())
    }
}

impl Output {
    pub fn new_with_pk(amount: u64, public_key: &PublicKey, data_hash: Hash) -> Self {
        let commitment = create_commitment::<Blake2s256>(public_key, &data_hash);
        Self {
            amount,
            data_hash,
            commitment,
        }
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        create_commitment::<Blake2s256>(public_key, &self.data_hash) == self.commitment
    }
}

/// Create the sighash for a transaction input
pub fn sighash<'a, D, I>(mut hasher: D, output_id: &'a OutputId, outputs: I) -> Hash
where
    D: Digest,
    I: Iterator<Item = &'a Output>,
{
    hasher.update(&output_id.transaction_id);
    hasher.update(&output_id.output_index.to_le_bytes());
    for Output {
        amount: data,
        data_hash,
        commitment: public_key_hash,
    } in outputs
    {
        hasher.update(&data.to_le_bytes());
        hasher.update(&data_hash);
        hasher.update(&public_key_hash);
    }
    hasher.finalize().as_slice().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{block::Block, ledger::Ledger};
    use blake2::Blake2s256;
    use ed25519_dalek::Signer;

    #[test]
    fn test_output_verify_true_and_false() {
        // Setup a public key and data_hash
        let pk: [u8; 32] = [1u8; 32];
        let data_hash: [u8; 32] = [2u8; 32];

        // Compute commitment via create_commitment and construct Output
        let commitment = create_commitment::<Blake2s256>(&pk, &data_hash);
        let output = Output {
            amount: 42u64,
            data_hash,
            commitment,
        };

        // Should verify with the correct public key
        assert!(output.verify(&pk));

        // Different public key should fail
        let other_pk: [u8; 32] = [3u8; 32];
        assert!(!output.verify(&other_pk));
    }

    #[test]
    fn test_sighash_matches_manual_hash() {
        // Prepare a fake transaction id and outputs
        let txid: [u8; 32] = [9u8; 32];
        let output_id = OutputId {
            transaction_id: txid,
            output_index: 1usize,
        };

        let out1 = Output {
            amount: 10u64,
            data_hash: [4u8; 32],
            commitment: [5u8; 32],
        };
        let out2 = Output {
            amount: 20u64,
            data_hash: [6u8; 32],
            commitment: [7u8; 32],
        };
        let outputs = vec![out1, out2];

        // Compute sighash via function
        let s1 = sighash(Blake2s256::new(), &output_id, outputs.iter());

        // Compute expected via manual hasher
        let mut hasher = Blake2s256::new();
        hasher.update(&txid);
        hasher.update(&output_id.output_index.to_le_bytes());
        for o in &outputs {
            hasher.update(&o.amount.to_le_bytes());
            hasher.update(&o.data_hash);
            hasher.update(&o.commitment);
        }
        let expected: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        assert_eq!(s1, expected);
    }

    #[test]
    fn test_transaction_hash() {
        // Build a transaction with one input and one output
        let input = Input {
            version: Version::V1,
            output_id: OutputId {
                transaction_id: [1u8; 32],
                output_index: 0,
            },
            signature: vec![],
            public_key: [2u8; 32],
        };
        let output = Output {
            amount: 10u64,
            data_hash: [3u8; 32],
            commitment: [4u8; 32],
        };
        let tx = Transaction {
            version: Version::V1,
            inputs: vec![input.clone()],
            outputs: vec![output.clone()],
        };

        let tx_hash = tx.hash::<Blake2s256>();

        // Manual hash
        let mut hasher = Blake2s256::new();
        hasher.update(&[tx.version as u8]);
        hasher.update(&tx.inputs.len().to_le_bytes());
        for inp in &tx.inputs {
            hasher.update(&[inp.version as u8]);
            hasher.update(&inp.output_id.transaction_id);
            hasher.update(&inp.output_id.output_index.to_le_bytes());
            hasher.update(&inp.signature);
            hasher.update(&inp.public_key);
        }
        hasher.update(&tx.outputs.len().to_le_bytes());
        for out in &tx.outputs {
            hasher.update(&out.amount.to_le_bytes());
            hasher.update(&out.data_hash);
            hasher.update(&out.commitment);
        }
        let expected: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        assert_eq!(tx_hash, expected);
    }

    #[test]
    fn test_transaction_verify_invalid_public_key() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = Ledger::new();

        // Build funding (previous) transaction that creates a UTXO
        let pk = [11u8; 32];
        let data_hash = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            version: Version::V1,
            inputs: vec![],
            outputs: vec![Output {
                amount: 100,
                data_hash,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block);

        // Now build a spending transaction that consumes the funding UTXO
        let input = Input {
            version: Version::V1,
            output_id: OutputId {
                transaction_id: funding_txid,
                output_index: 0,
            },
            signature: vec![],
            public_key: pk, // same public key used to construct commitment
        };

        let spending_tx = Transaction {
            version: Version::V1,
            inputs: vec![input],
            outputs: vec![Output {
                amount: 100 - reward,
                data_hash: [0u8; 32],
                commitment: [0u8; 32],
            }],
        };

        // Now verification should fail parsing the funding output's commitment as a public key
        match spending_tx.verify(&ledger) {
            Err(TransactionError::InvalidSignature { .. }) => {}
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[test]
    fn test_signed_sighash_verification() {
        // Create a signing key and derive the public key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        // Prepare a fake transaction id and outputs
        let txid: [u8; 32] = [9u8; 32];
        let output_id = OutputId {
            transaction_id: txid,
            output_index: 1usize,
        };

        let outputs = vec![Output {
            amount: 10u64,
            data_hash: [4u8; 32],
            commitment: [5u8; 32],
        }];

        // Compute the sighash
        let sighash = sighash(Blake2s256::new(), &output_id, outputs.iter());

        // Sign the sighash
        let signature = signing_key.sign(&sighash);

        // Verify the signature using the public key
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        assert!(verifying_key.verify_strict(&sighash, &signature).is_ok());
    }

    #[test]
    fn test_transaction_verify_invalid_input_output_totals() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = Ledger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data_hash = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];

        let funding_tx = Transaction {
            version: Version::V1,
            inputs: vec![],
            outputs: vec![Output {
                amount: 100u64,
                data_hash,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block);

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            transaction_id: funding_txid,
            output_index: 0,
        };
        let new_outputs = vec![Output {
            amount: 150,
            data_hash: data_hash,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter());
        let signature = signing_key.sign(&sighash).to_bytes().to_vec();
        let input = Input {
            version: Version::V1,
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
            version: Version::V1,
            inputs: vec![input],
            outputs: new_outputs,
        };

        // Now verification should fail due to mismatched input and output totals
        match spending_tx.verify(&ledger) {
            Err(TransactionError::InsufficientInputAmount { .. }) => {}
            other => panic!("Expected InsufficientInputAmount error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_valid_coinbase() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = Ledger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data_hash = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            version: Version::V1,
            inputs: vec![],
            outputs: vec![Output {
                amount: 2 * reward,
                data_hash,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block);

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            transaction_id: funding_txid,
            output_index: 0,
        };
        let new_outputs = vec![Output {
            amount: reward,
            data_hash: data_hash,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter());
        let signature = signing_key.sign(&sighash).to_bytes().to_vec();
        let input = Input {
            version: Version::V1,
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
            version: Version::V1,
            inputs: vec![input],
            outputs: new_outputs,
        };

        // Now verification should succeed
        match spending_tx.verify(&ledger) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_invalid_coinbase() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = Ledger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data_hash = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [1u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            version: Version::V1,
            inputs: vec![],
            outputs: vec![Output {
                amount: 2 * reward,
                data_hash,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block);

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            transaction_id: funding_txid,
            output_index: 0,
        };
        let new_outputs = vec![Output {
            amount: 1,
            data_hash: data_hash,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter());
        let signature = signing_key.sign(&sighash).to_bytes().to_vec();
        let input = Input {
            version: Version::V1,
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
            version: Version::V1,
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&ledger) {
            Err(TransactionError::CoinbaseValidation { .. }) => {}
            other => panic!("Expected CoinbaseValidation, got: {:?}", other),
        }
    }
}
