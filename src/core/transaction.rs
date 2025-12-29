use super::vm::{ExecError, Vm, check_sig_script, p2pk_script};
use super::{Hash, PublicKey, Version, commit, ledger::Ledger};
use super::{Signature, VirtualSize, calculate_reward};
use blake2::{Blake2s256, Digest};
use std::error;
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutputId {
    pub tx_hash: TransactionHash,
    pub index: u8,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Input {
    pub output_id: OutputId,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Output {
    pub version: Version,
    pub amount: u32,
    pub data: Hash,
    pub commitment: Hash,
}

pub type TransactionHash = Hash;

#[derive(Debug, Clone)]
pub enum TransactionError {
    /// The referenced transaction was not found in the ledger.
    InvalidInput { txid: Hash },

    /// The referenced output (UTXO) was not found in the given transaction.
    InvalidOutput(OutputId),

    /// Execution error occurred during transaction validation.
    Execution(ExecError),

    /// Total outputs exceed total inputs.
    InsufficientInputAmount { total_input: u32, total_output: u32 },

    /// Specific coinbase (mint) validation failed (mask/amount rules).
    CoinbaseValidation { reason: String },

    /// Number of inputs exceeds maximum allowed.
    TooManyInputs(usize),
    /// Number of outputs exceeds maximum allowed.
    TooManyOutputs(usize),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TransactionError::*;
        match self {
            InvalidInput { txid } => write!(f, "Invalid input: referenced txid {:02x?}", txid),
            InvalidOutput(OutputId { tx_hash, index }) => write!(
                f,
                "Invalid output: referenced txid {:02x?} index {}",
                tx_hash, index
            ),
            Execution(err) => err.fmt(f),
            InsufficientInputAmount {
                total_input,
                total_output,
            } => write!(
                f,
                "Insufficient input amount: inputs={} outputs={}",
                total_input, total_output
            ),
            CoinbaseValidation { reason } => write!(f, "Coinbase validation failed: {}", reason),
            TooManyInputs(max_allowed) => {
                write!(f, "Too many inputs: maximum allowed is {}", max_allowed)
            }
            TooManyOutputs(max_allowed) => {
                write!(f, "Too many outputs: maximum allowed is {}", max_allowed)
            }
        }
    }
}

impl error::Error for TransactionError {}

impl VirtualSize for Input {
    fn vsize(&self) -> usize {
        // the pk and sig can be pruned after validation
        let witness_len = self.public_key.len() + self.signature.len();
        self.output_id.vsize() + witness_len / 2
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Input")
            .field("output_id", &self.output_id)
            .field("signature", &hex::encode(&self.signature))
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

impl VirtualSize for OutputId {
    fn vsize(&self) -> usize {
        1 + self.tx_hash.len()
    }
}

impl fmt::Debug for OutputId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputId")
            .field("tx_hash", &hex::encode(&self.tx_hash))
            .field("index", &self.index)
            .finish()
    }
}

impl VirtualSize for Output {
    fn vsize(&self) -> usize {
        let size = 1 + std::mem::size_of::<u64>() + self.data.len() + self.commitment.len();
        if self.amount > 0 { size } else { size / 2 } // 0 amount outputs can be pruned after validation
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("version", &self.version)
            .field("amount", &self.amount)
            .field("data", &hex::encode(&self.data))
            .field("commitment", &hex::encode(&self.commitment))
            .finish()
    }
}

impl OutputId {
    pub fn new(tx_hash: TransactionHash, index: u8) -> Self {
        Self { tx_hash, index }
    }
}

impl Ord for OutputId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.tx_hash.cmp(&other.tx_hash) {
            std::cmp::Ordering::Equal => self.index.cmp(&other.index),
            other => other,
        }
    }
}

impl PartialOrd for OutputId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .finish()
    }
}

impl VirtualSize for Transaction {
    fn vsize(&self) -> usize {
        self.inputs.iter().map(|input| input.vsize()).sum::<usize>()
            + self
                .outputs
                .iter()
                .map(|output| output.vsize())
                .sum::<usize>()
    }
}

impl Transaction {
    /// Creates a new transaction.
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Self { inputs, outputs }
    }

    /// Calculates the hash of the transaction.
    pub fn hash<D: Digest>(&self) -> TransactionHash {
        let mut hasher = D::new();
        hasher.update(&self.inputs.len().to_be_bytes());
        for input in &self.inputs {
            hasher.update(&input.output_id.tx_hash);
            hasher.update(&input.output_id.index.to_be_bytes());
            hasher.update(&input.signature);
            hasher.update(&input.public_key);
        }
        hasher.update(&self.outputs.len().to_be_bytes());
        for output in &self.outputs {
            hasher.update(&[output.version as u8]);
            hasher.update(&output.amount.to_be_bytes());
            hasher.update(&output.data);
            hasher.update(&output.commitment);
        }

        hasher.finalize().as_ref().try_into().unwrap()
    }

    /// Verifies the transaction against the ledger.
    pub fn verify<L: Ledger>(&self, ledger: &L) -> Result<(), TransactionError> {
        let mut total_input_amount = 0_u32;
        let max_allowed = u8::MAX as usize;
        let is_genesis = ledger.get_last_block_metadata().is_none();

        if self.inputs.len() > max_allowed {
            return Err(TransactionError::TooManyInputs(max_allowed));
        }
        if self.outputs.len() > max_allowed {
            return Err(TransactionError::TooManyOutputs(max_allowed));
        }

        for (i, input) in self.inputs.iter().enumerate() {
            let vm = Vm::new(ledger, &input, &self.outputs);
            // Lookup referenced utxo
            let utxo = ledger
                .get_utxo(&input.output_id)
                .ok_or(TransactionError::InvalidInput {
                    txid: input.output_id.tx_hash,
                })?;
            total_input_amount = total_input_amount.saturating_add(utxo.amount);

            // Coinbase (mint) specific validation: input index 0 is the lead/mint UTXO
            //
            // ERROR
            // THIS VALIDATION SHOULD BE IN BLOCK BECAUSE THE TRANSACTION DOES NOT KNOW ITS INDEX
            if i < 1 {
                let mask = &utxo.commitment;
                let max_reward = calculate_reward(mask);
                let new_supply = self.outputs.get(0).map(|o| o.amount).unwrap_or_default();
                // Check if the public key matches the mask of the commitment
                if !super::matches_mask(mask, &input.public_key) {
                    return Err(TransactionError::CoinbaseValidation {
                        reason: "public key does not satisfy mint mask".into(),
                    });
                // The new output must have at least the previous amount minus MAX_MINT_AMOUNT.
                } else if new_supply < utxo.amount.saturating_sub(max_reward) {
                    return Err(TransactionError::CoinbaseValidation {
                        reason: format!(
                            "new supply too small: got {}, required >= {}",
                            new_supply,
                            utxo.amount.saturating_sub(max_reward)
                        ),
                    });
                }

                // We also check the signature of the coinbase transaction
                vm.run(&check_sig_script())
                    .map_err(|err| TransactionError::Execution(err))?;
            } else {
                match utxo.version {
                    Version::V1 => {
                        // V1 transactions use a simple P2PK script
                        vm.run(&p2pk_script())
                            .map_err(|err| TransactionError::Execution(err))?;
                    }
                    Version::V2 => {
                        // V2 transactions can use a more complex script
                        vm.run(&utxo.data)
                            .map_err(|err| TransactionError::Execution(err))?;
                    }
                }
            }
        }

        let total_output_amount = self.outputs.iter().map(|output| output.amount).sum();
        if !is_genesis && total_output_amount > total_input_amount {
            return Err(TransactionError::InsufficientInputAmount {
                total_input: total_input_amount,
                total_output: total_output_amount,
            });
        }
        Ok(())
    }
}

impl Output {
    pub fn new_v1(amount: u32, public_key: &PublicKey, data: &Hash) -> Self {
        let commitment = commit::<Blake2s256>(public_key, data);
        Self {
            version: Version::V1,
            amount,
            data: *data,
            commitment,
        }
    }

    pub fn new_v2(amount: u32, public_key: &PublicKey, script: &Hash) -> Self {
        let commitment = commit::<Blake2s256>(public_key, script);
        Self {
            version: Version::V2,
            amount,
            data: *script,
            commitment,
        }
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        commit::<Blake2s256>(public_key, &self.data) == self.commitment
    }
}

/// Create the sighash for a transaction input
pub fn sighash<'a, D, I>(mut hasher: D, output_id: &'a OutputId, outputs: I) -> Hash
where
    D: Digest,
    I: Iterator<Item = Output>,
{
    hasher.update(&output_id.tx_hash);
    hasher.update(&output_id.index.to_be_bytes());
    for Output {
        version,
        amount,
        data,
        commitment,
    } in outputs
    {
        hasher.update(&[version as u8]);
        hasher.update(&amount.to_be_bytes());
        hasher.update(&data);
        hasher.update(&commitment);
    }
    hasher.finalize().as_slice().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::core::{
        block::Block,
        ledger::{InMemoryLedger, Ledger},
    };
    use blake2::Blake2s256;
    use ed25519_dalek::Signer;

    #[test]
    fn test_output_verify_true_and_false() {
        // Setup a public key and data_hash
        let pk: [u8; 32] = [1u8; 32];
        let data: [u8; 32] = [2u8; 32];

        // Compute commitment via create_commitment and construct Output
        let output = Output::new_v1(42, &pk, &data);

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
            tx_hash: txid,
            index: 1,
        };

        let pk = [1u8; 32];
        let out1 = Output::new_v1(10, &pk, &[4u8; 32]);
        let out2 = Output::new_v1(20, &pk, &[6u8; 32]);
        let outputs = vec![out1, out2];

        // Compute sighash via function
        let s1 = sighash(Blake2s256::new(), &output_id, outputs.iter().copied());

        // Compute expected via manual hasher
        let mut hasher = Blake2s256::new();
        hasher.update(&txid);
        hasher.update(&output_id.index.to_be_bytes());
        for o in &outputs {
            hasher.update(&[o.version as u8]);
            hasher.update(&o.amount.to_be_bytes());
            hasher.update(&o.data);
            hasher.update(&o.commitment);
        }
        let expected: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        assert_eq!(s1, expected);
    }

    #[test]
    fn test_transaction_hash() {
        // Build a transaction with one input and one output
        let input = Input {
            output_id: OutputId {
                tx_hash: [1u8; 32],
                index: 0,
            },
            signature: [0; 64],
            public_key: [2u8; 32],
        };
        let output = Output::new_v1(10, &[0; 32], &[3u8; 32]);
        let tx = Transaction {
            inputs: vec![input.clone()],
            outputs: vec![output.clone()],
        };

        let tx_hash = tx.hash::<Blake2s256>();

        // Manual hash
        let mut hasher = Blake2s256::new();
        hasher.update(&tx.inputs.len().to_be_bytes());
        for inp in &tx.inputs {
            hasher.update(&inp.output_id.tx_hash);
            hasher.update(&inp.output_id.index.to_be_bytes());
            hasher.update(&inp.signature);
            hasher.update(&inp.public_key);
        }
        hasher.update(&tx.outputs.len().to_be_bytes());
        for out in &tx.outputs {
            hasher.update(&[out.version as u8]);
            hasher.update(&out.amount.to_be_bytes());
            hasher.update(&out.data);
            hasher.update(&out.commitment);
        }
        let expected: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        assert_eq!(tx_hash, expected);
    }

    #[test]
    fn test_transaction_verify_invalid_public_key() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: 100,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let input = Input {
            output_id: OutputId {
                tx_hash: funding_txid,
                index: 0,
            },
            signature: [0; 64],
            public_key: [11u8; 32], // we use a random public key
        };

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: vec![Output {
                version: Version::V1,
                amount: 100 - reward,
                data: [0u8; 32],
                commitment: [0u8; 32],
            }],
        };

        // Now verification should fail parsing the funding output's commitment as a public key
        match spending_tx.verify(&ledger) {
            Err(TransactionError::Execution(ExecError::VerifyFailed)) => {}
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
            tx_hash: txid,
            index: 1,
        };

        let outputs = vec![Output::new_v1(10, &public_key, &[5u8; 32])];

        // Compute the sighash
        let sighash = sighash(Blake2s256::new(), &output_id, outputs.iter().copied());

        // Sign the sighash
        let signature = signing_key.sign(&sighash);

        // Verify the signature using the public key
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        assert!(verifying_key.verify_strict(&sighash, &signature).is_ok());
    }

    #[test]
    fn test_transaction_verify_invalid_input_output_totals() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: 100,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output::new_v1(150, &mask, &data)]; // Any commitment will work with the mask chosen before
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter().copied());
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input {
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
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
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: 2 * reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output {
            version: Version::V1,
            amount: reward,
            data,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter().copied());
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input {
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
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
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [1u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: 2 * reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output {
            version: Version::V1,
            amount: 1,
            data,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter().copied());
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input {
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&ledger) {
            Err(TransactionError::CoinbaseValidation { .. }) => {}
            other => panic!("Expected CoinbaseValidation, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_v2() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let mut data = [0u8; 32];
        data.as_mut_slice().write(&p2pk_script()).unwrap();
        let mask = [0u8; 32]; // A zero mask allows for any pubkey
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V2,
                amount: 2 * reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let new_outputs = vec![Output::new_v1(reward, &mask, &data)];
        let sighash = sighash(Blake2s256::new(), &utxo_id, new_outputs.iter().copied());
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input {
            output_id: utxo_id,
            signature,
            public_key: signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
        };

        let spending_tx = Transaction {
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
    fn test_transaction_verify_too_many_inputs() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Generate inputs exceeding the maximum allowed
        let max_allowed = u8::MAX as usize;
        let mut inputs = Vec::new();
        for i in 0..=max_allowed {
            let utxo_id = OutputId {
                tx_hash: funding_txid,
                index: i as u8,
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
            let sighash = sighash(Blake2s256::new(), &utxo_id, [].iter().copied());
            let signature = signing_key.sign(&sighash).to_bytes();
            inputs.push(Input {
                output_id: utxo_id,
                signature,
                public_key: signing_key.verifying_key().to_bytes(),
            });
        }

        let spending_tx = Transaction {
            inputs,
            outputs: vec![Output {
                version: Version::V1,
                amount: reward,
                data,
                commitment: mask,
            }],
        };

        // Now verification should fail due to too many inputs
        match spending_tx.verify(&ledger) {
            Err(TransactionError::TooManyInputs(max)) if max == max_allowed => {}
            other => panic!("Expected TooManyInputs error, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_too_many_outputs() {
        // Create a ledger with one block containing a funding transaction
        let mut ledger = InMemoryLedger::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V1,
                amount: reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash::<Blake2s256>();

        // Create a block containing the funding transaction and add to ledger
        let mut block = Block::new(crate::core::Version::V1, [0u8; 32]);
        block.transactions.push(funding_tx);
        ledger.add_block(block).unwrap();

        // Generate outputs exceeding the maximum allowed
        let max_allowed = u8::MAX as usize;
        let outputs: Vec<Output> = (0..=max_allowed)
            .map(|_| Output {
                version: Version::V1,
                amount: reward,
                data,
                commitment: mask,
            })
            .collect();

        let spending_tx = Transaction {
            inputs: vec![Input {
                output_id: OutputId {
                    tx_hash: funding_txid,
                    index: 0,
                },
                signature: [0; 64],
                public_key: [11u8; 32],
            }],
            outputs,
        };

        // Now verification should fail due to too many outputs
        match spending_tx.verify(&ledger) {
            Err(TransactionError::TooManyOutputs(max)) if max == max_allowed => {}
            other => panic!("Expected TooManyOutputs error, got: {:?}", other),
        }
    }
}
