use super::vm::{ExecError, Vm, check_sig_script, p2pkh, p2wsh};
use super::{Hash, PublicKey, commitment, ledger::Indexer};
use super::{Signature, VirtualSize};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::fmt;

pub type TransactionHash = Hash;

const MAX_WITNESS_SIZE: usize = 1024;
const MAX_ALLOWED: usize = u8::MAX as usize;

/// A blockchain transaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

/// An output identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputId {
    pub tx_hash: TransactionHash,
    pub index: u8,
}

/// A blockchain transaction input.
#[derive(Clone, PartialEq, Eq)]
pub struct Input {
    /// The id of the output being spent.
    pub(crate) output_id: OutputId,
    /// The public key used to verify the signature.
    pub(crate) public_key: PublicKey,
    /// Witness data for the input.
    pub(crate) witness: Vec<u8>,
    /// The signature signed by the private key linked to the public key.
    pub(crate) signature: Signature,
}

/// Protocol version used for outputs in the codebase.
///
/// Adding a short doc comment makes the intent explicit and makes the type
/// easier to discover when browsing the code or generated documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Exclusively for mining.
    V0 = 0,
    /// Initial protocol revision.
    V1 = 1,
    /// Second protocol revision.
    V2 = 2,
    /// Third protocol revision. Segwit support.
    V3 = 3,
}

/// A blockchain transaction output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Output {
    /// Protocol version used for the output.
    pub(crate) version: Version,
    /// Amount of the output.
    pub(crate) amount: u32,
    /// Data associated with the output.
    pub(crate) data: Hash,
    /// The hash of the public key.
    pub(crate) commitment: Hash,
}

/// Error type for transaction validation.
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionError {
    /// The referenced output (UTXO) was not found in the given transaction.
    InvalidOutput(OutputId),

    /// The referenced output (UTXO) was already spent.
    DoubleSpend(OutputId),

    /// Execution error occurred during transaction validation.
    Execution(ExecError),

    /// Total outputs exceed total inputs.
    InvalidBalance { total_input: u32, total_output: u32 },

    /// Witness script is too large.
    InvalidWitnessSize,

    /// Number of inputs exceeds maximum allowed.
    TooManyInputs,
    /// Number of outputs exceeds maximum allowed.
    TooManyOutputs,
}

impl VirtualSize for Input {
    fn vsize(&self) -> usize {
        // the pk and sig can be pruned after validation
        let witness_len = self.public_key.len() + self.signature.len() + self.witness.len();
        self.output_id.vsize() + witness_len / 2
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Input")
            .field("output_id", &self.output_id)
            .field("public_key", &hex::encode(&self.public_key))
            .field("witness", &hex::encode(&self.witness))
            .field("signature", &hex::encode(&self.signature))
            .finish()
    }
}

impl Input {
    pub fn new_unsigned(output_id: OutputId, public_key: PublicKey) -> Self {
        Self {
            output_id,
            signature: [0; 64],
            public_key,
            witness: vec![],
        }
    }
    pub fn new(output_id: OutputId, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            output_id,
            signature,
            public_key,
            witness: vec![],
        }
    }
    pub fn new_with_witness(
        output_id: OutputId,
        public_key: PublicKey,
        signature: Signature,
        witness: Vec<u8>,
    ) -> Self {
        Self {
            output_id,
            signature,
            public_key,
            witness,
        }
    }
    pub fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = signature;
        self
    }
}

impl<'de> serde::Deserialize<'de> for Input {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct InputHelper {
            output_id: OutputId,
            public_key: String,
            witness: String,
            signature: String,
        }

        let helper = InputHelper::deserialize(deserializer)?;
        let pubkey = hex::decode(helper.public_key).map_err(serde::de::Error::custom)?;
        let witness = hex::decode(helper.witness).map_err(serde::de::Error::custom)?;
        let signature = hex::decode(helper.signature).map_err(serde::de::Error::custom)?;

        Ok(Input {
            output_id: helper.output_id,
            public_key: PublicKey::try_from(pubkey.as_slice()).map_err(serde::de::Error::custom)?,
            witness,
            signature: Signature::try_from(signature.as_slice())
                .map_err(serde::de::Error::custom)?,
        })
    }
}

impl serde::Serialize for Input {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Input", 4)?;
        state.serialize_field("output_id", &self.output_id)?;
        state.serialize_field("public_key", &hex::encode(&self.public_key))?;
        state.serialize_field("witness", &hex::encode(&self.witness))?;
        state.serialize_field("signature", &hex::encode(&self.signature))?;
        state.end()
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

impl<'de> serde::Deserialize<'de> for Output {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct OutputHelper {
            version: u8,
            amount: u32,
            data: String,
            commitment: String,
        }

        let helper = OutputHelper::deserialize(deserializer)?;
        let data = hex::decode(helper.data).map_err(serde::de::Error::custom)?;
        let commitment = hex::decode(helper.commitment).map_err(serde::de::Error::custom)?;

        Ok(Output {
            version: match helper.version {
                0 => Version::V0,
                1 => Version::V1,
                2 => Version::V2,
                3 => Version::V3,
                _ => return Err(serde::de::Error::custom("Invalid version")),
            },
            amount: helper.amount,
            data: Hash::try_from(data.as_slice()).map_err(serde::de::Error::custom)?,
            commitment: Hash::try_from(commitment.as_slice()).map_err(serde::de::Error::custom)?,
        })
    }
}

impl serde::Serialize for Output {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Output", 4)?;
        state.serialize_field("version", &(self.version as u8))?;
        state.serialize_field("amount", &self.amount)?;
        state.serialize_field("data", &hex::encode(&self.data))?;
        state.serialize_field("commitment", &hex::encode(&self.commitment))?;
        state.end()
    }
}

impl Output {
    pub fn new_v0(amount: u32, mask: &Hash, nonce: &Hash) -> Self {
        Self {
            version: Version::V0,
            amount,
            data: *mask,        // The mask for the next challenge
            commitment: *nonce, // The solution for the previous challenge
        }
    }
    pub fn new_v1(amount: u32, public_key: &PublicKey, data: &Hash) -> Self {
        let commitment = commitment(public_key, Some(data.as_slice()));
        Self {
            version: Version::V1,
            amount,
            data: *data,
            commitment,
        }
    }

    pub fn new_v2(amount: u32, public_key: &PublicKey, script: &Hash) -> Self {
        let commitment = commitment(public_key, Some(script.as_slice()));
        Self {
            version: Version::V2,
            amount,
            data: *script,
            commitment,
        }
    }

    pub fn new_v3(
        amount: u32,
        public_key: &PublicKey,
        data: &[u8; 32],
        witness_script: &[u8],
    ) -> Self {
        let commitment = commitment(public_key, [data.as_slice(), witness_script]);
        Self {
            version: Version::V3,
            amount,
            data: *data,
            commitment,
        }
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
    pub fn hash(&self) -> TransactionHash {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.inputs.len().to_be_bytes());
        for input in &self.inputs {
            hasher.update(&input.output_id.tx_hash);
            hasher.update(&input.output_id.index.to_be_bytes());
            hasher.update(&input.witness);
            hasher.update(&input.public_key);
        }
        hasher.update(&self.outputs.len().to_be_bytes());
        for output in &self.outputs {
            hasher.update(&[output.version as u8]);
            hasher.update(&output.amount.to_be_bytes());
            hasher.update(&output.data);
            hasher.update(&output.commitment);
        }

        hasher.finalize().into()
    }

    /// Verifies the transaction against the indexer.
    pub fn verify<L: Indexer>(&self, indexer: &L) -> Result<(), TransactionError> {
        let mut total_input_amount = 0_u32;
        let is_genesis = indexer.get_last_block_metadata().is_none();

        if self.inputs.len() > MAX_ALLOWED {
            return Err(TransactionError::TooManyInputs);
        }
        if self.outputs.len() > MAX_ALLOWED {
            return Err(TransactionError::TooManyOutputs);
        }

        for (i, input) in self.inputs.iter().enumerate() {
            let vm = Vm::new(indexer, i, self);

            // Lookup referenced utxo
            let utxo = indexer
                .get_utxo(&input.output_id)
                .ok_or(TransactionError::InvalidOutput(input.output_id))?;
            total_input_amount = total_input_amount.saturating_add(utxo.amount);

            match utxo.version {
                Version::V0 => {
                    // For mining transactions, only the signature is checked
                    vm.run(&check_sig_script())
                        .map_err(TransactionError::Execution)?;
                }
                Version::V1 => {
                    // V1 transactions use a simple P2PK script
                    vm.run(&p2pkh()).map_err(TransactionError::Execution)?;
                }
                Version::V2 => {
                    // V2 transactions can use a more complex script
                    vm.run(&utxo.data).map_err(TransactionError::Execution)?;
                }
                Version::V3 => {
                    // V3 transactions support segwit
                    if input.witness.len() > MAX_WITNESS_SIZE {
                        return Err(TransactionError::InvalidWitnessSize);
                    }
                    vm.run(&p2wsh()).map_err(TransactionError::Execution)?;
                    vm.run(&input.witness)
                        .map_err(TransactionError::Execution)?;
                }
            }
        }

        let total_output_amount = self.outputs.iter().map(|output| output.amount).sum();
        if !is_genesis && total_output_amount > total_input_amount {
            return Err(TransactionError::InvalidBalance {
                total_input: total_input_amount,
                total_output: total_output_amount,
            });
        }
        Ok(())
    }
}

/// Create the sighash for a transaction input
pub fn sighash<'a>(
    inputs: impl IntoIterator<Item = &'a OutputId>,
    outputs: impl IntoIterator<Item = &'a Output>,
) -> Hash {
    let mut hasher = Blake2s256::new();
    // hasher.update(&inputs.len().to_be_bytes());
    for input in inputs {
        hasher.update(&input.tx_hash);
        hasher.update(&input.index.to_be_bytes());
    }
    // hasher.update(&outputs.len().to_be_bytes());
    for Output {
        version,
        amount,
        data,
        commitment,
    } in outputs
    {
        hasher.update(&[*version as u8]);
        hasher.update(&amount.to_be_bytes());
        hasher.update(&data);
        hasher.update(&commitment);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::{
        block::Block,
        calculate_reward,
        ledger::{InMemoryIndexer, Indexer},
        vm::p2pkh,
    };
    use blake2::Blake2s256;
    use ed25519_dalek::Signer;

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
        let s1 = sighash(&[output_id], &outputs);

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
        let input = Input::new(
            OutputId {
                tx_hash: [1u8; 32],
                index: 0,
            },
            [2u8; 32],
            [0; 64],
        );
        let output = Output::new_v1(10, &[0; 32], &[3u8; 32]);
        let tx = Transaction {
            inputs: vec![input.clone()],
            outputs: vec![output.clone()],
        };

        let tx_hash = tx.hash();

        // Manual hash
        let mut hasher = Blake2s256::new();
        hasher.update(&tx.inputs.len().to_be_bytes());
        for inp in &tx.inputs {
            hasher.update(&inp.output_id.tx_hash);
            hasher.update(&inp.output_id.index.to_be_bytes());
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
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();

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
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let input = Input::new(
            OutputId {
                tx_hash: funding_txid,
                index: 0,
            },
            [11u8; 32], // we use a random public key
            [0; 64],
        );

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
        match spending_tx.verify(&indexer) {
            Err(TransactionError::Execution(_)) => {}
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
        let sighash = sighash(&[output_id], &outputs);

        // Sign the sighash
        let signature = signing_key.sign(&sighash);

        // Verify the signature using the public key
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        assert!(verifying_key.verify_strict(&sighash, &signature).is_ok());
    }

    #[test]
    fn test_transaction_verify_invalid_input_output_totals() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V0,
                amount: 100,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output::new_v0(150, &data, &mask)]; // Any commitment will work with the mask chosen before
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(&[utxo_id], &new_outputs);
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input::new(
            utxo_id,
            signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
            signature,
        );

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        // Now verification should fail due to mismatched input and output totals
        match spending_tx.verify(&indexer) {
            Err(TransactionError::InvalidBalance { .. }) => {}
            other => panic!("Expected InsufficientInputAmount error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_valid_coinbase() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();

        // Build funding (previous) transaction that creates a UTXO
        let data = [12u8; 32];
        // Here the commitment is a mask since it's a coinbase transaction
        // A zero mask allows for any pubkey
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V0,
                amount: 2 * reward,
                data,
                commitment: mask,
            }],
        };
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Now build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output {
            version: Version::V0,
            amount: reward,
            data,
            commitment: mask,
        }];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(&[utxo_id], &new_outputs);
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input::new(
            utxo_id,
            signing_key.verifying_key().to_bytes(), // same public key used to construct commitment
            signature,
        );

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        // Now verification should succeed
        match spending_tx.verify(&indexer) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_v2() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();
        // Create a signing key for the funding transaction
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Build funding (previous) transaction that creates a UTXO
        let mut data = [0u8; 32];
        data.as_mut_slice().write(&p2pkh()).unwrap();
        let mask = [0u8; 32]; // A zero mask allows for any pubkey
        let reward = calculate_reward(&mask);

        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![
                Output {
                    version: Version::V0,
                    amount: reward,
                    data,
                    commitment: mask,
                },
                Output::new_v2(reward, &pubkey, &data),
            ],
        };
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Now build a spending transaction that consumes the second UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 1,
        };
        let new_outputs = vec![Output::new_v1(reward, &mask, &data)];
        let sighash = sighash(&[utxo_id], &new_outputs);
        let signature = signing_key.sign(&sighash).to_bytes();
        let input = Input::new(
            utxo_id, pubkey, // same public key used to construct commitment
            signature,
        );

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        // Now verification should succeed
        match spending_tx.verify(&indexer) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_too_many_inputs() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();

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
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Generate inputs exceeding the maximum allowed
        let max_allowed = u8::MAX as usize;
        let mut inputs = Vec::new();
        for i in 0..=max_allowed {
            let utxo_id = OutputId {
                tx_hash: funding_txid,
                index: i as u8,
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
            let sighash = sighash(&[utxo_id], &[]);
            let signature = signing_key.sign(&sighash).to_bytes();
            inputs.push(Input::new(
                utxo_id,
                signing_key.verifying_key().to_bytes(),
                signature,
            ));
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
        match spending_tx.verify(&indexer) {
            Err(TransactionError::TooManyInputs) => {}
            other => panic!("Expected TooManyInputs error, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_too_many_outputs() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();

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
        let funding_txid = funding_tx.hash();

        // Create a block containing the funding transaction and add to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

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
            inputs: vec![Input::new(
                OutputId {
                    tx_hash: funding_txid,
                    index: 0,
                },
                [11u8; 32],
                [0; 64],
            )],
            outputs,
        };

        // Now verification should fail due to too many outputs
        match spending_tx.verify(&indexer) {
            Err(TransactionError::TooManyOutputs) => {}
            other => panic!("Expected TooManyOutputs error, got: {:?}", other),
        }
    }
    #[test]
    fn test_transaction_verify_v3_invalid_witness_script() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();
        // Create a signing key for the funding transaction
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Construct a witness (script) that will be run for V3
        let witness = check_sig_script().to_vec();
        // For this invalid test we intentionally set utxo.data to something else
        let bad_data = [0u8; 32];

        // commitment must match the pubkey used to spend
        let commitment = commitment(&pubkey, None);

        let reward = 42; // arbitrary non-zero amount for test
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output {
                version: Version::V3,
                amount: reward,
                data: bad_data, // does NOT equal blake2s(witness)
                commitment,
            }],
        };
        let funding_txid = funding_tx.hash();

        // Add funding block to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output::new_v1(reward, &[0u8; 32], &[0u8; 32])];

        // sighash for spending tx (what the signature must sign)
        let sighash = sighash(&[utxo_id], &new_outputs);
        let signature = signing_key.sign(&sighash).to_bytes();

        // Use the witness and place it on the input; but since utxo.data != hash(witness)
        // the verify() should return InvalidWitnessScript error before executing the witness.
        let input = Input::new_with_witness(utxo_id, pubkey, signature, witness);

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&indexer) {
            Err(TransactionError::Execution(_)) => {}
            other => panic!("Expected Execution error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_v3_valid_witness() {
        // Create a indexer with one block containing a funding transaction
        let mut indexer = InMemoryIndexer::new();
        // Create a signing key for the funding transaction
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Construct a witness (script) that will be run for V3
        let witness = check_sig_script().to_vec();

        let reward = 42; // arbitrary non-zero amount for test
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v3(reward, &pubkey, &[0; 32], &witness)],
        };
        let funding_txid = funding_tx.hash();

        // Add funding block to indexer
        let mut block = Block::new(0, [0u8; 32]);
        block.transactions.push(funding_tx);
        indexer.add_block(&block).unwrap();

        // Build a spending transaction that consumes the funding UTXO
        let utxo_id = OutputId {
            tx_hash: funding_txid,
            index: 0,
        };
        let new_outputs = vec![Output::new_v1(reward, &[0u8; 32], &[0u8; 32])];

        // sighash for spending tx (what the signature must sign)
        let sighash = sighash(&[utxo_id], &new_outputs);
        let signature = signing_key.sign(&sighash).to_bytes();

        // Place the witness on the input; since utxo.data == hash(witness),
        // the VM will run the witness which will verify the signature and succeed.
        let input = Input::new_with_witness(utxo_id, pubkey, signature, witness);

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&indexer) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }
}
