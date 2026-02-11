/*! Transaction module for blockchain operations.

This module defines the core data structures and logic for representing,
serializing, hashing, and verifying blockchain transactions. It includes
types for transactions, inputs, outputs, output identifiers, and protocol
versions, as well as error types for transaction validation.

The module is designed to be used with a blockchain ledger/indexer and
supports extensible script and witness validation for advanced transaction types.
*/

use super::vm::{ExecError, Vm, check_sig_script, p2pkh, p2wsh};
use super::{
    Hash, PublicKey, commitment, deserialize_arr, deserialize_vec, ledger::Indexer,
    serialize_to_hex,
};
use super::{Signature, VirtualSize};
use blake2::{Blake2s256, Digest};
use ed25519_dalek::{SecretKey, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The hash of a transaction.
pub type TransactionHash = Hash;

/// Maximum allowed size for witness data in bytes.
const MAX_WITNESS_SIZE: usize = 1024;

/// Maximum allowed number of inputs or outputs in a transaction.
const MAX_ALLOWED: usize = 256;

/// A blockchain transaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

/// An output identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputId {
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    pub tx_hash: TransactionHash,
    pub index: u8,
}

/// A blockchain transaction input.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// The id of the output being spent.
    pub(crate) output_id: OutputId,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// The public key used to verify the signature.
    pub(crate) public_key: PublicKey,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_vec"
    )]
    /// Witness data for the input.
    pub(crate) witness: Vec<u8>,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// The signature signed by the private key linked to the public key.
    pub(crate) signature: Signature,
}

/// Protocol version used for outputs in the codebase.
///
/// Adding a short doc comment makes the intent explicit and makes the type
/// easier to discover when browsing the code or generated documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
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
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    /// Protocol version used for the output.
    pub(crate) version: Version,
    /// Amount of the output.
    pub(crate) amount: u64,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// Data associated with the output.
    pub(crate) data: Hash,
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_arr"
    )]
    /// The hash of the public key.
    pub(crate) commitment: Hash,
}

/// Error type for transaction validation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum TransactionError {
    /// The referenced output (UTXO) was not found in the given transaction.
    InvalidOutput(OutputId),
    /// Execution error occurred during transaction validation.
    Execution(ExecError),
    /// Total outputs exceed total inputs.
    InvalidBalance { total_input: u64, total_output: u64 },
    /// Witness script is too large.
    InvalidWitnessSize,
    /// The transaction has no inputs.
    MissingInputs,
    /// Number of inputs exceeds maximum allowed.
    TooManyInputs,
    /// Number of outputs exceeds maximum allowed.
    TooManyOutputs,
}

impl From<ExecError> for TransactionError {
    fn from(err: ExecError) -> Self {
        TransactionError::Execution(err)
    }
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
    pub fn new_unsigned(output_id: OutputId) -> Self {
        Self {
            output_id,
            signature: [0; 64],
            public_key: Default::default(),
            witness: vec![],
        }
    }
    pub fn with_witness(mut self, witness: Vec<u8>) -> Self {
        self.witness = witness;
        self
    }
    pub fn sign(mut self, sk: &SecretKey, sighash: Hash) -> Self {
        let signing_key = SigningKey::from_bytes(sk);
        self.public_key = signing_key.verifying_key().to_bytes();
        self.signature = signing_key.sign(&sighash).to_bytes();
        self
    }
    pub fn output_id(&self) -> OutputId {
        self.output_id
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

impl Output {
    /// Creates a new V0 output.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount for the output.
    /// * `mask` - The mask for the next challenge.
    /// * `nonce` - The solution for the previous challenge.
    pub fn new_v0(amount: u64, mask: &Hash, nonce: &Hash) -> Self {
        Self {
            version: Version::V0,
            amount,
            data: *mask,        // The mask for the next challenge
            commitment: *nonce, // The solution for the previous challenge
        }
    }

    /// Creates a new V1 output (P2PKH style).
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount for the output.
    /// * `public_key` - The public key for the output.
    /// * `data` - Associated data for the output.
    pub fn new_v1(amount: u64, public_key: &PublicKey, data: &Hash) -> Self {
        let commitment = commitment(public_key, Some(data.as_slice()));
        Self {
            version: Version::V1,
            amount,
            data: *data,
            commitment,
        }
    }

    /// Creates a new V1 output locked to a pre-computed address (commitment hash).
    ///
    /// Use this when you only have the recipient's public key hash (address)
    /// rather than their full public key.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount for the output.
    /// * `address` - The recipient's address (commitment hash).
    /// * `data` - Associated data for the output.
    pub fn to_address(amount: u64, address: &Hash, data: &Hash) -> Self {
        Self {
            version: Version::V1,
            amount,
            data: *data,
            commitment: *address,
        }
    }

    /// Creates a new V2 output (P2SH style).
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount for the output.
    /// * `public_key` - The public key for the output.
    /// * `script` - The script hash for the output.
    pub fn new_v2(amount: u64, public_key: &PublicKey, script: &Hash) -> Self {
        let commitment = commitment(public_key, Some(script.as_slice()));
        Self {
            version: Version::V2,
            amount,
            data: *script,
            commitment,
        }
    }

    /// Creates a new V3 output (SegWit style).
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount for the output.
    /// * `public_key` - The public key for the output.
    /// * `data` - Associated data for the output (typically a hash).
    /// * `witness_script` - The witness script for the output.
    pub fn new_v3(
        amount: u64,
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

    /// Returns the mask for V0 outputs, or `None` for other versions.
    pub fn mask(&self) -> Option<&Hash> {
        match self.version {
            Version::V0 => Some(&self.data),
            _ => None,
        }
    }

    /// Returns the nonce for V0 outputs, or `None` for other versions.
    pub fn nonce(&self) -> Option<&Hash> {
        match self.version {
            Version::V0 => Some(&self.commitment),
            _ => None,
        }
    }

    /// Returns the address associated with the output.
    pub fn address(&self) -> &Hash {
        &self.commitment
    }

    /// Returns the data associated with the output.
    pub fn data(&self) -> &Hash {
        &self.data
    }

    /// Returns the amount of the output.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns the version of the output.
    pub fn version(&self) -> Version {
        self.version
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
        let mut total_input_amount = 0_u64;
        let prev_block = indexer.get_last_block_metadata();
        let reward = self
            .inputs
            .get(0)
            .map(|input| input.output_id)
            .zip(prev_block.as_ref())
            .filter(|(utxo, meta)| &meta.lead_output == utxo);

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
                .get_output(&input.output_id)
                .ok_or(TransactionError::InvalidOutput(input.output_id))?;
            total_input_amount = total_input_amount.saturating_add(utxo.amount);

            match utxo.version {
                Version::V0 => {
                    // For mining transactions, only the signature is checked
                    vm.run(&check_sig_script())?;
                }
                Version::V1 => {
                    // V1 transactions use a simple P2PK script
                    vm.run(&p2pkh())?;
                }
                Version::V2 => {
                    // V2 transactions can use a more complex script
                    vm.run(&utxo.data)?;
                }
                Version::V3 => {
                    // V3 transactions support segwit
                    if input.witness.len() > MAX_WITNESS_SIZE {
                        return Err(TransactionError::InvalidWitnessSize);
                    }
                    vm.run(&p2wsh())?;
                    vm.run(&input.witness)?;
                }
            }
        }
        if reward.is_some() {
            return Ok(());
        }

        let total_output_amount = self.outputs.iter().map(|output| output.amount).sum();
        if prev_block.is_some() && total_output_amount > total_input_amount {
            return Err(TransactionError::InvalidBalance {
                total_input: total_input_amount,
                total_output: total_output_amount,
            });
        }
        Ok(())
    }

    /// Calculates the transaction fee as sum(inputs) - sum(outputs).
    pub fn fee<L: Indexer>(&self, indexer: &L) -> u64 {
        let total_input_amount: u64 = self
            .inputs
            .iter()
            .filter_map(|input| indexer.get_output(&input.output_id))
            .map(|output| output.amount)
            .sum();
        let total_output_amount = self.outputs.iter().map(|output| output.amount).sum();
        total_input_amount.saturating_sub(total_output_amount)
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
        Hash,
        block::{Block, BlockError},
        ledger::{BlockMetadata, Indexer, Query},
        vm::p2pkh,
    };
    use blake2::Blake2s256;
    use ed25519_dalek::Signer;
    use ethnum::U256;
    use std::{borrow::Cow, collections::HashMap};

    // A mock indexer for testing transaction logic without a real blockchain.
    #[derive(Default, Clone)]
    struct MockIndexer {
        utxos: HashMap<OutputId, Output>,
        block_meta: Option<BlockMetadata>,
    }

    impl MockIndexer {
        /// Insert a UTXO into the mock.
        fn insert(&mut self, output_id: OutputId, output: Output) {
            self.utxos.insert(output_id, output);
        }

        /// Set block metadata with a specific lead output (for coinbase tests).
        fn with_lead_output(mut self, lead_output: OutputId) -> Self {
            let meta = self.block_meta.get_or_insert_with(|| BlockMetadata {
                version: 0,
                hash: [0; 32],
                prev_block_hash: [0; 32],
                height: 0,
                available_supply: 0,
                lead_output,
                cumulative_work: U256::MIN,
                merkle_root: [0; 32],
                cursor: None,
            });
            meta.lead_output = lead_output;
            self
        }

        /// Set a dummy block metadata so that balance checking is enabled.
        fn with_balance_check(mut self) -> Self {
            self.block_meta = Some(BlockMetadata {
                version: 0,
                hash: [0; 32],
                prev_block_hash: [0; 32],
                height: 1,
                available_supply: 0,
                lead_output: OutputId::new([0xFF; 32], 0), // won't match any real input
                cumulative_work: U256::MIN,
                merkle_root: [0; 32],
                cursor: None,
            });
            self
        }
    }

    impl Indexer for MockIndexer {
        fn add_block(&mut self, _block: &Block) -> Result<(), BlockError> {
            unimplemented!()
        }

        fn get_block_metadata(&'_ self, _hash: &Hash) -> Option<Cow<'_, BlockMetadata>> {
            self.block_meta.as_ref().map(Cow::Borrowed)
        }

        fn get_output(&self, id: &OutputId) -> Option<Output> {
            self.utxos.get(id).copied()
        }

        fn query_outputs(&self, _query: &Query) -> Vec<(OutputId, Output)> {
            unimplemented!()
        }

        fn get_block_from_output(&self, _output_id: &OutputId) -> Option<Hash> {
            self.block_meta.as_ref().map(|meta| meta.hash)
        }

        fn get_tip(&'_ self) -> Option<Hash> {
            None
        }

        fn get_last_block_metadata(&'_ self) -> Option<Cow<'_, BlockMetadata>> {
            self.block_meta.as_ref().map(Cow::Borrowed)
        }
    }

    #[test]
    fn test_sighash_matches_manual_hash() {
        let txid: [u8; 32] = [9u8; 32];
        let output_id = OutputId {
            tx_hash: txid,
            index: 1,
        };

        let pk = [1u8; 32];
        let out1 = Output::new_v1(10, &pk, &[4u8; 32]);
        let out2 = Output::new_v1(20, &pk, &[6u8; 32]);
        let outputs = vec![out1, out2];

        let s1 = sighash(&[output_id], &outputs);

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
        let input = Input::new_unsigned(OutputId {
            tx_hash: [1u8; 32],
            index: 0,
        });
        let output = Output::new_v1(10, &[0; 32], &[3u8; 32]);
        let tx = Transaction {
            inputs: vec![input.clone()],
            outputs: vec![output.clone()],
        };

        let tx_hash = tx.hash();

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
    fn test_transaction_fee() {
        let data = [12u8; 32];
        let mask = [0u8; 32];
        let utxo_id = OutputId::new([1u8; 32], 0);

        let mut indexer = MockIndexer::default();
        indexer.insert(
            utxo_id,
            Output {
                version: Version::V1,
                amount: 100,
                data,
                commitment: mask,
            },
        );

        let new_outputs = vec![
            Output::new_v1(60, &mask, &data),
            Output::new_v1(30, &mask, &data),
        ]; // total output: 90
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let sighash = sighash(&[utxo_id], &new_outputs);
        let input =
            Input::new_unsigned(utxo_id).sign(signing_key.verifying_key().as_bytes(), sighash);

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        assert_eq!(spending_tx.fee(&indexer), 10);
    }

    #[test]
    fn test_transaction_verify_invalid_public_key() {
        // UTXO with an invalid commitment (not a valid public key)
        let utxo_id = OutputId::new([1u8; 32], 0);
        let mut indexer = MockIndexer::default();
        indexer.insert(
            utxo_id,
            Output {
                version: Version::V1,
                amount: 100,
                data: [12u8; 32],
                commitment: [0u8; 32], // not a valid public key
            },
        );

        let spending_tx = Transaction {
            inputs: vec![Input::new_unsigned(utxo_id)],
            outputs: vec![Output::new_v1(99, &[0u8; 32], &[0u8; 32])],
        };

        match spending_tx.verify(&indexer) {
            Err(TransactionError::Execution(_)) => {}
            other => panic!("Expected Execution error, got: {:?}", other),
        }
    }

    #[test]
    fn test_signed_sighash_verification() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let output_id = OutputId {
            tx_hash: [9u8; 32],
            index: 1,
        };
        let outputs = vec![Output::new_v1(10, &public_key, &[5u8; 32])];

        let sighash = sighash(&[output_id], &outputs);
        let signature = signing_key.sign(&sighash);

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        assert!(verifying_key.verify_strict(&sighash, &signature).is_ok());
    }

    #[test]
    fn test_transaction_verify_invalid_input_output_totals() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let data = [12u8; 32];

        let utxo_id = OutputId::new([1u8; 32], 0);
        let mut indexer = MockIndexer::default().with_balance_check();
        indexer.insert(utxo_id, Output::new_v1(100, &pubkey, &data));

        // Try to spend 150 from a 100-value UTXO
        let new_outputs = vec![Output::new_v1(150, &data, &[0u8; 32])];
        let sighash = sighash(&[utxo_id], &new_outputs);

        let spending_tx = Transaction {
            inputs: vec![Input::new_unsigned(utxo_id).sign(signing_key.as_bytes(), sighash)],
            outputs: new_outputs,
        };

        match spending_tx.verify(&indexer) {
            Err(TransactionError::InvalidBalance { .. }) => {}
            other => panic!("Expected InvalidBalance error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_valid_coinbase() {
        let utxo_id = OutputId::new([1u8; 32], 0);
        let data = [12u8; 32];
        let mask = [0u8; 32];
        let amount = 200;

        // The lead_output matches the first input, so verify() treats this as a coinbase
        let mut indexer = MockIndexer::default().with_lead_output(utxo_id);
        indexer.insert(
            utxo_id,
            Output {
                version: Version::V0,
                amount,
                data,
                commitment: mask,
            },
        );

        let new_outputs = vec![Output {
            version: Version::V0,
            amount: amount / 2,
            data,
            commitment: mask,
        }];
        let sighash = sighash(&[utxo_id], &new_outputs);
        let input = Input::new_unsigned(utxo_id).sign(&[11u8; 32], sighash);

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&indexer) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_v2() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Build a V2 UTXO whose data contains a p2pkh script
        let mut script_data = [0u8; 32];
        script_data.as_mut_slice().write(&p2pkh()).unwrap();

        let utxo_id = OutputId::new([1u8; 32], 0);
        let amount = 50;
        let mut indexer = MockIndexer::default().with_balance_check();
        indexer.insert(utxo_id, Output::new_v2(amount, &pubkey, &script_data));

        let new_outputs = vec![Output::new_v1(amount, &[0u8; 32], &script_data)];
        let sighash = sighash(&[utxo_id], &new_outputs);
        let input = Input::new_unsigned(utxo_id).sign(signing_key.as_bytes(), sighash);

        let spending_tx = Transaction {
            inputs: vec![input],
            outputs: new_outputs,
        };

        match spending_tx.verify(&indexer) {
            Ok(_) => {}
            other => panic!("Expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_too_many_inputs() {
        let indexer = MockIndexer::default();
        let txid = [1u8; 32];

        let mut inputs = Vec::new();
        for i in 0..=(MAX_ALLOWED + 1) {
            let utxo_id = OutputId {
                tx_hash: txid,
                index: i as u8,
            };
            let sighash = sighash(&[utxo_id], &[]);
            inputs.push(Input::new_unsigned(utxo_id).sign(&[11u8; 32], sighash));
        }

        let spending_tx = Transaction {
            inputs,
            outputs: vec![Output::new_v1(1, &[0u8; 32], &[0u8; 32])],
        };

        match spending_tx.verify(&indexer) {
            Err(TransactionError::TooManyInputs) => {}
            other => panic!("Expected TooManyInputs error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_too_many_outputs() {
        let indexer = MockIndexer::default();

        let outputs: Vec<Output> = (0..=(MAX_ALLOWED + 1))
            .map(|_| Output::new_v1(1, &[0u8; 32], &[0u8; 32]))
            .collect();

        let spending_tx = Transaction {
            inputs: vec![Input::new_unsigned(OutputId::new([1u8; 32], 0))],
            outputs,
        };

        match spending_tx.verify(&indexer) {
            Err(TransactionError::TooManyOutputs) => {}
            other => panic!("Expected TooManyOutputs error, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_verify_v3_invalid_witness_script() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let witness = check_sig_script().to_vec();
        let bad_data = [0u8; 32]; // does NOT match blake2s(witness)
        let commitment = commitment(&pubkey, None);
        let amount = 42;

        let utxo_id = OutputId::new([1u8; 32], 0);
        let mut indexer = MockIndexer::default().with_balance_check();
        indexer.insert(
            utxo_id,
            Output {
                version: Version::V3,
                amount,
                data: bad_data,
                commitment,
            },
        );

        let new_outputs = vec![Output::new_v1(amount, &[0u8; 32], &[0u8; 32])];
        let sighash = sighash(&[utxo_id], &new_outputs);
        let input = Input::new_unsigned(utxo_id)
            .with_witness(witness)
            .sign(signing_key.as_bytes(), sighash);

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
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let witness = check_sig_script().to_vec();
        let amount = 42;

        let utxo_id = OutputId::new([1u8; 32], 0);
        let mut indexer = MockIndexer::default().with_balance_check();
        indexer.insert(utxo_id, Output::new_v3(amount, &pubkey, &[0; 32], &witness));

        let new_outputs = vec![Output::new_v1(amount, &[0u8; 32], &[0u8; 32])];
        let sighash = sighash(&[utxo_id], &new_outputs);
        let input = Input::new_unsigned(utxo_id)
            .with_witness(witness)
            .sign(signing_key.as_bytes(), sighash);

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
