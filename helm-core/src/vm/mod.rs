/*!
VM runtime implementing opcode execution.
*/

mod macros;
pub mod op;
mod scanner;
mod stack;

use crate::ledger::Indexer;
use blake2::Digest;
use ed25519_dalek::Verifier;
use op::Op;
use scanner::Scanner;
use serde::Serialize;
use stack::{Stack, TakeStackIter};

use super::transaction::{Input, Output, Transaction, sighash};

const MAX_VALUE_SIZE: usize = 1024;

/// Returns a standard pay to public key hash script.
pub const fn p2pkh() -> &'static [u8] {
    use op::r#const::*;
    &[
        // Verify signature
        OP_SIGHASH_ALL,
        OP_VERIFYSIG,
        // Verify commitment
        OP_SELF_COMM, // Push the original commitment from the UTXO
        OP_SELF_DATA, // Push the script from the UTXO
        OP_PUSH_PK,   // Push the public key from the UTXO
        OP_CAT,       // Concatenate the script and public key
        OP_HASH_B2,   // Hash the concatenated data (public_key + script)
        OP_EQUAL,     // Compare: HASH(public_key + script) == original_commitment
        OP_VERIFY,    // Fail if they are not equal
        OP_RETURN,    // Succeed
    ]
}

/// Returns a standard pay to witness script hash script.
pub const fn p2wsh() -> &'static [u8] {
    use op::r#const::*;
    &[
        // Verify signature
        OP_SIGHASH_ALL,
        OP_VERIFYSIG,
        // Verify commitment
        OP_SELF_COMM,
        OP_PUSH_WITNESS,
        OP_SELF_DATA,
        OP_PUSH_PK,
        OP_CAT,
        OP_CAT,
        OP_HASH_B2,
        OP_EQUAL,
        OP_VERIFY,
        OP_RETURN,
    ]
}

/// Verifies the signature of a transaction
pub const fn check_sig_script() -> &'static [u8] {
    use op::r#const::*;
    &[OP_SIGHASH_ALL, OP_VERIFYSIG]
}

/// VM-level execution error kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecError {
    pub(self) op: String,
    pub(self) code: u8,
    pub(self) trace: Vec<u8>,
}

impl ExecError {
    fn new(op: Op, trace: &VmStack) -> Self {
        Self {
            op: op.to_string(),
            code: op.into(),
            trace: trace
                .iter()
                .map(|v| v.to_bytes())
                .reduce(|mut a, b| {
                    a.extend_from_slice(&b);
                    a
                })
                .unwrap_or_default(),
        }
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed at opcode '{}' (code {}), stack trace: {:?}",
            self.op, self.code, self.trace
        )
    }
}

/// VM runtime holding a reference to a indexer.
pub struct Vm<'a, I> {
    input_index: usize,
    transaction: &'a Transaction,
    indexer: &'a I,
}

/// Represents a value on the VM stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackValue<'a> {
    U8(u8),
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
    Stream(TakeStackIter<'a, StackValue<'a>>),
}

/// Represents an owned value on the VM stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedStackValue {
    U8(u8),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
}

impl<'a> From<u64> for StackValue<'a> {
    fn from(value: u64) -> Self {
        StackValue::U64(value)
    }
}

impl<'a> From<u32> for StackValue<'a> {
    fn from(value: u32) -> Self {
        StackValue::U32(value)
    }
}

impl<'a> From<&'a [u8]> for StackValue<'a> {
    fn from(value: &'a [u8]) -> Self {
        StackValue::Bytes(value)
    }
}

impl<'a> From<u8> for StackValue<'a> {
    fn from(value: u8) -> Self {
        StackValue::U8(value)
    }
}

impl<'a> From<bool> for StackValue<'a> {
    fn from(value: bool) -> Self {
        StackValue::U8(value as u8)
    }
}

impl TryInto<u64> for StackValue<'_> {
    type Error = Self;
    fn try_into(self) -> Result<u64, Self> {
        match self {
            StackValue::U8(b) => Ok(b as u64),
            StackValue::U32(int) => Ok(int as u64),
            StackValue::U64(int) => Ok(int as u64),
            _ => Err(self),
        }
    }
}

impl<'a> StackValue<'a> {
    /// Returns the length of the stack value in bytes.
    fn len(&self) -> usize {
        match self {
            StackValue::U8(_) => 1,
            StackValue::U32(_) => 4,
            StackValue::U64(_) => 8,
            StackValue::Bytes(bytes) => bytes.len(),
            StackValue::Stream(iter) => iter.map(|value| value.len()).sum(),
        }
    }
    fn to_owned(&self) -> OwnedStackValue {
        match self {
            StackValue::U8(value) => OwnedStackValue::U8(*value),
            StackValue::U32(value) => OwnedStackValue::U32(*value),
            StackValue::U64(value) => OwnedStackValue::U64(*value),
            StackValue::Bytes(slice) => OwnedStackValue::Bytes(slice.to_vec()),
            StackValue::Stream { .. } => OwnedStackValue::Bytes(self.to_bytes()),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![0; self.len()];
        self.copy_from_self(&mut vec);
        vec
    }

    fn copy_from_self(&self, slice: &mut [u8]) -> usize {
        match self {
            StackValue::U8(value) => {
                if slice.len() >= 1 {
                    slice[0] = *value;
                    1
                } else {
                    0
                }
            }
            StackValue::Bytes(bytes) => {
                let len = bytes.len().min(slice.len());
                slice[..len].copy_from_slice(&bytes[..len]);
                len
            }
            StackValue::U32(int) => {
                let bytes = int.to_be_bytes();
                let len = bytes.len().min(slice.len());
                slice[..len].copy_from_slice(&bytes[..len]);
                len
            }
            StackValue::U64(int) => {
                let bytes = int.to_be_bytes();
                let len = bytes.len().min(slice.len());
                slice[..len].copy_from_slice(&bytes[..len]);
                len
            }
            StackValue::Stream(iter) => {
                let mut written = 0;
                for value in *iter {
                    if written >= slice.len() {
                        break;
                    }
                    written += value.copy_from_self(&mut slice[written..]);
                }
                written
            }
        }
    }
}

impl Default for OwnedStackValue {
    fn default() -> Self {
        Self::U8(0)
    }
}

impl OwnedStackValue {
    fn borrow<'a>(&'a self) -> StackValue<'a> {
        match self {
            OwnedStackValue::U8(val) => StackValue::U8(*val),
            OwnedStackValue::U32(val) => StackValue::U32(*val),
            OwnedStackValue::U64(val) => StackValue::U64(*val),
            OwnedStackValue::Bytes(val) => StackValue::Bytes(val),
        }
    }
}

type VmStack<'a, 'b> = Stack<'a, StackValue<'b>>;
type VmRegisters = [OwnedStackValue; 256];

impl<'a, I: Indexer> Vm<'a, I> {
    /// Create a VM that references the provided indexer.
    pub fn new(indexer: &'a I, input_index: usize, transaction: &'a Transaction) -> Self {
        Vm {
            indexer,
            input_index,
            transaction,
        }
    }

    fn get_input(&self) -> &Input {
        &self.transaction.inputs[self.input_index]
    }

    fn get_outputs(&self) -> &[Output] {
        &self.transaction.outputs
    }

    fn pop_stack<'s>(
        op: Op<'a>,
        stack: VmStack<'s, 's>,
    ) -> Result<(StackValue<'s>, &'s VmStack<'s, 's>), ExecError> {
        stack.pop().ok_or_else(|| ExecError::new(op, &stack))
    }

    /// Execute the provided bytecode slice.
    ///
    /// Returns a `u128` representing the exit code of the VM stack (top
    /// element first) after execution completes successfully. On error, a
    /// `VmError` is returned.
    pub fn run(
        &'a self,
        code: &'a [u8],
        registers: &mut VmRegisters,
    ) -> Result<OwnedStackValue, ExecError> {
        let scanner = Scanner::new(code);
        // start with an empty persistent stack
        let stack: VmStack = Stack::new();

        // iterate and execute instructions
        let mut iter = scanner.flatten();
        let exit_code = self.exec(&mut iter, stack, registers)?;

        Ok(exit_code)
    }

    /// Execute the provided bytecode.
    // This function needs a huge refactor to make it more readable and maintainable.
    fn exec<'i, S>(
        &self,
        iter: &'i mut S,
        stack: VmStack,
        registers: &mut VmRegisters,
    ) -> Result<OwnedStackValue, ExecError>
    where
        S: Iterator<Item = Op<'a>>,
    {
        if let Some(op) = iter.next() {
            return match op {
                // Stack manipulation
                Op::Dup => {
                    // duplicate top item
                    match stack.get() {
                        Some(&v) => return self.exec(iter, stack.push(v), registers),
                        None => Err(ExecError::new(op, &stack)),
                    }
                }
                Op::Drop => {
                    // pop top
                    let (_v, parent) = Self::pop_stack(op, stack)?;
                    return self.exec(iter, *parent, registers);
                }
                Op::Swap => {
                    // swap top two elements
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    return self.exec(iter, parent2.push(a).push(b), registers);
                }

                // Immediate pushes
                Op::PushU32(n) => return self.exec(iter, stack.push(n.into()), registers),
                Op::PushByte(b) => return self.exec(iter, stack.push(b.into()), registers),
                Op::PushBytes(bytes) => {
                    return self.exec(iter, stack.push(bytes.into()), registers);
                }

                Op::ReadByte => {
                    let (value, parent) = Self::pop_stack(op, stack)?;
                    let mut buffer = [0u8; 1];
                    let bytes_written = value.copy_from_self(&mut buffer);
                    if bytes_written > 0 {
                        self.exec(iter, parent.push(buffer[0].into()), registers)
                    } else {
                        Err(ExecError::new(op, &stack))
                    }
                }
                Op::ReadU32 => {
                    let (value, parent) = Self::pop_stack(op, stack)?;
                    let mut buffer = [0u8; 4];
                    let bytes_written = value.copy_from_self(&mut buffer);
                    if bytes_written < 4 {
                        Err(ExecError::new(op, &stack))
                    } else {
                        let value = u32::from_be_bytes(buffer);
                        self.exec(iter, parent.push(value.into()), registers)
                    }
                }
                Op::ReadU64 => {
                    let (value, parent) = Self::pop_stack(op, stack)?;
                    let mut buffer = [0u8; 8];
                    let bytes_written = value.copy_from_self(&mut buffer);
                    if bytes_written < 8 {
                        Err(ExecError::new(op, &stack))
                    } else {
                        let value = u64::from_be_bytes(buffer);
                        self.exec(iter, parent.push(value.into()), registers)
                    }
                }

                // indexer / transaction related (placeholders or small integrations)
                Op::SelfAmt => {
                    let utxo = self
                        .indexer
                        .get_output(&self.get_input().output_id)
                        .ok_or(ExecError::new(op, &stack))?;
                    return self.exec(iter, stack.push(utxo.amount.into()), registers);
                }
                Op::SelfData => {
                    let utxo = self
                        .indexer
                        .get_output(&self.get_input().output_id)
                        .ok_or(ExecError::new(op, &stack))?;
                    return self.exec(iter, stack.push(StackValue::Bytes(&utxo.data)), registers);
                }
                Op::SelfComm => {
                    let utxo = self
                        .indexer
                        .get_output(&self.get_input().output_id)
                        .ok_or(ExecError::new(op, &stack))?;
                    return self.exec(
                        iter,
                        stack.push(StackValue::Bytes(&utxo.commitment)),
                        registers,
                    );
                }

                // These opcodes pop an index from the stack at runtime and then
                // push data from the referenced output.
                Op::OutAmt => {
                    let (idx_val, parent) = Self::pop_stack(op, stack)?;
                    let idx = match idx_val {
                        StackValue::U8(n) => n as usize,
                        _ => return Err(ExecError::new(op, &stack)),
                    };
                    let output = &self.get_outputs()[idx];
                    return self.exec(iter, parent.push(output.amount.into()), registers);
                }
                Op::OutData => {
                    let (idx_val, parent) = Self::pop_stack(op, stack)?;
                    let idx = match idx_val {
                        StackValue::U8(n) => n as usize,
                        _ => return Err(ExecError::new(op, &stack)),
                    };
                    let output = &self.get_outputs()[idx];
                    return self.exec(
                        iter,
                        parent.push(StackValue::Bytes(&output.data)),
                        registers,
                    );
                }
                Op::OutComm => {
                    let (idx_val, parent) = Self::pop_stack(op, stack)?;
                    let idx = match idx_val {
                        StackValue::U8(n) => n as usize,
                        _ => return Err(ExecError::new(op, &stack)),
                    };
                    let output = &self.get_outputs()[idx];
                    return self.exec(
                        iter,
                        parent.push(StackValue::Bytes(&output.commitment)),
                        registers,
                    );
                }
                Op::OutCount => {
                    // Push the number of outputs in the current transaction as a single byte.
                    let count = self.get_outputs().len();
                    // If there are more outputs than fit in a single byte, wrap/truncate.
                    // For typical transactions this will fit in a u8.
                    return self.exec(iter, stack.push(StackValue::U8(count as u8)), registers);
                }

                // Chain state
                Op::Supply => {
                    let supply = self
                        .indexer
                        .get_last_block_metadata()
                        .map_or(0, |meta| meta.available_supply);
                    return self.exec(iter, stack.push(supply.into()), registers);
                }
                Op::SelfSupply => {
                    let supply = self
                        .indexer
                        .get_block_from_output(&self.get_input().output_id)
                        .and_then(|hash| self.indexer.get_block_metadata(&hash))
                        .map_or(0, |meta| meta.available_supply);
                    return self.exec(iter, stack.push(supply.into()), registers);
                }
                Op::Height => {
                    let height = self
                        .indexer
                        .get_last_block_metadata()
                        .map_or(0, |meta| meta.height);
                    return self.exec(iter, stack.push(height.into()), registers);
                }
                Op::SelfHeight => {
                    let height = self
                        .indexer
                        .get_block_from_output(&self.get_input().output_id)
                        .and_then(|hash| self.indexer.get_block_metadata(&hash))
                        .map_or(0, |meta| meta.height);
                    return self.exec(iter, stack.push(height.into()), registers);
                }

                Op::PushPk => {
                    return self.exec(
                        iter,
                        stack.push(self.get_input().public_key.as_slice().into()),
                        registers,
                    );
                }
                Op::PushSig => {
                    return self.exec(
                        iter,
                        stack.push(self.get_input().signature.as_slice().into()),
                        registers,
                    );
                }
                Op::PushWitness => {
                    return self.exec(
                        iter,
                        stack.push(self.get_input().witness.as_slice().into()),
                        registers,
                    );
                }
                Op::SighashAll => {
                    let sighash = sighash(
                        self.transaction.inputs.iter().map(|input| &input.output_id),
                        &self.transaction.outputs,
                    );
                    return self.exec(iter, stack.push(sighash.as_slice().into()), registers);
                }
                Op::SighashOut => {
                    let sighash = sighash([], &self.transaction.outputs);
                    return self.exec(iter, stack.push(sighash.as_slice().into()), registers);
                }

                // Crypto & hashing (placeholders)
                Op::CheckSig => {
                    // Pops pk, sig, and sighash (top is sig, next is pk, then sighash)
                    let (pk_val, parent1) = Self::pop_stack(op, stack)?;
                    let pk = match pk_val {
                        StackValue::Bytes(pk) => pk,
                        _ => return Err(ExecError::new(op, &stack)),
                    };

                    let (sighash_val, parent2) = Self::pop_stack(op, *parent1)?;
                    let sighash = match sighash_val {
                        StackValue::Bytes(sighash) => sighash,
                        _ => return Err(ExecError::new(op, &stack)),
                    };

                    let (sig_val, parent3) = Self::pop_stack(op, *parent2)?;
                    let sig = match sig_val {
                        StackValue::Bytes(sig) => sig,
                        _ => return Err(ExecError::new(op, &stack)),
                    };

                    let signature = ed25519_dalek::Signature::from_slice(sig)
                        .map_err(|_| ExecError::new(op, &stack))?;
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes.copy_from_slice(pk);
                    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
                        .map_err(|_| ExecError::new(op, &stack))?;

                    let result = verifying_key.verify(sighash, &signature).is_ok();
                    return self.exec(iter, parent3.push(result.into()), registers);
                }
                Op::HashB2 => {
                    let (value, parent) = Self::pop_stack(op, stack)?;
                    let hash = blake2::Blake2s256::digest(&value.to_bytes());
                    return self.exec(iter, parent.push(StackValue::Bytes(&hash)), registers);
                }

                // Comparisons / arithmetic
                Op::Equal => {
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    let res = (a == b) as u8;
                    return self.exec(iter, parent2.push(res.into()), registers);
                }
                // Pops a,b pushes 1 if b>a (consistent with earlier spec)
                Op::Greater => {
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    match (a.try_into(), b.try_into()) {
                        (Ok(a), Ok::<u64, _>(b)) => {
                            let res = (b > a) as u8;
                            return self.exec(iter, parent2.push(res.into()), registers);
                        }
                        _ => return Err(ExecError::new(op, &stack)),
                    }
                }
                Op::Cat => {
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    // Limit the size of the concatenated stream to DOS attacks
                    if a.len() + b.len() > MAX_VALUE_SIZE {
                        return Err(ExecError::new(op, &stack));
                    }
                    return self.exec(
                        iter,
                        parent2.push(StackValue::Stream(stack.iter().take(2))),
                        registers,
                    );
                }
                Op::Split(index) => {
                    let (a, parent) = Self::pop_stack(op, stack)?;
                    match a {
                        StackValue::Bytes(bytes) => {
                            let (left, right) = bytes.split_at(index as usize);
                            return self.exec(
                                iter,
                                parent.push(left.into()).push(right.into()),
                                registers,
                            );
                        }
                        StackValue::Stream { .. } => {
                            let bytes = a.to_bytes();
                            let (left, right) = bytes.split_at(index as usize);
                            return self.exec(
                                iter,
                                parent.push(left.into()).push(right.into()),
                                registers,
                            );
                        }
                        _ => Err(ExecError::new(op, &stack)),
                    }
                }
                Op::Add => {
                    // Pops a,b pushes b+a
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    let sum = match (a.try_into(), b.try_into()) {
                        (Ok(a), Ok::<u64, _>(b)) => b.wrapping_add(a),
                        _ => return Err(ExecError::new(op, &stack)),
                    };
                    return self.exec(iter, parent2.push(sum.into()), registers);
                }
                Op::Sub => {
                    // Pops a,b pushes b-a
                    let (a, parent1) = Self::pop_stack(op, stack)?;
                    let (b, parent2) = Self::pop_stack(op, *parent1)?;
                    let diff = match (a.try_into(), b.try_into()) {
                        (Ok(a), Ok::<u64, _>(b)) => b.wrapping_sub(a),
                        _ => return Err(ExecError::new(op, &stack)),
                    };
                    return self.exec(iter, parent2.push(diff.into()), registers);
                }

                // Flow control / verification
                // `Op::Err` is a runtime-only opcode that unconditionally fails with a
                // verify-style error. It should be indistinguishable from a verification
                // failure to callers, so the returned ExecError uses `OP_VERIFY` as the
                // error code while retaining a sensible op name and stack trace.
                Op::Err => {
                    return Err(ExecError::new(op, &stack));
                }
                Op::Return => Ok(stack.get().map(StackValue::to_owned).unwrap_or_default()),
                Op::If => {
                    let (cond, parent) = Self::pop_stack(op, stack)?;
                    if matches!(cond, StackValue::U32(0) | StackValue::U8(0)) {
                        iter.find(|op| matches!(op, Op::EndIf));
                        // Skip the if block and recurse with the parent stack.
                        return self.exec(iter, stack, registers);
                    } else if matches!(cond, StackValue::Bytes(_)) {
                        return Err(ExecError::new(op, &stack));
                    } else {
                        // Recurse with the parent stack.
                        return self.exec(iter, *parent, registers);
                    }
                }
                // Register operations
                Op::Load(reg) => {
                    let value = registers[reg as usize].clone();
                    return self.exec(iter, stack.push(value.borrow()), registers);
                }
                Op::Store(reg) => match stack.pop() {
                    Some((value, parent)) => {
                        registers[reg as usize] = value.to_owned();
                        return self.exec(iter, *parent, registers);
                    }
                    None => return Err(ExecError::new(op, &stack)),
                },

                Op::EndIf => return self.exec(iter, stack, registers),
            };
        } else {
            return Ok(stack.get().map(StackValue::to_owned).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Hash, Version,
        block::{Block, BlockError},
        ledger::{BlockMetadata, OutputEntry},
        transaction::{Input, Output, OutputId, TransactionHash},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use ethnum::U256;
    use op::r#const::*;
    use std::{borrow::Cow, collections::HashMap, u64};

    // A mock indexer for testing purposes.
    #[derive(Default, Clone)]
    struct MockLedger {
        utxos: HashMap<OutputId, Output>,
        block_meta: Option<BlockMetadata>,
    }

    impl Indexer for MockLedger {
        fn add_block(&mut self, _block: &Block) -> Result<(), BlockError> {
            unimplemented!()
        }

        fn get_block_metadata(&'_ self, _hash: &Hash) -> Option<Cow<'_, BlockMetadata>> {
            self.block_meta.as_ref().map(Cow::Borrowed)
        }

        fn get_output(&self, id: &OutputId) -> Option<Output> {
            self.utxos.get(id).copied()
        }

        fn query_outputs(&self, _query: &crate::ledger::Query) -> Vec<OutputEntry> {
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

    fn default_transaction() -> Transaction {
        Transaction {
            inputs: vec![
                Input::builder()
                    .with_output_id(OutputId::new([0; 32], 0))
                    .with_public_key([1; 32])
                    .build()
                    .unwrap(),
            ],
            outputs: vec![],
        }
    }

    fn create_vm<'a, I: Indexer>(
        indexer: &'a I,
        input: usize,
        transaction: &'a Transaction,
    ) -> Vm<'a, I> {
        Vm::new(indexer, input, transaction)
    }

    fn default_registers() -> VmRegisters {
        std::array::from_fn(|_| OwnedStackValue::default())
    }

    #[test]
    fn test_op_false() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_FALSE];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_true() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_TRUE];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_dup() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_DUP, OP_ADD];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(246))
        );
    }

    #[test]
    fn test_op_drop() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_DROP];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(123))
        );
    }

    #[test]
    fn test_op_swap() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_SWAP];
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U8(200))
        );
    }

    #[test]
    fn test_op_push_u32() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let val = 12345u32.to_le_bytes();
        let code = [OP_PUSH_U32, val[0], val[1], val[2], val[3]];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U32(12345))
        );
    }

    #[test]
    fn test_op_push_byte() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let val = 100u8;
        let code = [OP_PUSH_BYTE, val];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(val))
        );
    }

    #[test]
    fn test_op_in_amt() {
        let output_id = OutputId::new(TransactionHash::default(), 0);
        let input = Input::builder()
            .with_output_id(output_id)
            .with_public_key([1; 32])
            .build()
            .unwrap();
        let utxo = Output {
            version: Version::ONE,
            amount: 100,
            commitment: [0; 32],
            data: [0; 32],
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, utxo);

        let transaction = Transaction::new(vec![input], vec![]);
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_SELF_AMT];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(100))
        );
    }

    #[test]
    fn test_op_in_data() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let mut data = [0; 32];
        data[0] = 1;
        let utxo = Output {
            version: Version::ONE,
            amount: 100,
            commitment: [0; 32],
            data,
        };
        let input = Input::builder()
            .with_output_id(output_id)
            .with_public_key([1; 32])
            .build()
            .unwrap();
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, utxo);

        let transaction = Transaction::new(vec![input], vec![]);
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_SELF_DATA, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_in_comm() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let mut commitment = [0; 32];
        commitment[0] = 1;
        let output = Output {
            version: Version::ONE,
            amount: 100,
            commitment,
            data: [0; 32],
        };
        let input = Input::builder()
            .with_output_id(output_id)
            .with_public_key([1; 32])
            .build()
            .unwrap();
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output);

        let new_outputs = vec![output];
        let transaction = Transaction::new(vec![input], new_outputs);
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_SELF_COMM, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );

        let code_vs_data = [OP_SELF_COMM, OP_SELF_DATA, OP_EQUAL];
        assert_eq!(
            vm.run(&code_vs_data, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_out_amt() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let output = Output {
            version: Version::ONE,
            amount: 200,
            commitment: [0; 32],
            data: [0; 32],
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&indexer, 0, &transaction);
        // Push index then call the opcode which will pop it at runtime.
        let code = [OP_PUSH_BYTE, 0, OP_OUT_AMT];
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U64(200))
        );
    }

    #[test]
    fn test_op_out_data() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let mut data = [0; 32];
        data[5] = 5;
        let output = Output {
            version: Version::ONE,
            amount: 200,
            commitment: [0; 32],
            data,
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&indexer, 0, &transaction);

        // Push index then call the opcode which will pop it and push the data.
        let code = [OP_PUSH_BYTE, 0, OP_OUT_DATA, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_out_comm() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let mut commitment = [0; 32];
        commitment[5] = 5;
        let output = Output {
            version: Version::ONE,
            amount: 200,
            commitment,
            data: [0; 32],
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&indexer, 0, &transaction);

        // Push index then call the opcode which will pop it and push the commitment.
        let code = [OP_PUSH_BYTE, 0, OP_OUT_COMM, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_out_count() {
        let tx_hash = [2; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let output_a = Output {
            version: Version::ONE,
            amount: 111,
            commitment: [0; 32],
            data: [0; 32],
        };
        let output_b = Output {
            version: Version::ONE,
            amount: 222,
            commitment: [0; 32],
            data: [0; 32],
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output_a);
        // build a transaction with two outputs
        let mut transaction = default_transaction();
        transaction.outputs.push(output_a);
        transaction.outputs.push(output_b);

        let vm = create_vm(&indexer, 0, &transaction);

        // OP_OUT_COUNT should push the number of outputs (2) as a byte.
        let code = [OP_OUT_COUNT];
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U8(2))
        );
    }

    #[test]
    fn test_op_supply_height() {
        let mut indexer = MockLedger::default();
        indexer.block_meta = Some(BlockMetadata {
            version: Version::ZERO,
            hash: [0; 32],
            prev_block_hash: [0; 32],
            height: 50,
            available_supply: 100_000,
            merkle_root: [0; 32],
            cumulative_work: U256::MIN,
            lead_output: OutputId::new([0; 32], 0),
            cursor: None,
        });
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_PUSH_SUPPLY];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(100_000))
        );
        let code = [OP_SELF_HEIGHT];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U32(50))
        );
    }

    #[test]
    fn test_op_supply_height_none() {
        let indexer = MockLedger::default(); // No block_meta
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_PUSH_SUPPLY];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(0))
        );
        let code = [OP_SELF_HEIGHT];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U32(0))
        );
    }

    #[test]
    fn test_op_self_supply() {
        let mut indexer = MockLedger::default();
        indexer.block_meta = Some(BlockMetadata {
            version: Version::ZERO,
            hash: [0; 32],
            prev_block_hash: [0; 32],
            height: 50,
            available_supply: 100_000,
            merkle_root: [0; 32],
            cumulative_work: U256::MIN,
            lead_output: OutputId::new([0; 32], 0),
            cursor: None,
        });

        let output_id = OutputId::new(TransactionHash::default(), 0);
        let input = Input::builder()
            .with_output_id(output_id)
            .with_public_key([1; 32])
            .build()
            .unwrap();
        let utxo = Output {
            version: Version::ONE,
            amount: 100,
            commitment: [0; 32],
            data: [0; 32],
        };
        indexer.utxos.insert(output_id, utxo);

        let transaction = Transaction::new(vec![input], vec![]);
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_SELF_SUPPLY];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(100_000))
        );
    }

    #[test]
    fn test_op_push_pk() {
        let public_key = [0u8; 32];
        let input = Input {
            output_id: OutputId::new([0; 32], 0),
            public_key,
            signature: [0; 64],
            witness: vec![],
        };
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let indexer = MockLedger::default();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_PUSH_PK, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_push_sig() {
        let mut signature = [0_u8; 64];
        signature[10] = 10;
        let input = Input {
            output_id: OutputId::new([0; 32], 0),
            public_key: [0; 32],
            signature,
            witness: vec![],
        };
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let indexer = MockLedger::default();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_PUSH_SIG, OP_DUP, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_checksig_valid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let sighash = sighash(&[output_id], []);
        let input = Input::builder()
            .with_output_id(output_id)
            .sign(signing_key.as_bytes(), sighash)
            .build()
            .unwrap();
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let indexer = MockLedger::default();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = check_sig_script();
        assert_eq!(
            vm.run(&code, Default::default()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_checksig_invalid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let other_signing_key = SigningKey::from_bytes(&[2u8; 32]);

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let sighash = sighash(&[output_id], []);
        let signature = other_signing_key.sign(&sighash); // Signed with wrong key
        let input = Input {
            output_id,
            public_key: verifying_key.to_bytes(),
            signature: signature.to_bytes(),
            witness: vec![],
        };
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let indexer = MockLedger::default();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = check_sig_script();
        assert_eq!(vm.run(&code, Default::default()).unwrap_err().code, OP_ERR);
    }

    #[test]
    fn test_op_hash_b2() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let data = [5u8; 32];
        let commitment = blake2::Blake2s256::digest(data).try_into().unwrap();
        let output = Output {
            version: Version::ONE,
            amount: 100,
            commitment,
            data,
        };
        let input = Input::builder()
            .with_output_id(output_id)
            .with_public_key([1; 32])
            .build()
            .unwrap();
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let mut indexer = MockLedger::default();
        indexer.utxos.insert(output_id, output);
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [OP_SELF_DATA, OP_HASH_B2, OP_SELF_COMM, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_equal() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 123, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );

        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );

        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_EQUAL];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_greater() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        // b > a -> 456 > 123
        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_GREATER];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );

        // b > a -> 123 > 456
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_GREATER];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );

        // b > a -> 123 > 123
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 123, OP_GREATER];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_add() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let val1 = 10u32.to_le_bytes();
        let val2 = 20u32.to_le_bytes();
        let code = [
            OP_PUSH_U32,
            val1[0],
            val1[1],
            val1[2],
            val1[3],
            OP_PUSH_U32,
            val2[0],
            val2[1],
            val2[2],
            val2[3],
            OP_ADD,
        ];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(30))
        );
    }

    #[test]
    fn test_op_sub() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 30, OP_PUSH_BYTE, 10, OP_SUB];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(20))
        );
    }

    #[test]
    fn test_op_verify_ok() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 1, OP_VERIFY, OP_TRUE];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );
    }

    #[test]
    fn test_op_verify_fail() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 0, OP_VERIFY, OP_TRUE];
        assert!(vm.run(&code, Default::default()).is_err());
    }

    #[test]
    fn test_op_err() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let res = vm.run(&[OP_ERR], Default::default());
        assert_eq!(res.unwrap_err().code, OP_ERR);
    }

    #[test]
    fn test_op_return() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let code = [OP_PUSH_BYTE, 200, OP_RETURN, OP_TRUE];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(200))
        );
    }

    #[test]

    fn test_op_if() {
        let indexer = MockLedger::default();

        let transaction = default_transaction();

        let vm = create_vm(&indexer, 0, &transaction);

        // Condition is 1, so OP_TRUE is executed
        let val = 1u8;

        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE];

        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(1))
        );

        // Condition is 0, so OP_TRUE is skipped. The next op is... nothing.
        // It should end with an empty stack, which is an error.
        let val = 0u8;
        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );

        // Condition is 0, so OP_TRUE is skipped, OP_FALSE is executed.
        let val = 0u8;
        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE, OP_FALSE];

        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]

    fn test_p2pk_script_valid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let mut indexer = MockLedger::default();
        indexer.utxos.insert(
            output_id,
            Output::new_v1(100, &verifying_key.to_bytes(), &[0; 32]),
        );
        let sighash = sighash(&[output_id], []);
        let input = Input::builder()
            .with_output_id(output_id)
            .sign(signing_key.as_bytes(), sighash)
            .build()
            .unwrap();
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let vm = create_vm(&indexer, 0, &transaction);
        let script = p2pkh();

        assert_eq!(
            vm.run(script, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_p2pk_script_invalid() {
        let indexer = MockLedger::default();
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let other_signing_key = SigningKey::from_bytes(&[2u8; 32]);

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let sighash = sighash(&[output_id], []);
        let signature = other_signing_key.sign(&sighash);

        let input = Input {
            output_id,
            public_key: verifying_key.to_bytes(),
            signature: signature.to_bytes(),
            witness: vec![],
        };
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let vm = create_vm(&indexer, 0, &transaction);
        let script = p2pkh();

        assert_eq!(
            vm.run(&script, Default::default()).unwrap_err().code,
            OP_ERR
        );
    }

    #[test]
    fn test_op_cat() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [
            OP_PUSH_BYTE,
            1,
            OP_PUSH_BYTE,
            2,
            OP_CAT, // Concatenate the top two byte arrays
        ];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::Bytes(vec![2, 1]))
        );
    }
    #[test]
    fn test_op_cat_dos_attack() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        // Create a script that continuously pushes onto the stack and concatenates
        let mut code = vec![];
        code.push(OP_PUSH_SIG);
        for _ in 0..32 {
            code.push(OP_DUP);
            code.push(OP_CAT); // Concatenate with the previous stack value
        }

        // Expect a stack overflow error due to excessive concatenation
        assert_eq!(
            vm.run(&code, &mut default_registers()).unwrap_err().code,
            OP_CAT
        );
    }

    #[test]
    fn test_op_push_witness() {
        let indexer = MockLedger::default();
        let mut transaction = default_transaction();
        let witness_data = [0x01, 0x02, 0x03, 0x04];
        transaction.inputs[0].witness = witness_data.to_vec();
        let vm = create_vm(&indexer, 0, &transaction);

        let result = vm.run(&[OP_PUSH_WITNESS], &mut default_registers());
        assert_eq!(result, Ok(OwnedStackValue::Bytes(witness_data.to_vec())));
    }

    #[test]
    fn test_op_split() {
        let indexer = MockLedger::default();
        let mut transaction = default_transaction();
        let witness_data = [0x01, 0x02, 0x03, 0x04];
        transaction.inputs[0].witness = witness_data.to_vec();
        let vm = create_vm(&indexer, 0, &transaction);

        let result = vm.run(&[OP_PUSH_WITNESS, OP_SPLIT, 2], &mut default_registers());
        assert_eq!(result, Ok(OwnedStackValue::Bytes(vec![0x03, 0x04])));
    }
    #[test]
    fn test_op_read_u32() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let data = 12345678u32.to_le_bytes();
        let code = [
            OP_PUSH_BYTE,
            data[0],
            OP_PUSH_BYTE,
            data[1],
            OP_PUSH_BYTE,
            data[2],
            OP_PUSH_BYTE,
            data[3],
            OP_CAT,
            OP_CAT,
            OP_CAT, // Combine bytes into a single slice
            OP_READ_U32,
        ];

        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U32(12345678))
        );
    }
    #[test]
    fn test_op_read_u64() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let code = [
            OP_PUSH_U32,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            OP_DUP,
            OP_CAT, // Combine bytes into a single slice
            OP_READ_U64,
        ];

        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U64(u64::MAX))
        );
    }

    #[test]
    fn test_op_store_and_load() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let mut regs = default_registers();
        // Push a value, store it in register 0, then load it back.
        let code = [
            OP_PUSH_BYTE,
            0x42, // Push 0x42 onto the stack
            OP_STORE,
            0x00, // Pop 0x42 and store it in register 0
            OP_LOAD,
            0x00, // Push the value from register 0 back onto the stack
        ];
        assert_eq!(vm.run(&code, &mut regs), Ok(OwnedStackValue::U8(0x42)));
    }

    #[test]
    fn test_op_registers_persist_across_scripts() {
        // Verify that the same mutable register array can be reused between
        // two separate vm.run calls, preserving written values.
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let mut regs = default_registers();

        // First script: push 0x99 and store it in register 10.
        let store_code = [OP_PUSH_BYTE, 0x99, OP_STORE, 0x0A];
        vm.run(&store_code, &mut regs).unwrap();

        // Second script: load register 10 — must still be 0x99.
        let load_code = [OP_LOAD, 0x0A];
        assert_eq!(vm.run(&load_code, &mut regs), Ok(OwnedStackValue::U8(0x99)));
    }

    #[test]
    fn test_op_store_and_load_multiple_registers() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let mut regs = default_registers();
        // Store two different values in two registers, then load them independently.
        let code_r0 = [
            OP_PUSH_BYTE,
            0x01, // Push 0x01
            OP_STORE,
            0x00, // Store 0x01 in register 0
            OP_PUSH_BYTE,
            0x02, // Push 0x02
            OP_STORE,
            0x01, // Store 0x02 in register 1
            OP_LOAD,
            0x00, // Load register 0 → 0x01
        ];
        assert_eq!(vm.run(&code_r0, &mut regs), Ok(OwnedStackValue::U8(0x01)));

        // Verify register 1 holds 0x02 by loading it in a fresh script.
        let code_r1 = [OP_LOAD, 0x01];
        assert_eq!(vm.run(&code_r1, &mut regs), Ok(OwnedStackValue::U8(0x02)));
    }

    #[test]
    fn test_op_load_default_register() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        // Registers are zero-initialised (OwnedStackValue::U8(0)), so loading
        // from a register that was never written returns U8(0).
        let code = [OP_LOAD, 0x05];
        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0))
        );
    }

    #[test]
    fn test_op_store_empty_stack_fails() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        // Storing when the stack is empty must return an error.
        let code = [OP_STORE, 0x00];
        assert!(vm.run(&code, &mut default_registers()).is_err());
    }

    #[test]
    fn test_op_store_overwrites_register() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);
        let mut regs = default_registers();
        // Storing twice in the same register keeps only the latest value.
        let code = [
            OP_PUSH_BYTE,
            0xAA, // Push 0xAA
            OP_STORE,
            0x00, // Store 0xAA in register 0
            OP_PUSH_BYTE,
            0xBB, // Push 0xBB
            OP_STORE,
            0x00, // Overwrite register 0 with 0xBB
            OP_LOAD,
            0x00, // Load register 0 → should be 0xBB
        ];
        assert_eq!(vm.run(&code, &mut regs), Ok(OwnedStackValue::U8(0xBB)));
    }

    #[test]
    fn test_op_read_byte() {
        let indexer = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&indexer, 0, &transaction);

        let data = [0xAB];
        let code = [OP_PUSH_BYTE, data[0], OP_READ_BYTE];

        assert_eq!(
            vm.run(&code, &mut default_registers()),
            Ok(OwnedStackValue::U8(0xAB))
        );
    }
}
