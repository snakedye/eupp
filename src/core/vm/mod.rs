/*!
VM runtime implementing opcode execution.
*/

mod op;
mod scanner;
mod stack;

use crate::core::ledger::Ledger;
use ed25519_dalek::Verifier;
use op::Op;
use scanner::Scanner;
use sha2::Digest;
use stack::{Stack, StackIter};
use std::fmt;

use super::transaction::{Input, Output, Transaction, sighash};

const MAX_VALUE_SIZE: usize = 1024;

/// Returns a standard pay to public key hash script.
pub const fn p2pkh() -> &'static [u8] {
    use op::r#const::*;
    &[
        OP_PUSH_SIG,
        OP_SIGHASH_ALL,
        OP_PUSH_PK,
        OP_CHECKSIG,
        OP_VERIFY,
        // // --- Corrected Part 2 ---
        OP_SELF_COMM, // Push the original commitment from the UTXO
        OP_PUSH_PK,   // Push the public key
        OP_HASH_B2,   // Hash the pubkey (public_key)
        OP_EQUAL,     // Compare: HASH(public_key) == original_commitment
        OP_VERIFY,    // Fail if they are not equal
        OP_RETURN,    // Succeed
    ]
}

/// Returns a standard pay to witness script hash script.
pub const fn p2wsh() -> &'static [u8] {
    use op::r#const::*;
    &[
        OP_SELF_DATA,
        OP_PUSH_WITNESS,
        OP_HASH_B2,
        OP_EQUAL,
        OP_VERIFY,
        OP_RETURN,
    ]
}

pub const fn check_sig_script() -> &'static [u8] {
    use op::r#const::*;
    &[
        OP_PUSH_SIG,
        OP_SIGHASH_ALL,
        OP_PUSH_PK,
        OP_CHECKSIG,
        OP_VERIFY,
    ]
}

/// VM-level execution error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    StackUnderflow,
    VerifyFailed,
    TypeMismatch,
    FetchFailed,
    StackOverflow,
    Unimplemented(u8), // fallback if something unexpected happens
}

/// VM runtime holding a reference to a Ledger.
pub struct Vm<'a, L> {
    input_index: usize,
    transaction: &'a Transaction,
    ledger: &'a L,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackValue<'a> {
    U8(u8),
    U32(u32),
    Bytes(&'a [u8]),
    Stream {
        iter: StackIter<'a, StackValue<'a>>,
        len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedStackValue {
    U8(u8),
    U32(u32),
    Bytes(Vec<u8>),
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

/// Implement Display for ExecError to provide user-friendly error messages.
impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::StackUnderflow => {
                write!(f, "Stack underflow: not enough items on the stack")
            }
            ExecError::StackOverflow => {
                write!(f, "Stack overflow: maximum stack size exceeded")
            }
            ExecError::VerifyFailed => write!(f, "Verification failed: condition not met"),
            ExecError::TypeMismatch => {
                write!(f, "Type mismatch: unexpected value type on the stack")
            }
            ExecError::FetchFailed => write!(f, "Fetch failed: unable to retrieve required data"),
            ExecError::Unimplemented(op) => {
                write!(f, "Opcode {:?} is not implemented yet", op)
            }
        }
    }
}

impl<'a> StackValue<'a> {
    /// Returns the length of the stack value in bytes.
    fn len(&self) -> usize {
        match self {
            StackValue::U8(_) => 1,
            StackValue::U32(_) => 4,
            StackValue::Bytes(bytes) => bytes.len(),
            StackValue::Stream { iter, .. } => iter.map(|value| value.len()).sum(),
        }
    }
    fn to_owned(&self) -> OwnedStackValue {
        match self {
            StackValue::U8(value) => OwnedStackValue::U8(*value),
            StackValue::U32(value) => OwnedStackValue::U32(*value),
            StackValue::Bytes(slice) => OwnedStackValue::Bytes(slice.to_vec()),
            StackValue::Stream { .. } => OwnedStackValue::Bytes(self.to_bytes()),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            StackValue::U8(value) => vec![*value],
            StackValue::Bytes(bytes) => bytes.to_vec(),
            StackValue::U32(int) => int.to_be_bytes().to_vec(),
            StackValue::Stream { iter, len } => {
                let mut bytes = Vec::new();
                for value in iter.take(*len) {
                    bytes.extend(value.to_bytes());
                }
                bytes
            }
        }
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
            StackValue::Stream { iter, len } => {
                let mut written = 0;
                for value in iter.take(*len) {
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
        Self::U32(0)
    }
}

type VmStack<'a, 'b> = Stack<'a, StackValue<'b>>;

impl<'a, L: Ledger> Vm<'a, L> {
    /// Create a VM that references the provided ledger.
    pub fn new(ledger: &'a L, input_index: usize, transaction: &'a Transaction) -> Self {
        Vm {
            ledger,
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

    /// Execute the provided bytecode slice.
    ///
    /// Returns a `u128` representing the exit code of the VM stack (top
    /// element first) after execution completes successfully. On error, a
    /// `VmError` is returned.
    pub fn run(&self, code: &[u8]) -> Result<OwnedStackValue, ExecError> {
        let scanner = Scanner::new(code);
        // start with an empty persistent stack
        let stack: VmStack = Stack::new();

        // iterate and execute instructions
        let mut iter = scanner;
        let exit_code = self.exec(&mut iter, stack)?;

        Ok(exit_code)
    }

    /// Execute the provided bytecode.
    // This function needs a huge refactor to make it more readable and maintainable.
    fn exec<'i, I>(
        &self,
        scanner: &'i mut I,
        mut stack: VmStack,
    ) -> Result<OwnedStackValue, ExecError>
    where
        I: Iterator<Item = Op<'i>>,
    {
        if let Some(op) = scanner.next() {
            return match op {
                // Literals / stack constants
                Op::False => return self.exec(scanner, stack.push(0_u8.into())),
                Op::True => return self.exec(scanner, stack.push(1_u8.into())),

                // Stack manipulation
                Op::Dup => {
                    // duplicate top item
                    match stack.get() {
                        Some(&v) => return self.exec(scanner, stack.push(v)),
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                Op::Drop => {
                    // pop top
                    match stack.pop() {
                        Some((_v, parent)) => return self.exec(scanner, *parent),
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                Op::Swap => {
                    // swap top two elements
                    if let Some((a, parent1)) = stack.pop() {
                        if let Some((b, parent2)) = parent1.pop() {
                            stack = parent2.push(b);
                            return self.exec(scanner, stack.push(a));
                        } else {
                            Err(ExecError::StackUnderflow)
                        }
                    } else {
                        Err(ExecError::StackUnderflow)
                    }
                }

                // Immediate pushes (scanner already produces `Op::Push(u32)` or `Op::PushByte`)
                Op::PushU32(n) => return self.exec(scanner, stack.push(n.into())),
                Op::PushByte(b) => return self.exec(scanner, stack.push(b.into())),
                Op::PushBytes(bytes) => return self.exec(scanner, stack.push(bytes.into())),

                Op::ReadByte => match stack.pop() {
                    Some((value, parent)) => {
                        let mut buffer = [0u8; 1];
                        let bytes_written = value.copy_from_self(&mut buffer);
                        if bytes_written > 0 {
                            self.exec(scanner, parent.push(buffer[0].into()))
                        } else {
                            Err(ExecError::StackUnderflow)
                        }
                    }
                    None => Err(ExecError::StackUnderflow),
                },
                Op::ReadU32 => match stack.pop() {
                    Some((value, parent)) => {
                        let mut buffer = [0u8; 4];
                        let bytes_written = value.copy_from_self(&mut buffer);
                        if bytes_written < 4 {
                            Err(ExecError::StackUnderflow)
                        } else {
                            let value = u32::from_be_bytes(buffer);
                            self.exec(scanner, parent.push(value.into()))
                        }
                    }
                    None => Err(ExecError::StackUnderflow),
                },

                // Ledger / transaction related (placeholders or small integrations)
                Op::SelfAmt => {
                    let utxo = self
                        .ledger
                        .get_utxo(&self.get_input().output_id)
                        .ok_or(ExecError::FetchFailed)?;
                    return self.exec(scanner, stack.push(utxo.amount.into()));
                }
                Op::SelfData => {
                    let utxo = self
                        .ledger
                        .get_utxo(&self.get_input().output_id)
                        .ok_or(ExecError::FetchFailed)?;
                    return self.exec(scanner, stack.push(StackValue::Bytes(&utxo.data)));
                }
                Op::SelfComm => {
                    let utxo = self
                        .ledger
                        .get_utxo(&self.get_input().output_id)
                        .ok_or(ExecError::FetchFailed)?;
                    return self.exec(scanner, stack.push(StackValue::Bytes(&utxo.commitment)));
                }
                // The opcode should contain the index of the output to push.
                Op::OutAmt(idx) => {
                    let output = self.get_outputs()[idx as usize];
                    return self.exec(scanner, stack.push(StackValue::U32(output.amount)));
                }
                Op::OutData(idx) => {
                    let output = self.get_outputs()[idx as usize];
                    return self.exec(scanner, stack.push(StackValue::Bytes(&output.data)));
                }
                Op::OutComm(idx) => {
                    let output = self.get_outputs()[idx as usize];
                    return self.exec(scanner, stack.push(StackValue::Bytes(&output.commitment)));
                }

                // Chain state
                Op::Supply => {
                    let supply = self
                        .ledger
                        .get_last_block_metadata()
                        .map_or(0, |meta| meta.available_supply);
                    return self.exec(scanner, stack.push(supply.into()));
                }
                Op::Height => {
                    let height = self
                        .ledger
                        .get_last_block_metadata()
                        .map_or(0, |meta| meta.height);
                    return self.exec(scanner, stack.push(height.into()));
                }
                Op::SelfHeight => {
                    let height = self
                        .ledger
                        .get_utxo_block_hash(&self.get_input().output_id)
                        .and_then(|hash| self.ledger.get_block_metadata(&hash))
                        .map_or(0, |meta| meta.height);
                    return self.exec(scanner, stack.push(height.into()));
                }

                Op::PushPk => {
                    return self.exec(
                        scanner,
                        stack.push(self.get_input().public_key.as_slice().into()),
                    );
                }
                Op::PushSig => {
                    return self.exec(
                        scanner,
                        stack.push(self.get_input().signature.as_slice().into()),
                    );
                }
                Op::PushWitness => {
                    return self.exec(
                        scanner,
                        stack.push(self.get_input().witness.as_slice().into()),
                    );
                }
                Op::SighashAll => {
                    let sighash = sighash(
                        blake2::Blake2s256::new(),
                        self.transaction.inputs.iter().map(|input| &input.output_id),
                        &self.transaction.outputs,
                    );
                    return self.exec(scanner, stack.push(sighash.as_slice().into()));
                }
                Op::SighashOut => {
                    let sighash = sighash(blake2::Blake2s256::new(), [], &self.transaction.outputs);
                    return self.exec(scanner, stack.push(sighash.as_slice().into()));
                }

                // Crypto & hashing (placeholders)
                Op::CheckSig => {
                    // Pops pk, sig, and msg (top is sig, next is pk, then msg)
                    if let Some((StackValue::Bytes(pk), parent1)) = stack.pop() {
                        if let Some((StackValue::Bytes(msg), parent2)) = parent1.pop() {
                            if let Some((StackValue::Bytes(sig), parent3)) = parent2.pop() {
                                let signature = ed25519_dalek::Signature::from_slice(sig)
                                    .map_err(|_| ExecError::VerifyFailed)?;
                                let mut pubkey_bytes = [0u8; 32];
                                pubkey_bytes.copy_from_slice(pk);
                                let verifying_key =
                                    ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
                                        .map_err(|_| ExecError::VerifyFailed)?;

                                let result = verifying_key.verify(msg, &signature).is_ok();
                                return self.exec(scanner, parent3.push((result as u8).into()));
                            } else {
                                return Err(ExecError::StackUnderflow);
                            }
                        } else {
                            return Err(ExecError::StackUnderflow);
                        }
                    } else {
                        return Err(ExecError::TypeMismatch);
                    }
                }
                Op::HashB2 => match stack.pop() {
                    Some((value, parent)) => {
                        let hash = match value {
                            StackValue::U8(data) => blake2::Blake2s256::digest(&[data]),
                            StackValue::Bytes(data) => blake2::Blake2s256::digest(data),
                            StackValue::U32(data) => {
                                blake2::Blake2s256::digest(&data.to_be_bytes())
                            }
                            StackValue::Stream { .. } => {
                                blake2::Blake2s256::digest(&value.to_bytes())
                            }
                        };
                        let hash_bytes: [u8; 32] = hash.try_into().unwrap();
                        return self.exec(scanner, parent.push(StackValue::Bytes(&hash_bytes)));
                    }
                    None => Err(ExecError::StackUnderflow),
                },

                // Comparisons / arithmetic
                Op::Equal => match stack.pop() {
                    Some((a, parent1)) => match parent1.pop() {
                        Some((b, parent2)) => {
                            let res = (a == b) as u8;
                            return self.exec(scanner, parent2.push(res.into()));
                        }
                        None => return Err(ExecError::StackUnderflow),
                    },
                    None => return Err(ExecError::StackUnderflow),
                },
                // Pops a,b pushes 1 if b>a (consistent with earlier spec)
                Op::Greater => match stack.pop() {
                    Some((a, parent1)) => match parent1.pop() {
                        Some((b, parent2)) => match (a, b) {
                            (StackValue::U8(a), StackValue::U8(b)) => {
                                let res = (b > a) as u8;
                                return self.exec(scanner, parent2.push(res.into()));
                            }
                            (StackValue::U32(a), StackValue::U32(b)) => {
                                let res = (b > a) as u8;
                                return self.exec(scanner, parent2.push(res.into()));
                            }
                            (StackValue::U8(a), StackValue::U32(b)) => {
                                let res = (b > a as u32) as u8;
                                return self.exec(scanner, parent2.push(res.into()));
                            }
                            (StackValue::U32(a), StackValue::U8(b)) => {
                                let res = (b as u32 > a) as u8;
                                return self.exec(scanner, parent2.push(res.into()));
                            }
                            _ => return Err(ExecError::TypeMismatch),
                        },
                        None => return Err(ExecError::StackUnderflow),
                    },
                    None => return Err(ExecError::StackUnderflow),
                },
                Op::Cat => {
                    if let Some((a, parent1)) = stack.pop() {
                        if let Some((b, parent2)) = parent1.pop() {
                            // Limit the size of the concatenated stream to DOS attacks
                            if a.len() + b.len() > MAX_VALUE_SIZE {
                                return Err(ExecError::StackOverflow);
                            }
                            return self.exec(
                                scanner,
                                parent2.push(StackValue::Stream {
                                    iter: stack.iter(),
                                    len: 2,
                                }),
                            );
                        }
                    }
                    Err(ExecError::StackUnderflow)
                }
                Op::Split(index) => {
                    if let Some((a, parent)) = stack.pop() {
                        match a {
                            StackValue::Bytes(bytes) => {
                                let (left, right) = bytes.split_at(index as usize);
                                return self
                                    .exec(scanner, parent.push(left.into()).push(right.into()));
                            }
                            StackValue::Stream { .. } => {
                                let bytes = a.to_bytes();
                                let (left, right) = bytes.split_at(index as usize);
                                return self
                                    .exec(scanner, parent.push(left.into()).push(right.into()));
                            }
                            _ => Err(ExecError::TypeMismatch),
                        }
                    } else {
                        Err(ExecError::StackUnderflow)
                    }
                }
                Op::Add => {
                    // Pops a,b pushes b+a
                    match stack.pop() {
                        Some((a, parent1)) => match parent1.pop() {
                            Some((b, parent2)) => {
                                let sum = match (a, b) {
                                    (StackValue::U32(a), StackValue::U32(b)) => b.wrapping_add(a),
                                    (StackValue::U8(a), StackValue::U8(b)) => {
                                        (b as u32).wrapping_add(a as u32)
                                    }
                                    (StackValue::U8(a), StackValue::U32(b)) => {
                                        b.wrapping_add(a as u32)
                                    }
                                    (StackValue::U32(a), StackValue::U8(b)) => {
                                        (b as u32).wrapping_add(a)
                                    }
                                    _ => return Err(ExecError::TypeMismatch),
                                };
                                return self.exec(scanner, parent2.push(sum.into()));
                            }
                            None => return Err(ExecError::StackUnderflow),
                        },
                        None => return Err(ExecError::StackUnderflow),
                    }
                }
                Op::Sub => {
                    // Pops a,b pushes b-a
                    match stack.pop() {
                        Some((a, parent1)) => match parent1.pop() {
                            Some((b, parent2)) => {
                                let sum = match (a, b) {
                                    (StackValue::U32(a), StackValue::U32(b)) => b.wrapping_sub(a),
                                    (StackValue::U8(a), StackValue::U8(b)) => {
                                        (b as u32).wrapping_sub(a as u32)
                                    }
                                    (StackValue::U8(a), StackValue::U32(b)) => {
                                        b.wrapping_sub(a as u32)
                                    }
                                    (StackValue::U32(a), StackValue::U8(b)) => {
                                        (b as u32).wrapping_sub(a)
                                    }
                                    _ => return Err(ExecError::TypeMismatch),
                                };
                                return self.exec(scanner, parent2.push(sum.into()));
                            }
                            None => return Err(ExecError::StackUnderflow),
                        },
                        None => return Err(ExecError::StackUnderflow),
                    }
                }

                // Flow control / verification
                Op::Verify => {
                    // Pops top item. If 0 -> entire transaction (script) invalid.
                    match stack.pop() {
                        Some((StackValue::U32(0), _)) | Some((StackValue::U8(0), _)) => {
                            return Err(ExecError::VerifyFailed);
                        }
                        Some((_, parent)) => return self.exec(scanner, *parent),
                        None => return Err(ExecError::StackUnderflow),
                    }
                }
                Op::Return => Ok(stack.get().map(StackValue::to_owned).unwrap_or_default()),
                Op::If => {
                    match stack.pop() {
                        Some((cond, parent)) => {
                            if matches!(cond, StackValue::U32(0) | StackValue::U8(0)) {
                                scanner.find(|op| matches!(op, Op::EndIf));
                                // Skip the if block and recurse with the parent stack.
                                return self.exec(scanner, stack);
                            } else if matches!(cond, StackValue::Bytes(_)) {
                                return Err(ExecError::TypeMismatch);
                            } else {
                                // Recurse with the parent stack.
                                return self.exec(scanner, *parent);
                            }
                        }
                        None => return Err(ExecError::StackUnderflow),
                    }
                }
                Op::EndIf => return self.exec(scanner, stack),
            };
        } else {
            return Ok(stack.get().map(StackValue::to_owned).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        Hash,
        block::{Block, BlockError},
        ledger::BlockMetadata,
        transaction::{Input, Output, OutputId, TransactionHash, Version},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use op::r#const::*;
    use sha2::Digest;
    use std::collections::HashMap;

    // A mock ledger for testing purposes.
    #[derive(Default, Clone)]
    struct MockLedger {
        utxos: HashMap<OutputId, Output>,
        block_meta: Option<BlockMetadata>,
    }

    impl Ledger for MockLedger {
        fn add_block(&mut self, _block: Block) -> Result<(), BlockError> {
            unimplemented!()
        }

        fn get_block_metadata(&self, _hash: &Hash) -> Option<BlockMetadata> {
            self.block_meta.clone()
        }

        fn get_utxo(&self, id: &OutputId) -> Option<Output> {
            self.utxos.get(id).copied()
        }

        fn get_utxo_block_hash(&self, _output_id: &OutputId) -> Option<Hash> {
            self.block_meta.as_ref().map(|meta| meta.hash)
        }

        fn get_last_block_metadata(&self) -> Option<BlockMetadata> {
            self.block_meta.clone()
        }
    }

    fn default_transaction() -> Transaction {
        Transaction {
            inputs: vec![Input::new(OutputId::new([0; 32], 0), [0; 32], [0; 64])],
            outputs: vec![],
        }
    }

    fn create_vm<'a>(
        ledger: &'a MockLedger,
        input: usize,
        transaction: &'a Transaction,
    ) -> Vm<'a, MockLedger> {
        Vm::new(ledger, input, transaction)
    }

    #[test]
    fn test_op_false() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_FALSE];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));
    }

    #[test]
    fn test_op_true() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_TRUE];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_dup() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_DUP, OP_ADD];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(246)));
    }

    #[test]
    fn test_op_drop() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_DROP];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(123)));
    }

    #[test]
    fn test_op_swap() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_SWAP, OP_SUB];
        assert_eq!(
            vm.run(&code),
            Ok(OwnedStackValue::U32(200u32.wrapping_sub(123)))
        );
    }

    #[test]
    fn test_op_push_u32() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let val = 12345u32.to_le_bytes();
        let code = [OP_PUSH_U32, val[0], val[1], val[2], val[3]];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(12345)));
    }

    #[test]
    fn test_op_push_byte() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let val = 100u8;
        let code = [OP_PUSH_BYTE, val];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(val)));
    }

    #[test]
    fn test_op_in_amt() {
        let output_id = OutputId::new(TransactionHash::default(), 0);
        let input = Input::new(output_id, [0; 32], [0; 64]);
        let utxo = Output {
            version: Version::V1,
            amount: 100,
            commitment: [0; 32],
            data: [0; 32],
        };
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, utxo);

        let transaction = Transaction::new(vec![input], vec![]);
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_SELF_AMT];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(100)));
    }

    #[test]
    fn test_op_in_data() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let mut data = [0; 32];
        data[0] = 1;
        let utxo = Output {
            version: Version::V1,
            amount: 100,
            commitment: [0; 32],
            data,
        };
        let input = Input::new(output_id, [0; 32], [0; 64]);
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, utxo);

        let transaction = Transaction::new(vec![input], vec![]);
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_SELF_DATA, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_in_comm() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let mut commitment = [0; 32];
        commitment[0] = 1;
        let output = Output {
            version: Version::V1,
            amount: 100,
            commitment,
            data: [0; 32],
        };
        let input = Input::new(output_id, [0; 32], [0; 64]);
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, output);

        let new_outputs = vec![output];
        let transaction = Transaction::new(vec![input], new_outputs);
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_SELF_COMM, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));

        let code_vs_data = [OP_SELF_COMM, OP_SELF_DATA, OP_EQUAL];
        assert_eq!(vm.run(&code_vs_data), Ok(OwnedStackValue::U8(0)));
    }

    #[test]
    fn test_op_out_amt() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let output = Output {
            version: Version::V1,
            amount: 200,
            commitment: [0; 32],
            data: [0; 32],
        };
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&ledger, 0, &transaction);
        let code = [u8::from(Op::OutAmt(0)), 0];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(200)));
    }

    #[test]
    fn test_op_out_data() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let mut data = [0; 32];
        data[5] = 5;
        let output = Output {
            version: Version::V1,
            amount: 200,
            commitment: [0; 32],
            data,
        };
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&ledger, 0, &transaction);

        let code = [u8::from(Op::OutData(0)), 0, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_out_comm() {
        let tx_hash = [1; 32];
        let output_id = OutputId::new(tx_hash, 0);
        let mut commitment = [0; 32];
        commitment[5] = 5;
        let output = Output {
            version: Version::V1,
            amount: 200,
            commitment,
            data: [0; 32],
        };
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, output);
        let mut transaction = default_transaction();
        transaction.outputs.push(output);

        let vm = create_vm(&ledger, 0, &transaction);

        let code = [u8::from(Op::OutComm(0)), 0, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_supply_height() {
        let mut ledger = MockLedger::default();
        ledger.block_meta = Some(BlockMetadata {
            hash: [0; 32],
            prev_block_hash: [0; 32],
            height: 50,
            available_supply: 100_000,
            locked_supply: 0,
            lead_utxo: OutputId::new([0; 32], 0),
        });
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [OP_PUSH_SUPPLY];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(100_000)));
        let code = [OP_SELF_HEIGHT];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(50)));
        let code = [OP_PUSH_HEIGHT];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(50)));
    }

    #[test]
    fn test_op_supply_height_none() {
        let ledger = MockLedger::default(); // No block_meta
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [OP_PUSH_SUPPLY];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(0)));
        let code = [OP_SELF_HEIGHT];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(0)));
        let code = [OP_PUSH_HEIGHT];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(0)));
    }

    #[test]
    fn test_op_push_pk() {
        let mut public_key = [0u8; 32];
        public_key[10] = 10;
        let input = Input::new(OutputId::new([0; 32], 0), public_key, [0; 64]);
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let ledger = MockLedger::default();
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [OP_PUSH_PK, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_push_sig() {
        let mut signature = [0_u8; 64];
        signature[10] = 10;
        let input = Input::new(OutputId::new([0; 32], 0), [0; 32], signature);
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let ledger = MockLedger::default();
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [OP_PUSH_SIG, OP_DUP, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_checksig_valid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let msg = sighash(blake2::Blake2s256::new(), &[output_id], []);
        let signature = signing_key.sign(&msg);
        let input = Input::new(output_id, verifying_key.to_bytes(), signature.to_bytes());
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let ledger = MockLedger::default();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = check_sig_script();
        assert_eq!(vm.run(&code[..4]), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_checksig_invalid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let other_signing_key = SigningKey::from_bytes(&[2u8; 32]);

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let msg = sighash(blake2::Blake2s256::new(), &[output_id], []);
        let signature = other_signing_key.sign(&msg); // Signed with wrong key
        let input = Input::new(output_id, verifying_key.to_bytes(), signature.to_bytes());
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let ledger = MockLedger::default();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = check_sig_script();
        assert_eq!(vm.run(&code[0..4]), Ok(OwnedStackValue::U8(0)));
    }

    #[test]
    fn test_op_hash_b2() {
        let tx_hash = TransactionHash::default();
        let output_id = OutputId::new(tx_hash, 0);
        let data = [5u8; 32];
        let commitment = blake2::Blake2s256::digest(data).try_into().unwrap();
        let output = Output {
            version: Version::V1,
            amount: 100,
            commitment,
            data,
        };
        let input = Input::new(output_id, [0; 32], [0; 64]);
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };
        let mut ledger = MockLedger::default();
        ledger.utxos.insert(output_id, output);
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [OP_SELF_DATA, OP_HASH_B2, OP_SELF_COMM, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_equal() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 123, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));

        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));

        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_EQUAL];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));
    }

    #[test]
    fn test_op_greater() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        // b > a -> 456 > 123
        let code = [OP_PUSH_BYTE, 200, OP_PUSH_BYTE, 123, OP_GREATER];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));

        // b > a -> 123 > 456
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 200, OP_GREATER];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));

        // b > a -> 123 > 123
        let code = [OP_PUSH_BYTE, 123, OP_PUSH_BYTE, 123, OP_GREATER];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));
    }

    #[test]
    fn test_op_add() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
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
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(30)));
    }

    #[test]
    fn test_op_sub() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 30, OP_PUSH_BYTE, 10, OP_SUB];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(20)));
    }

    #[test]
    fn test_op_verify_ok() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 1, OP_VERIFY, OP_TRUE];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));
    }

    #[test]
    fn test_op_verify_fail() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 0, OP_VERIFY, OP_TRUE];
        assert_eq!(vm.run(&code), Err(ExecError::VerifyFailed));
    }

    #[test]
    fn test_op_return() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);
        let code = [OP_PUSH_BYTE, 200, OP_RETURN, OP_TRUE];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(200)));
    }

    #[test]

    fn test_op_if() {
        let ledger = MockLedger::default();

        let transaction = default_transaction();

        let vm = create_vm(&ledger, 0, &transaction);

        // Condition is 1, so OP_TRUE is executed
        let val = 1u8;

        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE];

        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(1)));

        // Condition is 0, so OP_TRUE is skipped. The next op is... nothing.
        // It should end with an empty stack, which is an error.
        let val = 0u8;
        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));

        // Condition is 0, so OP_TRUE is skipped, OP_FALSE is executed.
        let val = 0u8;
        let code = [OP_PUSH_BYTE, val, OP_IF, OP_TRUE, OP_FALSE];

        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0)));
    }

    #[test]

    fn test_p2pk_script_valid() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let mut ledger = MockLedger::default();
        ledger.utxos.insert(
            output_id,
            Output::new_v1(100, &verifying_key.to_bytes(), &[0; 32]),
        );
        let msg = sighash(blake2::Blake2s256::new(), &[output_id], []);

        let signature = signing_key.sign(&msg);
        let input = Input::new(output_id, verifying_key.to_bytes(), signature.to_bytes());
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let vm = create_vm(&ledger, 0, &transaction);
        let script = p2pkh().to_vec();

        assert_eq!(vm.run(&script), Ok(OwnedStackValue::U32(0)));
    }

    #[test]
    fn test_p2pk_script_invalid() {
        let ledger = MockLedger::default();
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let other_signing_key = SigningKey::from_bytes(&[2u8; 32]);

        let tx_hash = [1u8; 32];
        let output_id = OutputId::new(tx_hash, 0);

        let msg = sighash(blake2::Blake2s256::new(), &[output_id], []);
        let signature = other_signing_key.sign(&msg);

        let input = Input::new(output_id, verifying_key.to_bytes(), signature.to_bytes());
        let transaction = Transaction {
            inputs: vec![input],
            outputs: vec![],
        };

        let vm = create_vm(&ledger, 0, &transaction);
        let script = p2pkh();

        assert_eq!(vm.run(&script), Err(ExecError::VerifyFailed));
    }

    #[test]
    fn test_op_cat() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        let code = [
            OP_PUSH_BYTE,
            1,
            OP_PUSH_BYTE,
            2,
            OP_CAT, // Concatenate the top two byte arrays
        ];
        assert_eq!(vm.run(&code), Ok(OwnedStackValue::Bytes(vec![2, 1])));
    }
    #[test]
    fn test_op_cat_dos_attack() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        // Create a script that continuously pushes onto the stack and concatenates
        let mut code = vec![];
        code.push(OP_PUSH_SIG);
        for _ in 0..32 {
            code.push(OP_DUP);
            code.push(OP_CAT); // Concatenate with the previous stack value
        }

        // Expect a stack overflow error due to excessive concatenation
        assert_eq!(vm.run(&code), Err(ExecError::StackOverflow));
    }

    #[test]
    fn test_op_push_witness() {
        let ledger = MockLedger::default();
        let mut transaction = default_transaction();
        let witness_data = [0x01, 0x02, 0x03, 0x04];
        transaction.inputs[0].witness = witness_data.to_vec();
        let vm = create_vm(&ledger, 0, &transaction);

        let result = vm.run(&[OP_PUSH_WITNESS]);
        assert_eq!(result, Ok(OwnedStackValue::Bytes(witness_data.to_vec())));
    }

    #[test]
    fn test_op_split() {
        let ledger = MockLedger::default();
        let mut transaction = default_transaction();
        let witness_data = [0x01, 0x02, 0x03, 0x04];
        transaction.inputs[0].witness = witness_data.to_vec();
        let vm = create_vm(&ledger, 0, &transaction);

        let result = vm.run(&[OP_PUSH_WITNESS, OP_SPLIT, 2]);
        assert_eq!(result, Ok(OwnedStackValue::Bytes(vec![0x03, 0x04])));
    }
    #[test]
    fn test_op_read_u32() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

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

        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U32(12345678)));
    }

    #[test]
    fn test_op_read_byte() {
        let ledger = MockLedger::default();
        let transaction = default_transaction();
        let vm = create_vm(&ledger, 0, &transaction);

        let data = [0xAB];
        let code = [OP_PUSH_BYTE, data[0], OP_READ_BYTE];

        assert_eq!(vm.run(&code), Ok(OwnedStackValue::U8(0xAB)));
    }
}
