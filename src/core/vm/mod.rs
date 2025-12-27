/*!
VM runtime implementing opcode execution using the project's `Stack` type.

This VM:
- holds a reference to a `Ledger` implementation (read-only),
- exposes `Vm::run(&self, code: &[u8]) -> Result<Vec<u128>, VmError>`,
- decodes instructions via `Scanner` and executes them, manipulating a
  persistent `Stack<'_, u128>` value.

Notes:
- This is a simple, deterministic implementation of the opcode semantics
  described earlier. Some opcodes that normally require external data
  (signatures, transaction inputs, hashing) are implemented as placeholders
  or use ledger data where it makes sense (`Supply`, `Height`).
- The `Stack` in `stack.rs` is used directly (persistent, zero-cost linked
  list); pushes/pop/replace semantics follow that implementation's API.
*/

mod op;
mod scanner;
mod stack;

use crate::core::{ledger::Ledger, transaction::sighash};
use ed25519_dalek::Verifier;
use op::Op;
use scanner::Scanner;
use sha2::Digest;
use stack::Stack;

use super::transaction::{Input, OutputId, TransactionHash};

/// VM-level execution error kinds.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecError {
    StackUnderflow,
    VerifyFailed,
    EndOfProgram,
    TypeMismatch,
    FetchFailed,
    UnknownOpcode, // fallback if something unexpected happens
}

/// VM runtime holding a reference to a Ledger.
pub struct Vm<'a, L> {
    input: &'a Input,
    tx_hash: &'a TransactionHash,
    ledger: &'a L,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
enum StackValue<'a> {
    U32(u32),
    HashRef(&'a [u8]),
}

impl<'a> From<u32> for StackValue<'a> {
    fn from(value: u32) -> Self {
        StackValue::U32(value)
    }
}

impl<'a> From<&'a [u8]> for StackValue<'a> {
    fn from(value: &'a [u8]) -> Self {
        StackValue::HashRef(value)
    }
}

impl<'a> Into<u32> for StackValue<'a> {
    fn into(self) -> u32 {
        match self {
            StackValue::U32(value) => value,
            StackValue::HashRef(h) => h.as_ptr() as u32,
        }
    }
}

type VmStack<'a> = Stack<'a, StackValue<'a>>;

impl<'a, L: Ledger> Vm<'a, L> {
    /// Create a VM that references the provided ledger.
    pub fn new(ledger: &'a L, input: &'a Input, tx_hash: &'a TransactionHash) -> Self {
        Vm {
            ledger,
            tx_hash,
            input,
        }
    }

    /// Execute the provided bytecode slice.
    ///
    /// Returns a `u128` representing the exit code of the VM stack (top
    /// element first) after execution completes successfully. On error, a
    /// `VmError` is returned.
    pub fn run(&self, code: &[u8]) -> Result<u32, ExecError> {
        let scanner = Scanner::new(code);
        // start with an empty persistent stack
        let stack: VmStack = Stack::new();

        // iterate and execute instructions
        let mut iter = scanner;
        let exit_code = self.exec(&mut iter, stack)?;

        Ok(exit_code)
    }

    /// Execute the provided bytecode.
    fn exec<I>(&self, scanner: &mut I, mut stack: VmStack) -> Result<u32, ExecError>
    where
        I: Iterator<Item = Op>,
    {
        if let Some(op) = scanner.next() {
            let buf;
            let stack = match op {
                // Literals / stack constants
                Op::False => Ok(stack.push(0.into())),
                Op::True => Ok(stack.push(1.into())),

                // Stack manipulation
                Op::Dup => {
                    // duplicate top item
                    match stack.get() {
                        Some(&v) => Ok(stack.push(v)),
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                Op::Drop => {
                    // pop top
                    match stack.pop() {
                        Some((_v, parent)) => Ok(*parent),
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                Op::Swap => {
                    // swap top two elements
                    if let Some((a, parent1)) = stack.pop() {
                        if let Some((b, parent2)) = parent1.pop() {
                            stack = parent2.push(b);
                            Ok(stack.push(a))
                        } else {
                            Err(ExecError::StackUnderflow)
                        }
                    } else {
                        Err(ExecError::StackUnderflow)
                    }
                }

                // Immediate pushes (scanner already produces `Op::Push(u32)`)
                Op::Push(n) => Ok(stack.push(n.into())),

                // Ledger / transaction related (placeholders or small integrations)
                Op::InAmt => {
                    let utxo = self
                        .ledger
                        .get_utxo(&self.input.output_id)
                        .ok_or(ExecError::FetchFailed)?;
                    Ok(stack.push(utxo.amount.into()))
                }
                Op::InData | Op::InComm => {
                    let utxo = self
                        .ledger
                        .get_utxo(&self.input.output_id)
                        .ok_or(ExecError::FetchFailed)?;
                    buf = match op {
                        Op::InData => utxo.data,
                        Op::InComm => utxo.commitment,
                        _ => unreachable!(),
                    };
                    Ok(stack.push(StackValue::HashRef(&buf)))
                }
                Op::OutAmt | Op::OutData | Op::OutComm => {
                    // Pops index then pushes requested field; we don't have outputs
                    // context here, so implement safe behavior: pop index (if present)
                    // and push 0 as placeholder.
                    match stack.pop() {
                        Some((idx, parent)) => {
                            let index: u32 = idx.into();
                            let output_id = OutputId::new(*self.tx_hash, index as usize);
                            match self.ledger.get_utxo(&output_id) {
                                Some(output) => match op {
                                    Op::OutAmt => Ok(parent.push(StackValue::U32(output.amount))),
                                    Op::OutData => {
                                        buf = output.data;
                                        Ok(parent.push(StackValue::HashRef(&buf)))
                                    }
                                    Op::OutComm => {
                                        buf = output.commitment;
                                        Ok(parent.push(StackValue::HashRef(&buf)))
                                    }
                                    _ => unreachable!(),
                                },
                                None => Err(ExecError::FetchFailed),
                            }
                        }
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                // Op::TxFee => {
                //     // Push total fee - unknown here, push 0 placeholder.
                //     unimplemented!()
                // }

                // Chain state
                Op::Supply => {
                    // If ledger provides last block metadata, push available_supply
                    let supply = self
                        .ledger
                        .get_last_block_metadata()
                        .map(|meta| meta.available_supply.into());
                    Ok(stack.push(supply.unwrap_or(0).into()))
                }
                Op::Height => {
                    let height = self
                        .ledger
                        .get_last_block_metadata()
                        .map(|meta| meta.height.into());
                    Ok(stack.push(height.unwrap_or(0).into()))
                }

                Op::PushPk => Ok(stack.push(self.input.public_key.as_slice().into())),
                Op::PushSig => Ok(stack.push(self.input.signature.as_slice().into())),

                // Crypto & hashing (placeholders)
                Op::CheckSig => {
                    // Pops pk, sig (top is sig, next is pk) and push 1 (true) as a
                    // placeholder for 'valid signature'.
                    match stack
                        .pop()
                        .and_then(|(sig, parent)| parent.pop().map(|(pk, _)| (sig, pk)))
                    {
                        Some((StackValue::HashRef(sig), StackValue::HashRef(pk))) => {
                            let signature = ed25519_dalek::Signature::from_slice(sig)
                                .map_err(|_| ExecError::VerifyFailed)?;
                            let msg = sighash(
                                blake2::Blake2s256::new(),
                                &self.input.output_id,
                                self.ledger.get_tx_utxos(&self.tx_hash),
                            );
                            let mut pubkey = [0u8; 32];
                            pubkey.copy_from_slice(pk);
                            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
                                .map_err(|_| ExecError::VerifyFailed)?;
                            verifying_key
                                .verify(&msg, &signature)
                                .map(|_| stack.push(StackValue::U32(1)))
                                .map_err(|_| ExecError::VerifyFailed)
                        }
                        None => Err(ExecError::StackUnderflow),
                        _ => Err(ExecError::TypeMismatch),
                    }
                }
                Op::HashB2 => {
                    match stack.pop() {
                        Some((StackValue::HashRef(data), parent)) => {
                            // TODO: Implement hashing
                            buf = blake2::Blake2s256::digest(data).try_into().unwrap();
                            Ok(parent.push(StackValue::HashRef(&buf)))
                        }
                        None => Err(ExecError::StackUnderflow),
                        _ => Err(ExecError::TypeMismatch),
                    }
                }

                // Comparisons / arithmetic
                Op::Equal => match stack.pop() {
                    Some((a, parent1)) => match parent1.pop() {
                        Some((b, parent2)) => {
                            let res = (a == b) as u32;
                            Ok(parent2.push(res.into()))
                        }
                        None => Err(ExecError::StackUnderflow),
                    },
                    None => Err(ExecError::StackUnderflow),
                },
                Op::Greater => {
                    // Pops a,b pushes 1 if b>a (consistent with earlier spec)
                    match stack.pop() {
                        Some((a, parent1)) => match parent1.pop() {
                            Some((b, parent2)) => {
                                let res = (b > a) as u32;
                                Ok(parent2.push(res.into()))
                            }
                            None => Err(ExecError::StackUnderflow),
                        },
                        None => Err(ExecError::StackUnderflow),
                    }
                }
                Op::Add => {
                    // Pops a,b pushes b+a
                    match stack.pop() {
                        Some((StackValue::U32(a), parent1)) => match parent1.pop() {
                            Some((StackValue::U32(b), parent2)) => {
                                let sum = b.wrapping_add(a);
                                Ok(parent2.push(sum.into()))
                            }
                            None => Err(ExecError::StackUnderflow),
                            _ => Err(ExecError::TypeMismatch),
                        },
                        None => Err(ExecError::StackUnderflow),
                        _ => Err(ExecError::TypeMismatch),
                    }
                }
                Op::Sub => {
                    // Pops a,b pushes b-a
                    match stack.pop() {
                        Some((StackValue::U32(a), parent1)) => match parent1.pop() {
                            Some((StackValue::U32(b), parent2)) => {
                                let sum = b.wrapping_sub(a);
                                Ok(parent2.push(sum.into()))
                            }
                            None => Err(ExecError::StackUnderflow),
                            _ => Err(ExecError::TypeMismatch),
                        },
                        None => Err(ExecError::StackUnderflow),
                        _ => Err(ExecError::TypeMismatch),
                    }
                }

                // Flow control / verification
                Op::Verify => {
                    // Pops top item. If 0 -> entire transaction (script) invalid.
                    stack
                        .pop()
                        .map_or(Err(ExecError::StackUnderflow), |(v, parent)| {
                            if matches!(v, StackValue::U32(0)) {
                                Err(ExecError::VerifyFailed)
                            } else {
                                Ok(*parent)
                            }
                        })
                }
                Op::Return => {
                    // Immediately terminate the program: return current stack to
                    return stack
                        .get()
                        .copied()
                        .map(StackValue::into)
                        .ok_or(ExecError::EndOfProgram);
                }
                Op::If => {
                    // Pop condition. Skip next instruction if zero.
                    stack
                        .pop()
                        .map_or(Err(ExecError::StackUnderflow), |(cond, parent)| {
                            if matches!(cond, StackValue::U32(0)) {
                                scanner.next();
                            }
                            Ok(*parent)
                        })
                }
            }?;
            self.exec(scanner, stack)
        } else {
            return stack
                .get()
                .copied()
                .map(StackValue::into)
                .ok_or(ExecError::EndOfProgram);
        }
    }
}
