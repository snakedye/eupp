#![allow(clippy::upper_case_acronyms)]
//! Opcode definitions and `Op` enum for the VM.
//!
//! This file places all opcode byte constants in a child `const` module and
//! re-exports them at the module root. The `Op` enum and conversions remain
//! defined here so callers can use `Op` alongside the opcode values.

/// Opcode constants are collected in this submodule so they are grouped and
/// can be managed independently of the `Op` type.
pub mod r#const {
    //! Raw opcode byte values.

    // Stack / VM opcodes
    pub const OP_FALSE: u8 = 0x00;
    pub const OP_TRUE: u8 = 0x01;
    pub const OP_DUP: u8 = 0x02;
    pub const OP_DROP: u8 = 0x03;
    pub const OP_SWAP: u8 = 0x04;
    /// Push a 32-bit unsigned integer (4 bytes follow the opcode, little-endian).
    pub const OP_PUSH_U32: u8 = 0x06;
    /// Push a single byte onto the stack.
    pub const OP_PUSH_BYTE: u8 = 0x07;

    pub const OP_SELF_AMT: u8 = 0x10;
    pub const OP_SELF_DATA: u8 = 0x11;
    pub const OP_SELF_COMM: u8 = 0x12;
    pub const OP_OUT_AMT: u8 = 0x13;
    pub const OP_OUT_DATA: u8 = 0x14;
    pub const OP_OUT_COMM: u8 = 0x15;
    // pub const OP_TX_FEE: u8 = 0x16;

    /// Pushes the sighash for all inputs and outputs onto the stack.
    pub const OP_SIGHASH_ALL: u8 = 0x60;
    /// Pushes the sighash for only the outputs onto the stack.
    pub const OP_SIGHASH_OUT: u8 = 0x61;

    /// Push current total supply onto the stack.
    pub const OP_SUPPLY: u8 = 0x50;

    /// Push current block height onto the stack.
    pub const OP_HEIGHT: u8 = 0x51;

    pub const OP_PUSH_PK: u8 = 0x20;
    pub const OP_PUSH_SIG: u8 = 0x21;
    /// Pushes the witness data onto the stack.
    pub const OP_PUSH_WITNESS: u8 = 0x22;

    pub const OP_CHECKSIG: u8 = 0x30;
    pub const OP_HASH_B2: u8 = 0x31;
    pub const OP_EQUAL: u8 = 0x32;
    /// Pops `n` items, hashes them using Blake2s256, and pushes the result.
    pub const OP_MUL_HASH_B2: u8 = 0x36;
    pub const OP_GREATER: u8 = 0x33;
    /// Concatenate the top two byte arrays on the stack.
    pub const OP_CAT: u8 = 0x37;
    pub const OP_ADD: u8 = 0x34;
    pub const OP_SUB: u8 = 0x35;
    /// Splits a slice into two at a given index (u8).
    pub const OP_SPLIT: u8 = 0x38;
    /// Reads a byte slice from the stack and casts it into a u32.
    pub const OP_READ_U32: u8 = 0x39;
    /// Reads a byte slice from the stack and casts it into a single byte.
    pub const OP_READ_BYTE: u8 = 0x3A;

    pub const OP_VERIFY: u8 = 0x40;
    pub const OP_RETURN: u8 = 0x41;
    pub const OP_IF: u8 = 0x42;
    pub const OP_END_IF: u8 = 0x43;
}

// Re-export the constants so existing imports like `use crate::core::vm::op::OP_TRUE`
// continue to work.
pub use r#const::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Pushes an empty array (0) onto the stack.
    False,
    /// Pushes a 1 onto the stack.
    True,
    /// Duplicates the top item on the stack.
    Dup,
    /// Removes the top item from the stack.
    Drop,
    /// Swaps the top two items on the stack.
    Swap,
    /// Pushes a 32-bit unsigned integer (u32) onto the stack.
    ///
    /// Encoding: `[OP_PUSH_U32][u32 le bytes...]`.
    PushU32(u32),
    /// Pushes a single byte onto the stack.
    ///
    /// Encoding: `[OP_PUSH_BYTE][u8 byte...]`.
    PushByte(u8),

    /// Pushes the Amount of the UTXO being spent.
    SelfAmt,
    /// Pushes the Data Hash of the UTXO being spent.
    SelfData,
    /// Pushes the Commitment of the UTXO being spent.
    SelfComm,
    /// Pops index, pushes Amount of Output[index].
    OutAmt(u8),
    /// Pops index, pushes Data Hash of Output[index].
    OutData(u8),
    /// Pops index, pushes Commitment of Output[index].
    OutComm(u8),
    /// Pushes the current total supply of the currency onto the stack.
    Supply,
    /// Pushes the current block height onto the stack.
    Height,

    /// Pushes the 32-byte Public Key from the input.
    PushPk,
    /// Pushes the 64-byte Signature from the input.
    PushSig,

    /// Pops pk, sig. Checks Ed25519 signature against the transaction sighash.
    CheckSig,
    /// Pops data, pushes Blake2s256 hash.
    HashB2,
    /// Pops two items, pushes 1 if equal, 0 otherwise.
    Equal,
    /// Pops `n` items, hashes them using Blake2s256, and pushes the result.
    MulHashB2(u8),
    /// Pops a, b. Pushes 1 if b > a.
    Greater,
    /// Concatenates the top two byte arrays on the stack.
    Cat,
    /// Pops a, b. Pushes a + b.
    Add,
    /// Pops a, b. Pushes b − a.
    Sub,

    /// Pops top item. If 0 (False), the entire transaction is invalid.
    Verify,
    /// Immediately terminates the script.
    Return,
    /// Executes subsequent code only if the top item is non-zero.
    If,
    /// Mark the end of an if block.
    EndIf,
    /// Pushes the sighash for all inputs and outputs onto the stack.
    SighashAll,
    /// Pushes the sighash for only the outputs onto the stack.
    SighashOut,
    /// Pushes the witness data onto the stack.
    PushWitness,
    /// Splits a slice into two at a given index (u8).
    Split(u8),
    /// Reads a byte slice from the stack and casts it into a u32.
    ReadU32,
    /// Reads a byte slice from the stack and casts it into a single byte.
    ReadByte,
}

/// Error returned when decoding an opcode byte into an `Op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpDecodeError(pub u8);

impl OpDecodeError {
    /// Returns the unknown opcode byte.
    pub fn unknown_byte(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for OpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown opcode byte: 0x{:02x}", self.0)
    }
}

impl std::error::Error for OpDecodeError {}

impl core::convert::TryFrom<u8> for Op {
    type Error = OpDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            OP_FALSE => Ok(Op::False),
            OP_TRUE => Ok(Op::True),
            OP_DUP => Ok(Op::Dup),
            OP_DROP => Ok(Op::Drop),
            OP_SWAP => Ok(Op::Swap),
            OP_PUSH_U32 => Ok(Op::PushU32(0)), // placeholder; Scanner must read 4 bytes after opcode
            OP_PUSH_BYTE => Ok(Op::PushByte(0)), // placeholder; Scanner must read 1 byte after opcode

            OP_SELF_AMT => Ok(Op::SelfAmt),
            OP_SELF_DATA => Ok(Op::SelfData),
            OP_SELF_COMM => Ok(Op::SelfComm),
            OP_OUT_AMT => Ok(Op::OutAmt(0)), // placeholder; Scanner must read 1 byte after opcode
            OP_OUT_DATA => Ok(Op::OutData(0)), // placeholder; Scanner must read 1 byte after opcode
            OP_OUT_COMM => Ok(Op::OutComm(0)), // placeholder; Scanner must read 1 byte after opcode
            OP_SUPPLY => Ok(Op::Supply),
            OP_HEIGHT => Ok(Op::Height),

            OP_PUSH_PK => Ok(Op::PushPk),
            OP_PUSH_SIG => Ok(Op::PushSig),

            OP_CHECKSIG => Ok(Op::CheckSig),
            OP_HASH_B2 => Ok(Op::HashB2),
            OP_EQUAL => Ok(Op::Equal),
            OP_GREATER => Ok(Op::Greater),
            OP_CAT => Ok(Op::Cat),
            OP_ADD => Ok(Op::Add),
            OP_SUB => Ok(Op::Sub),

            OP_VERIFY => Ok(Op::Verify),
            OP_MUL_HASH_B2 => Ok(Op::MulHashB2(0)), // placeholder; Scanner must read 1 byte after opcode
            OP_RETURN => Ok(Op::Return),
            OP_SIGHASH_ALL => Ok(Op::SighashAll),
            OP_IF => Ok(Op::If),
            OP_SIGHASH_OUT => Ok(Op::SighashOut),
            OP_PUSH_WITNESS => Ok(Op::PushWitness),
            OP_END_IF => Ok(Op::EndIf),
            OP_SPLIT => Ok(Op::Split(0)),
            OP_READ_U32 => Ok(Op::ReadU32),
            OP_READ_BYTE => Ok(Op::ReadByte),

            other => Err(OpDecodeError(other)),
        }
    }
}

impl From<Op> for u8 {
    fn from(op: Op) -> u8 {
        match op {
            Op::False => OP_FALSE,
            Op::True => OP_TRUE,
            Op::Dup => OP_DUP,
            Op::Drop => OP_DROP,
            Op::Swap => OP_SWAP,
            Op::PushU32(_) => OP_PUSH_U32,
            Op::PushByte(_) => OP_PUSH_BYTE,

            Op::SelfAmt => OP_SELF_AMT,
            Op::SelfData => OP_SELF_DATA,
            Op::SelfComm => OP_SELF_COMM,
            Op::OutAmt(_) => OP_OUT_AMT,
            Op::OutData(_) => OP_OUT_DATA,
            Op::OutComm(_) => OP_OUT_COMM,
            Op::Supply => OP_SUPPLY,
            Op::Height => OP_HEIGHT,

            Op::PushPk => OP_PUSH_PK,
            Op::PushSig => OP_PUSH_SIG,

            Op::CheckSig => OP_CHECKSIG,
            Op::HashB2 => OP_HASH_B2,
            Op::Equal => OP_EQUAL,
            Op::Greater => OP_GREATER,
            Op::Cat => OP_CAT,
            Op::Add => OP_ADD,
            Op::Sub => OP_SUB,

            Op::Verify => OP_VERIFY,
            Op::MulHashB2(_) => OP_MUL_HASH_B2,
            Op::Return => OP_RETURN,
            Op::If => OP_IF,
            Op::SighashAll => OP_SIGHASH_ALL,
            Op::EndIf => OP_END_IF,
            Op::SighashOut => OP_SIGHASH_OUT,
            Op::PushWitness => OP_PUSH_WITNESS,
            Op::Split(_) => OP_SPLIT,
            Op::ReadU32 => OP_READ_U32,
            Op::ReadByte => OP_READ_BYTE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

    #[test]
    fn roundtrip_all_simple_ops() {
        let all = [
            Op::False,
            Op::True,
            Op::Dup,
            Op::Drop,
            Op::Swap,
            Op::PushU32(0),
            Op::SelfAmt,
            Op::SelfData,
            Op::SelfComm,
            Op::OutAmt(0),
            Op::OutData(0),
            Op::OutComm(0),
            Op::Supply,
            Op::Height,
            Op::PushPk,
            Op::PushSig,
            Op::CheckSig,
            Op::HashB2,
            Op::Equal,
            Op::Greater,
            Op::Cat,
            Op::Add,
            Op::Sub,
            Op::Verify,
            Op::Return,
            Op::If,
            Op::EndIf,
            Op::PushByte(0),
            Op::MulHashB2(0),
            Op::Verify,
            Op::Return,
            Op::If,
            Op::EndIf,
            Op::SighashAll,
            Op::SighashOut,
            Op::PushWitness,
            Op::Split(0),
            Op::ReadU32,
            Op::ReadByte,
        ];

        for &op in &all {
            let b: u8 = op.into();
            let parsed = Op::try_from(b).expect("opcode should parse");
            assert_eq!(parsed, op);
        }
    }

    #[test]
    fn push_u32_into_opcode_byte() {
        let op = Op::PushU32(0x12345678);
        let b: u8 = op.into();
        assert_eq!(b, OP_PUSH_U32);
    }

    #[test]
    fn push_u32_tryfrom_returns_placeholder() {
        // TryFrom only inspects the opcode byte; it cannot read the following
        // 4 payload bytes. We expect a placeholder Push(0).
        let parsed = Op::try_from(OP_PUSH_U32).expect("should parse push opcode");
        assert_eq!(parsed, Op::PushU32(0));
    }

    #[test]
    fn push_byte_tryfrom_returns_placeholder() {
        // TryFrom only inspects the opcode byte; it cannot read the following
        // payload byte. We expect a placeholder PushByte(0).
        let parsed = Op::try_from(OP_PUSH_BYTE).expect("should parse push opcode");
        assert_eq!(parsed, Op::PushByte(0));
    }

    #[test]
    fn supply_height_and_out_ops_bytes() {
        let s: u8 = Op::Supply.into();
        let h: u8 = Op::Height.into();
        let out_amt: u8 = Op::OutAmt(42).into();
        let out_data: u8 = Op::OutData(42).into();
        let out_comm: u8 = Op::OutComm(42).into();

        assert_eq!(s, OP_SUPPLY);
        assert_eq!(out_amt, OP_OUT_AMT);
        assert_eq!(out_data, OP_OUT_DATA);
        assert_eq!(out_comm, OP_OUT_COMM);
        assert_eq!(h, OP_HEIGHT);

        let ps = Op::try_from(s).unwrap();
        let ph = Op::try_from(h).unwrap();
        let parsed_out_amt = Op::try_from(out_amt).unwrap();
        let parsed_out_data = Op::try_from(out_data).unwrap();
        let parsed_out_comm = Op::try_from(out_comm).unwrap();

        assert_eq!(ps, Op::Supply);
        assert_eq!(parsed_out_amt, Op::OutAmt(0));
        assert_eq!(parsed_out_data, Op::OutData(0));
        assert_eq!(parsed_out_comm, Op::OutComm(0));
        assert_eq!(ph, Op::Height);
    }

    #[test]
    fn unknown_byte_returns_err() {
        // pick some unused opcode
        let err = Op::try_from(0x99_u8).unwrap_err();
        assert_eq!(err, OpDecodeError(0x99));
    }
}

#[test]
fn mul_hash_b2_tryfrom_returns_placeholder() {
    // TryFrom only inspects the opcode byte; it cannot read the following
    // payload byte. We expect a placeholder MulHashB2(0).
    let parsed = Op::try_from(OP_MUL_HASH_B2).expect("should parse mul_hash_b2 opcode");
    assert_eq!(parsed, Op::MulHashB2(0));
}
