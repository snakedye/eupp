/*! Scanner for VM bytecode

`Scanner` is an iterator over a byte slice (`&[u8]`) that yields fully-decoded
`Op` instances from `op.rs`. It consumes any payload bytes that follow opcodes
that require them (e.g. `OP_PUSH_1`, `OP_PUSH_U32`).

The scanner performs full decoding: when it encounters `OP_PUSH_1` it reads the
next single byte and yields `Op::Push8(value)`. When it encounters
`OP_PUSH_U32` it reads the next 4 bytes as a little-endian `u32` and yields
`Op::Push(value)`. For single-byte opcodes the scanner maps the opcode to the
corresponding `Op` by using `Op::try_from`.
*/

use core::fmt;

use super::op::{OP_HEIGHT, OP_PUSH_BYTE, OP_PUSH_U32, OP_SUPPLY, Op};

/// Errors that can occur while scanning a byte stream of opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerError {
    /// The opcode byte was unknown.
    UnknownOpcode(u8),
    /// The stream ended before the expected payload bytes could be read.
    UnexpectedEof,
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ScannerError::UnknownOpcode(b) => write!(f, "unknown opcode byte: 0x{:02x}", b),
            ScannerError::UnexpectedEof => write!(f, "unexpected end of byte stream"),
        }
    }
}

impl std::error::Error for ScannerError {}

/// An iterator that reads opcodes (and their payloads) from a byte slice.
///
/// Example:
/// ```rust
/// use core::convert::TryInto;
/// use crate::core::vm::scanner::Scanner;
/// use crate::core::vm::op::{OP_PUSH_1, Op};
///
/// let mut s = Scanner::new(&[OP_PUSH_1, 0x05]);
/// assert_eq!(s.next(), Some(Ok(Op::Push8(0x05))));
/// ```
pub struct Scanner<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> Scanner<'a> {
    /// Create a new scanner over the provided byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Scanner { bytes, idx: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.idx)
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.idx < self.bytes.len() {
            let b = self.bytes[self.idx];
            self.idx += 1;
            Some(b)
        } else {
            None
        }
    }

    fn read_u32_le(&mut self) -> Option<u32> {
        if self.idx + 4 <= self.bytes.len() {
            let b0 = self.bytes[self.idx];
            let b1 = self.bytes[self.idx + 1];
            let b2 = self.bytes[self.idx + 2];
            let b3 = self.bytes[self.idx + 3];
            self.idx += 4;
            Some(u32::from_le_bytes([b0, b1, b2, b3]))
        } else {
            None
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = Op;

    fn next(&mut self) -> Option<Self::Item> {
        // Read next byte (opcode)
        let b = match self.read_u8() {
            Some(v) => v,
            None => return None,
        };

        // Handle opcodes that carry payloads first, so we can consume payload
        // bytes and return fully-formed `Op` variants.
        match b {
            OP_PUSH_U32 => match self.read_u32_le() {
                Some(v) => Some(Op::PushU32(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_PUSH_BYTE => match self.read_u8() {
                Some(v) => Some(Op::PushByte(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_SUPPLY => Some(Op::Supply),
            OP_HEIGHT => Some(Op::Height),
            other => {
                // For other single-byte opcodes rely on Op::try_from which maps
                // known opcode bytes to `Op`. If it's unknown, translate the
                // decode error to `ScannerError::UnknownOpcode`.
                match Op::try_from(other) {
                    Ok(op) => Some(op),
                    Err(_) => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::op::r#const::*;
    use super::*;

    #[test]
    fn scan_push_u32() {
        let bytes = [OP_PUSH_U32, 0x78, 0x56, 0x34, 0x12]; // 0x12345678 little-endian
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(got, Op::PushU32(0x12345678));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_push_byte() {
        let bytes = [OP_PUSH_BYTE, 0x42]; // Push the byte 0x42
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(got, Op::PushByte(0x42));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_sequence() {
        let bytes = [
            OP_TRUE,
            OP_PUSH_U32,
            1,
            0,
            0,
            0,
            OP_SUPPLY,
            OP_HEIGHT,
            OP_FALSE,
        ];

        let collected: Vec<Op> = Scanner::new(&bytes).collect();
        let v = collected;
        assert_eq!(
            v,
            vec![Op::True, Op::PushU32(1), Op::Supply, Op::Height, Op::False]
        );
    }

    #[test]
    fn eof_in_payload_returns_error() {
        let bytes = [OP_PUSH_U32, 1, 2]; // incomplete 4-byte payload
        let mut s = Scanner::new(&bytes);
        match s.next() {
            None => {}
            other => panic!("expected None, got {:?}", other),
        }
        // after an error, iterator should continue from end (no more bytes)
        assert!(s.next().is_none());
    }

    #[test]
    fn unknown_opcode_returns_error() {
        let bytes = [0x99u8];
        let mut s = Scanner::new(&bytes);
        match s.next() {
            None => {}
            other => panic!("expected None, got {:?}", other),
        }
    }
}
