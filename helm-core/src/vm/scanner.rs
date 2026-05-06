/*! Scanner for VM bytecode

`Scanner` is an iterator over a byte slice (`&[u8]`) that yields fully-decoded
`Op` instances from `op.rs`. It consumes any payload bytes that follow opcodes
that require them (e.g. `OP_PUSH_1`, `OP_PUSH_U32`).
*/

use crate::vm::{
    macros::Expr,
    op::{OP_ENDIF, OP_EQUAL, OP_ERR, OP_FALSE, OP_IF, OP_TRUE},
};

use super::op::{
    OP_CHECKSIG, OP_CLONE, OP_ENDPRAGMA, OP_OUT_AMT, OP_OUT_COMM, OP_OUT_DATA, OP_PRAGMA,
    OP_PUSH_BYTE, OP_PUSH_BYTES, OP_PUSH_PK, OP_PUSH_SIG, OP_PUSH_U32, OP_SPLIT, OP_SWAP,
    OP_VERIFY, OP_VERIFYSIG, Op,
};

#[derive(Clone, Copy, PartialEq)]
/// An iterator that reads opcodes (and their payloads) from a byte slice.
pub struct Scanner<'a> {
    bytes: &'a [u8],
}

impl<'a> Scanner<'a> {
    /// Create a new scanner over the provided byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Scanner { bytes }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let (b, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(*b)
    }

    fn read_exact(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < n {
            return None;
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Some(head)
    }

    fn read_u32_le(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.read_exact(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn fail_eof(&mut self) -> Option<Expr<'a>> {
        self.bytes = &[];
        None
    }

    fn read_pragma_body(&mut self) -> Option<&'a [u8]> {
        let end = self.bytes.iter().position(|b| *b == OP_ENDPRAGMA)?;
        let (body, rest) = self.bytes.split_at(end);
        self.bytes = rest.split_first()?.1;
        Some(body)
    }
}

impl<'a> std::fmt::Debug for Scanner<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.into_iter()).finish()
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = Expr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read next byte (opcode)
        let b = self.read_u8()?;

        // Handle opcodes that carry payloads first, so we can consume payload
        // bytes and return fully-formed `Op` variants.
        match b {
            OP_TRUE => Some(Op::PushByte(1).into()),
            OP_FALSE => Some(Op::PushByte(0).into()),
            OP_CLONE => {
                let count = self.read_u8()?;
                let expr = self.next()?;
                Some(Expr::iter(
                    std::iter::repeat_n(expr, count as usize).flatten(),
                ))
            }

            OP_PUSH_U32 => match self.read_u32_le() {
                Some(v) => Some(Op::PushU32(v).into()),
                None => self.fail_eof(),
            },
            OP_PUSH_BYTE => match self.read_u8() {
                Some(v) => Some(Op::PushByte(v).into()),
                None => self.fail_eof(),
            },
            OP_OUT_AMT => Some(Op::OutAmt.into()),
            OP_OUT_DATA => Some(Op::OutData.into()),
            OP_OUT_COMM => Some(Op::OutComm.into()),
            OP_SPLIT => match self.read_u8() {
                Some(v) => Some(Op::Split(v).into()),
                None => self.fail_eof(),
            },
            OP_LOAD => match self.read_u8() {
                Some(v) => Some(Op::Load(v).into()),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_STORE => match self.read_u8() {
                Some(v) => Some(Op::Store(v).into()),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_PUSH_BYTES => match self.read_u8() {
                Some(n) => match self.read_exact(n as usize) {
                    Some(slice) => Some(Op::PushBytes(slice).into()),
                    None => self.fail_eof(),
                },
                None => self.fail_eof(),
            },
            OP_VERIFYSIG => Some(Expr::iter(
                Scanner::new(&[OP_PUSH_SIG, OP_SWAP, OP_PUSH_PK, OP_CHECKSIG, OP_VERIFY]).flatten(),
            )),
            OP_VERIFY => Some(Expr::iter(
                Scanner::new(&[OP_FALSE, OP_EQUAL, OP_IF, OP_ERR, OP_ENDIF]).flatten(),
            )),
            OP_PRAGMA => match self.read_pragma_body() {
                Some(body) => Some(Expr::iter(Scanner::new(body).flatten())),
                None => self.fail_eof(),
            },
            OP_ENDPRAGMA => self.fail_eof(),
            // For other single-byte opcodes rely on Op::try_from
            other => Op::try_from(other).ok().map(Expr::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::op::Op;
    use super::super::op::r#const::*;
    use super::*;

    #[test]
    fn scan_push_u32() {
        let bytes = [OP_PUSH_U32, 0x78, 0x56, 0x34, 0x12]; // 0x12345678 little-endian
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(Op::PushU32(0x12345678), got.try_into().unwrap());
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_push_byte() {
        let bytes = [OP_PUSH_BYTE, 0x42]; // Push the byte 0x42
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(Op::PushByte(0x42), got.try_into().unwrap());
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_sequence_with_out_ops() {
        let bytes = [
            OP_TRUE,
            OP_PUSH_U32,
            1,
            0,
            0,
            0,
            OP_PUSH_SUPPLY,
            OP_PUSH_HEIGHT,
            OP_FALSE,
            OP_PUSH_BYTE,
            0x01,
            OP_OUT_AMT,
            OP_PUSH_BYTE,
            0x02,
            OP_OUT_DATA,
            OP_PUSH_BYTE,
            0x03,
            OP_OUT_COMM,
            OP_SIGHASH_ALL,
            OP_SPLIT,
            1,
            OP_PUSH_BYTES,
            3,
            0xAA,
            0xBB,
            0xCC,
        ];

        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        let v = collected;
        assert_eq!(
            v,
            vec![
                Op::PushByte(1),
                Op::PushU32(1),
                Op::Supply,
                Op::Height,
                Op::PushByte(0),
                Op::PushByte(1),
                Op::OutAmt,
                Op::PushByte(2),
                Op::OutData,
                Op::PushByte(3),
                Op::OutComm,
                Op::SighashAll,
                Op::Split(1),
                Op::PushBytes(&[0xAA, 0xBB, 0xCC])
            ]
        );
    }

    #[test]
    fn eof_in_payload_returns_error() {
        let bytes = [OP_PUSH_U32, 1, 2]; // incomplete 4-byte payload
        let mut s = Scanner::new(&bytes);
        match s.next() {
            None => {}
            _ => panic!("expected None, got Expr"),
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
            _ => panic!("expected None, got Expr"),
        }
    }

    #[test]
    fn scan_clone_macro_simple() {
        let bytes = [OP_CLONE, 3, OP_TRUE];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![Op::PushByte(1), Op::PushByte(1), Op::PushByte(1)]
        );
    }

    #[test]
    fn scan_clone_macro_with_payload_op() {
        let bytes = [OP_CLONE, 2, OP_PUSH_BYTE, 0x42];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(collected, vec![Op::PushByte(0x42), Op::PushByte(0x42)]);
    }

    #[test]
    fn scan_clone_macro_in_sequence() {
        let bytes = [OP_TRUE, OP_CLONE, 2, OP_FALSE, OP_TRUE];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![
                Op::PushByte(1),
                Op::PushByte(0),
                Op::PushByte(0),
                Op::PushByte(1),
            ]
        );
    }

    #[test]
    fn scan_verifysig_macro() {
        let bytes = [OP_VERIFYSIG];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![
                Op::PushSig,
                Op::Swap,
                Op::PushPk,
                Op::CheckSig,
                Op::PushByte(0),
                Op::Equal,
                Op::If,
                Op::Err,
                Op::EndIf,
            ]
        );
    }

    #[test]
    fn scan_verifysig_macro_in_sequence() {
        let bytes = [OP_TRUE, OP_VERIFYSIG, OP_FALSE];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![
                Op::PushByte(1),
                Op::PushSig,
                Op::Swap,
                Op::PushPk,
                Op::CheckSig,
                Op::PushByte(0),
                Op::Equal,
                Op::If,
                Op::Err,
                Op::EndIf,
                Op::PushByte(0),
            ]
        );
    }

    #[test]
    fn scan_pragma_sequence_macro() {
        let bytes = [OP_PRAGMA, OP_TRUE, OP_FALSE, OP_ENDPRAGMA];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(collected, vec![Op::PushByte(1), Op::PushByte(0)]);
    }

    #[test]
    fn scan_pragma_sequence_macro_in_sequence() {
        let bytes = [
            OP_TRUE,
            OP_PRAGMA,
            OP_PUSH_BYTE,
            0x2A,
            OP_ENDPRAGMA,
            OP_FALSE,
        ];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![Op::PushByte(1), Op::PushByte(0x2A), Op::PushByte(0)]
        );
    }

    #[test]
    fn scan_clone_macro_with_pragma() {
        let bytes = [OP_CLONE, 2, OP_PRAGMA, OP_TRUE, OP_FALSE, OP_ENDPRAGMA];
        let collected: Vec<Op> = Scanner::new(&bytes).flatten().collect();
        assert_eq!(
            collected,
            vec![
                Op::PushByte(1),
                Op::PushByte(0),
                Op::PushByte(1),
                Op::PushByte(0),
            ]
        );
    }

    #[test]
    fn scan_pragma_without_end_returns_error() {
        let bytes = [OP_PRAGMA, OP_TRUE];
        let mut s = Scanner::new(&bytes);
        assert_eq!(s.next(), None);
        assert_eq!(s.next(), None);
    }
}
