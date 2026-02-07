use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::{error::Error, fmt};

use serde_json;

use eupp_core::block::Block;

/// Errors produced by the file-backed ledger.
#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

impl From<serde_json::Error> for LedgerError {
    fn from(e: serde_json::Error) -> Self {
        LedgerError::Serde(e)
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "io error: {}", e),
            LedgerError::Serde(e) => write!(f, "serialization error: {}", e),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LedgerError::Io(e) => Some(e),
            LedgerError::Serde(e) => Some(e),
        }
    }
}

/// A very small file-backed block store. Blocks are appended to the end of the file
/// as JSON (via `serde_json`).
pub struct FileBlockStore {
    file: Mutex<File>,
}

impl FileBlockStore {
    /// Create a new file-backed block store for the given path. The file will be created if it
    /// does not exist. The underlying file handle is opened and kept open for the lifetime of
    /// the store.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let path = path.into();
        // Open the file for read+append and create it if missing. Keep the handle open.
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        Ok(FileBlockStore {
            file: Mutex::new(f),
        })
    }

    /// Append a block to the file. Returns (start_offset, len_bytes_written).
    ///
    /// Note: the function writes only the raw JSON bytes. It does not write any framing or
    /// length prefix. The caller must retain the returned length in order to be able to read
    /// the block later using `get_block`.
    pub fn append_block(&self, block: &Block) -> Result<(u64, usize), LedgerError> {
        // Serialize the block to JSON bytes
        let bytes = serde_json::to_vec(block)?;

        // Lock the file handle
        let mut file = self.file.lock().unwrap();

        // Seek to the end to find the starting offset.
        let start = file.seek(SeekFrom::End(0))?;

        // Write bytes
        file.write_all(&bytes)?;
        file.flush()?;

        Ok((start, bytes.len()))
    }

    /// Read a block from the file at the given cursor (byte offset) and length (in bytes).
    /// The function reads exactly `len` bytes starting at `cursor`, then deserializes them
    /// using `serde_json` and returns the `Block`.
    pub fn get_block(&self, pos: u64, len: usize) -> Result<Block, LedgerError> {
        // Lock the file handle
        let mut file = self.file.lock().unwrap();

        file.seek(SeekFrom::Start(pos))?;

        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;

        let block: Block = serde_json::from_slice(&buf)?;
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    use eupp_core::block::Block as CoreBlock;
    use eupp_core::transaction::Output;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("eupp_db_ledger_test_{}.dat", name));
        // ensure clean file
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn append_and_get_block_roundtrip() {
        let path = temp_path("roundtrip");
        let store = FileBlockStore::new(&path).expect("create store");

        // Build a simple block
        let mut block = CoreBlock::new(0, [0u8; 32]);
        let tx = eupp_core::transaction::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(123, &[1u8; 32], &[2u8; 32])],
        };
        block.transactions.push(tx);

        let (cursor, len) = store.append_block(&block).expect("append");
        let read = store.get_block(cursor, len).expect("read");
        assert_eq!(block.header().hash(), read.header().hash());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_and_get_second_block() {
        let path = temp_path("second_block");
        let store = FileBlockStore::new(&path).expect("create store");

        // Build the first block
        let mut block1 = CoreBlock::new(0, [0u8; 32]);
        let tx1 = eupp_core::transaction::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(789, &[5u8; 32], &[6u8; 32])],
        };
        block1.transactions.push(tx1);

        // Append the first block
        let (cursor1, len1) = store.append_block(&block1).expect("append first block");

        // Build the second block
        let mut block2 = CoreBlock::new(1, [1u8; 32]);
        let tx2 = eupp_core::transaction::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(101112, &[7u8; 32], &[8u8; 32])],
        };
        block2.transactions.push(tx2);

        // Append the second block
        let (cursor2, len2) = store.append_block(&block2).expect("append second block");

        // Read the first block
        let read_first = store.get_block(cursor1, len1).expect("read first block");
        assert_eq!(block1.header().hash(), read_first.header().hash());

        // Read the second block
        let read = store.get_block(cursor2, len2).expect("read second block");
        assert_eq!(block2.header().hash(), read.header().hash());

        let _ = fs::remove_file(&path);
    }
}
