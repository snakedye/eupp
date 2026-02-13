use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

/// Errors produced by the file-backed ledger.
#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Postcard(postcard::Error),
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

impl From<postcard::Error> for LedgerError {
    fn from(e: postcard::Error) -> Self {
        LedgerError::Postcard(e)
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "io error: {}", e),
            LedgerError::Postcard(e) => write!(f, "serialization error: {}", e),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LedgerError::Io(e) => Some(e),
            LedgerError::Postcard(e) => Some(e),
        }
    }
}

/// A very small file-backed block store. Blocks are appended as JSON and buffered in
/// memory until `commit` is called.
pub struct FileStore {
    inner: Mutex<(File, Vec<u8>)>,
    file_end: AtomicU64,
}

impl AsRef<Self> for FileStore {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl FileStore {
    /// Create a new file-backed block store for the given path. The file will be created if it
    /// does not exist. The underlying file handle is opened and kept open for the lifetime of
    /// the store.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let path = path.into();
        // Open the file for read+append and create it if missing. Keep the handle open.
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let file_end = f.seek(SeekFrom::End(0))?;
        Ok(FileStore {
            inner: Mutex::new((f, Vec::new())),
            file_end: AtomicU64::new(file_end),
        })
    }

    /// Buffer a block for writing. The block is only persisted on `commit`.
    /// Returns (start_offset, len_bytes).
    pub fn append<T: Serialize>(&self, data: &T) -> Result<(u64, usize), LedgerError> {
        let bytes = postcard::to_allocvec(data)?;
        let mut inner = self.inner.lock().unwrap();
        let (_, ref mut buf) = *inner;
        let start = self.file_end.load(Ordering::Acquire) + buf.len() as u64;
        buf.extend_from_slice(&bytes);
        buf.push(b'\n');
        Ok((start, bytes.len()))
    }

    /// Flush buffered blocks to disk.
    pub fn commit(&self) -> Result<(), LedgerError> {
        let (ref mut file, ref mut buf) = *self.inner.lock().unwrap();
        if buf.is_empty() {
            return Ok(());
        }
        file.write_all(buf)?;
        file.flush()?;
        self.file_end.fetch_add(buf.len() as u64, Ordering::Release);
        buf.clear();
        Ok(())
    }

    /// Read a block at the given byte offset and length. Works for both committed
    /// and uncommitted (buffered) blocks.
    pub fn get<T>(&self, pos: u64, len: usize) -> Result<T, LedgerError>
    where
        for<'a> T: Deserialize<'a>,
    {
        let file_end = self.file_end.load(Ordering::Acquire);
        let (ref mut file, ref buf) = *self.inner.lock().unwrap();
        let bytes = if pos + len as u64 <= file_end {
            file.seek(SeekFrom::Start(pos))?;
            let mut b = vec![0u8; len];
            file.read_exact(&mut b)?;
            b
        } else {
            let start = (pos - file_end) as usize;
            buf.get(start..start + len)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "read past end of buffer",
                    )
                })?
                .to_vec()
        };
        Ok(postcard::from_bytes(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    use eupp_core::{Block, Output};

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
        let store = FileStore::new(&path).expect("create store");

        // Build a simple block
        let mut block = Block::new(0, [0u8; 32]);
        let tx = eupp_core::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(123, &[1u8; 32], &[2u8; 32])],
        };
        block.transactions.push(tx);

        let (cursor, len) = store.append(&block).expect("append");

        // Block should be readable from the buffer before commit.
        let read: Block = store.get(cursor, len).expect("read before commit");
        assert_eq!(block.header().hash(), read.header().hash());

        // Commit to disk and verify it's still readable.
        store.commit().expect("commit");
        let read: Block = store.get(cursor, len).expect("read after commit");
        assert_eq!(block.header().hash(), read.header().hash());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_and_get_second_block() {
        let path = temp_path("second_block");
        let store = FileStore::new(&path).expect("create store");

        // Build the first block
        let mut block1 = Block::new(0, [0u8; 32]);
        let tx1 = eupp_core::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(789, &[5u8; 32], &[6u8; 32])],
        };
        block1.transactions.push(tx1);

        // Append the first block
        let (cursor1, len1) = store.append(&block1).expect("append first block");

        // Build the second block
        let mut block2 = Block::new(1, [1u8; 32]);
        let tx2 = eupp_core::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(101112, &[7u8; 32], &[8u8; 32])],
        };
        block2.transactions.push(tx2);

        // Append the second block
        let (cursor2, len2) = store.append(&block2).expect("append second block");

        // Both blocks should be readable from the buffer before commit.
        let read_first: Block = store
            .get(cursor1, len1)
            .expect("read first block before commit");
        assert_eq!(block1.header().hash(), read_first.header().hash());

        let read_second: Block = store
            .get(cursor2, len2)
            .expect("read second block before commit");
        assert_eq!(block2.header().hash(), read_second.header().hash());

        // Commit to disk and verify both are still readable.
        store.commit().expect("commit");

        let read_first: Block = store
            .get(cursor1, len1)
            .expect("read first block after commit");
        assert_eq!(block1.header().hash(), read_first.header().hash());

        let read_second: Block = store
            .get(cursor2, len2)
            .expect("read second block after commit");
        assert_eq!(block2.header().hash(), read_second.header().hash());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn uncommitted_block_not_persisted() {
        let path = temp_path("uncommitted");
        let mut block = Block::new(0, [0u8; 32]);
        let tx = eupp_core::Transaction {
            inputs: vec![],
            outputs: vec![Output::new_v1(456, &[3u8; 32], &[4u8; 32])],
        };
        block.transactions.push(tx);

        // Append without committing, then drop the store.
        let (cursor, len) = {
            let store = FileStore::new(&path).expect("create store");
            let result = store.append(&block).expect("append");
            // deliberately no commit
            result
        };

        // Re-open the file — the block should not be there.
        let store = FileStore::new(&path).expect("reopen store");
        assert!(store.get::<Block>(cursor, len).is_err());

        let _ = fs::remove_file(&path);
    }
}
