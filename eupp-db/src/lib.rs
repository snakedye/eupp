mod fs;
mod indexer;

pub use fs::FileStore;
pub use indexer::RedbIndexer;

use eupp_core::TryAsRef;

impl TryAsRef<FileStore> for () {
    fn try_as_ref(&self) -> Option<&FileStore> {
        None
    }
}
