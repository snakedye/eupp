mod fs;
mod indexer;

pub use indexer::RedbIndexer;

pub use crate::fs::FileStore;

pub trait FileStoreView {
    type Data<'a>: serde::Serialize;
    fn as_fs(&self) -> Option<&FileStore>;
}

impl FileStoreView for () {
    type Data<'a> = &'a eupp_core::block::Block;
    fn as_fs(&self) -> Option<&FileStore> {
        None
    }
}

impl FileStoreView for FileStore {
    type Data<'a> = &'a eupp_core::block::Block;
    fn as_fs(&self) -> Option<&FileStore> {
        Some(self)
    }
}
