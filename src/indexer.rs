use std::ops::{Deref, DerefMut};

use eupp_core::ledger::{Indexer, Ledger, LedgerView};

/// A wrapper around the indexer's capabilities.
pub enum AnyIndexer<I, L> {
    /// A simple indexer.
    Indexer(I),
    /// A ledger indexer.
    Ledger(L),
}

impl<I: Indexer + 'static, L: Indexer + 'static> Deref for AnyIndexer<I, L> {
    type Target = dyn Indexer;

    fn deref(&self) -> &Self::Target {
        match self {
            AnyIndexer::Indexer(indexer) => indexer,
            AnyIndexer::Ledger(ledger) => ledger,
        }
    }
}

impl<I: Indexer + 'static, L: Indexer + 'static> DerefMut for AnyIndexer<I, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            AnyIndexer::Indexer(indexer) => indexer,
            AnyIndexer::Ledger(ledger) => ledger,
        }
    }
}

impl<I, L: Ledger> LedgerView for AnyIndexer<I, L> {
    type Ledger<'a>
        = L
    where
        Self: 'a;
    fn as_ledger<'a>(&'a self) -> Option<&'a L> {
        match self {
            Self::Indexer(_) => None,
            Self::Ledger(ledger) => Some(ledger),
        }
    }
}
