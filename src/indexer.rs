use std::ops::{Deref, DerefMut};

use eupp_core::TryAsRef;
use eupp_core::ledger::{Indexer, Ledger};

/// A runtime-polymorphic wrapper over two [`Indexer`] implementations.
///
/// `NodeStore` lets the node choose at startup whether to run with a pruned
/// store (UTXO set and metadata only) or a full store (indexer + on-disk block
/// storage) without introducing trait-object overhead on every call site. The
/// enum delegates to the concrete variant through its [`Deref`]/[`DerefMut`]
/// impls, which erase the concrete type behind `dyn Indexer`.
///
/// Use [`TryAsRef::<dyn Ledger>::try_as_ref`] to conditionally access
/// ledger-specific capabilities (e.g. fetching full blocks) when the `Full`
/// variant is active.
pub enum NodeStore<I, L> {
    /// A pruned store – tracks the UTXO set and block metadata but discards
    /// full blocks and cannot retrieve them from disk.
    Pruned(I),
    /// A full store – an indexer backed by on-disk block storage, capable of
    /// serving complete block data.
    Full(L),
}

impl<I: Indexer + 'static, L: Indexer + 'static> Deref for NodeStore<I, L> {
    type Target = dyn Indexer;

    fn deref(&self) -> &Self::Target {
        match self {
            NodeStore::Pruned(indexer) => indexer,
            NodeStore::Full(ledger) => ledger,
        }
    }
}

impl<I: Indexer + 'static, L: Indexer + 'static> DerefMut for NodeStore<I, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            NodeStore::Pruned(indexer) => indexer,
            NodeStore::Full(ledger) => ledger,
        }
    }
}

/// Provides optional access to the inner [`Ledger`] when the `Full` variant
/// is active. Returns [`None`] for the `Pruned` variant, signalling that
/// full-block retrieval is unavailable.
impl<I, L: Ledger + 'static> TryAsRef<dyn Ledger> for NodeStore<I, L> {
    fn try_as_ref(&self) -> Option<&(dyn Ledger + 'static)> {
        match self {
            Self::Pruned(_) => None,
            Self::Full(ledger) => Some(ledger),
        }
    }
}
