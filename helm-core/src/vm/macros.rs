use std::fmt::Debug;

use crate::vm::op::Op;

/// Trait implemented by all macro iterators that yield `Op` items.
pub trait OpMacro<'a>: Iterator<Item = Op<'a>> {
    fn dyn_clone(&self) -> Box<dyn OpMacro<'a> + 'a>;
}

// Blanket impl: every iterator that yields `Op<'a>` is automatically an `OpMacro<'a>`.
impl<'a, T: Clone + Iterator<Item = Op<'a>> + 'a> OpMacro<'a> for T {
    fn dyn_clone(&self) -> Box<dyn OpMacro<'a> + 'a> {
        Box::new(self.clone())
    }
}

// #[derive(Debug)]
/// A decoded expression produced by the [`Scanner`].
pub enum Expr<'a> {
    /// A single, immediately-available opcode.
    Op(Option<Op<'a>>),
    /// A clone-macro expansion that repeats one opcode N times.
    Iter(Box<dyn OpMacro<'a> + 'a>),
}

impl<'a> Expr<'a> {
    /// Constructs a [`Expr::Iter`] from an iterator.
    pub fn iter<I: IntoIterator<Item = Op<'a>> + 'a>(iter: I) -> Self
    where
        I::IntoIter: Clone,
    {
        Expr::Iter(Box::new(iter.into_iter()))
    }
}

impl<'a> Clone for Expr<'a> {
    fn clone(&self) -> Self {
        match self {
            Self::Op(op) => Self::Op(op.clone()),
            Self::Iter(iter) => Self::Iter(iter.dyn_clone()),
        }
    }
}

impl<'a> Debug for Expr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> PartialEq for Expr<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.clone().eq(other.clone())
    }
}

impl<'a> From<Op<'a>> for Expr<'a> {
    fn from(op: Op<'a>) -> Self {
        Expr::Op(Some(op))
    }
}

impl<'a> TryFrom<Expr<'a>> for Op<'a> {
    type Error = Expr<'a>;
    fn try_from(value: Expr<'a>) -> Result<Self, Self::Error> {
        match value {
            Expr::Op(op) => Ok(op.unwrap()),
            _ => Err(value),
        }
    }
}

impl<'a> Iterator for Expr<'a> {
    type Item = Op<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Op(op) => op.take(),
            Self::Iter(iter) => iter.next(),
        }
    }
}
