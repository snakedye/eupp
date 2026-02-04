use std::fmt::Debug;

/// A zero-cost stack based linked list.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stack<'a, T> {
    Root,
    Parent(T, &'a Stack<'a, T>),
}

impl<'a, T> Stack<'a, T> {
    /// Create a new list.
    pub fn new() -> Stack<'a, T> {
        Stack::Root
    }
    /// Push a new item at the top of the list.
    pub fn push(&'a self, data: T) -> Stack<'a, T> {
        Stack::Parent(data, self)
    }
    /// Get the item at the top of the stack.
    pub fn get(&self) -> Option<&T> {
        match self {
            Self::Root => None,
            Self::Parent(data, _) => Some(data),
        }
    }
    /// Replace the last item of the list.
    pub fn replace(&'a self, data: T) -> Stack<'a, T> {
        match self {
            Self::Root => Stack::Parent(data, self),
            Self::Parent(_, parent) => Stack::Parent(data, *parent),
        }
    }
    /// Pop the item at the top of the stack.
    pub fn pop(self) -> Option<(T, &'a Self)> {
        match self {
            Self::Root => None,
            Self::Parent(data, parent) => Some((data, parent)),
        }
    }
    pub fn chain<F, U>(&'a self, mut items: impl Iterator<Item = T>, f: F) -> U
    where
        F: FnOnce(&Stack<T>) -> U,
    {
        match items.next() {
            Some(item) => self.push(item).chain(items, f),
            None => f(self),
        }
    }
    /// Create a [`StackIter`].
    pub fn iter(&'a self) -> StackIter<'a, T> {
        StackIter(self)
    }
}

impl<'a, T: Debug> Debug for Stack<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A [`Stack`] iterator.
///
/// It iterates from the top to the bottom of the stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StackIter<'a, T>(&'a Stack<'a, T>);

impl<'a, T> StackIter<'a, T> {
    /// Creates a new `StackIter` from a reference to a `Stack`.
    pub fn new(stack: &'a Stack<T>) -> Self {
        Self(stack)
    }
    /// Returns a reference to the underlying `Stack`.
    pub fn stack(&'_ self) -> &'_ Stack<'a, T> {
        self.0
    }
    /// Returns a `TakeStackIter` that yields at most `len` elements from this iterator.
    pub fn take(self, len: usize) -> TakeStackIter<'a, T> {
        TakeStackIter { iter: self, len }
    }
}

impl<'a, T> IntoIterator for &'a Stack<'a, T> {
    type IntoIter = StackIter<'a, T>;
    type Item = &'a T;

    fn into_iter(self) -> Self::IntoIter {
        StackIter(self)
    }
}

impl<'a, T> Iterator for StackIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0 {
            Stack::Root => None,
            Stack::Parent(data, next) => {
                self.0 = *next;
                Some(data)
            }
        }
    }
}

/// An iterator that yields at most `len` elements from a [`StackIter`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TakeStackIter<'a, T> {
    iter: StackIter<'a, T>,
    len: usize,
}

impl<'a, T> Iterator for TakeStackIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            self.iter.next()
        }
    }
}
