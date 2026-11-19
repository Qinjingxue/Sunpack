//! Request-local result blocks. Recursive returns splice ownership rather than
//! copying every descendant through every ancestor. Public results remain Vecs.
use super::{ArchiveResult, CleanupResult, FailureKind, InputError,
    InputErrorKind, InputCheckpoint, Outcome, GeneratedSource, ScanTaskFailure};
use std::collections::LinkedList;
use std::path::PathBuf;
#[cfg(test)]
use std::ops::Index;

pub(super) trait ResultFacts {
    fn incomplete(&self) -> bool { false }
    fn cancelled(&self) -> bool { false }
}
impl ResultFacts for ArchiveResult {
    fn incomplete(&self) -> bool { self.failure.is_some() || self.partial }
    fn cancelled(&self) -> bool {
        self.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::Cancelled)
    }
}
impl ResultFacts for InputError {
    fn incomplete(&self) -> bool {
        self.kind != InputErrorKind::EmbeddedDiscovery
    }
}
impl ResultFacts for CleanupResult {
    fn incomplete(&self) -> bool { self.mode == "flatten" }
}
impl ResultFacts for InputCheckpoint {}
impl ResultFacts for GeneratedSource {}
#[cfg(test)]
impl ResultFacts for String {}

#[derive(Debug)]
pub(super) struct Results<T> {
    blocks: LinkedList<Vec<T>>,
    tail: Vec<T>,
    len: usize,
    incomplete: usize,
    cancelled: usize,
}
impl<T> Default for Results<T> {
    fn default() -> Self { Self { blocks: LinkedList::new(), tail: Vec::new(), len: 0, incomplete: 0, cancelled: 0 } }
}
impl<T: ResultFacts> Results<T> {
    pub fn len(&self) -> usize { self.len }
    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.len == 0 }
    #[cfg(test)]
    pub fn capacity(&self) -> usize { self.blocks.iter().map(Vec::capacity).sum::<usize>() + self.tail.capacity() }
    #[cfg(test)]
    pub fn last(&self) -> Option<&T> { self.iter().last() }
    pub fn iter(&self) -> impl Iterator<Item = &T> { self.blocks.iter().flatten().chain(&self.tail) }
    pub fn refresh(&mut self) {
        let (incomplete, cancelled) = self.iter().fold((0, 0), |(incomplete, cancelled), item| {
            (incomplete + usize::from(item.incomplete()), cancelled + usize::from(item.cancelled()))
        });
        self.incomplete = incomplete;
        self.cancelled = cancelled;
    }
    pub fn push(&mut self, item: T) {
        self.len += 1;
        self.incomplete += usize::from(item.incomplete());
        self.cancelled += usize::from(item.cancelled());
        self.tail.push(item);
    }
    pub fn append(&mut self, other: &mut Self) {
        if other.len == 0 { return; }
        self.len += std::mem::take(&mut other.len);
        self.incomplete += std::mem::take(&mut other.incomplete);
        self.cancelled += std::mem::take(&mut other.cancelled);
        if !self.tail.is_empty() { self.blocks.push_back(std::mem::take(&mut self.tail)); }
        self.blocks.append(&mut other.blocks);
        self.tail = std::mem::take(&mut other.tail);
    }
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        self.len = 0;
        self.incomplete = 0;
        self.cancelled = 0;
        for block in self.blocks.iter_mut().chain(std::iter::once(&mut self.tail)) {
            block.retain(|item| {
                if !keep(item) { return false; }
                self.incomplete += usize::from(item.incomplete());
                self.cancelled += usize::from(item.cancelled());
                true
            });
            self.len += block.len();
            if block.is_empty() { *block = Vec::new(); }
        }
        if self.len == 0 { self.blocks.clear(); }
    }
    pub fn into_vec(mut self) -> Vec<T> {
        if self.blocks.is_empty() { return self.tail; }
        if self.blocks.len() == 1 && self.tail.is_empty() { return self.blocks.pop_front().unwrap(); }
        let mut result = Vec::with_capacity(self.len);
        for mut block in self.blocks { result.append(&mut block); }
        result.append(&mut self.tail);
        result
    }
    // Carrier flatten temporarily appends its own completed segment batch.
    // Taking that batch back must not traverse/reallocate descendant blocks.
    pub fn take_tail(&mut self) -> Vec<T> {
        let tail = std::mem::take(&mut self.tail);
        self.len -= tail.len();
        for item in &tail {
            self.incomplete -= usize::from(item.incomplete());
            self.cancelled -= usize::from(item.cancelled());
        }
        tail
    }

}
impl<T: ResultFacts> From<Vec<T>> for Results<T> {
    fn from(items: Vec<T>) -> Self {
        let mut result = Self::default();
        result.len = items.len();
        result.tail = items;
        result.refresh();
        result
    }
}
impl<T: ResultFacts> Extend<T> for Results<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, items: I) {
        let block: Vec<_> = items.into_iter().collect();
        self.append(&mut Self::from(block));
    }
}
#[cfg(test)]
impl<T: ResultFacts> Index<usize> for Results<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T { self.iter().nth(index).expect("result index") }
}
impl<'a, T> IntoIterator for &'a Results<T> {
    type Item = &'a T;
    type IntoIter = std::iter::Chain<std::iter::Flatten<std::collections::linked_list::Iter<'a, Vec<T>>>, std::slice::Iter<'a, T>>;
    fn into_iter(self) -> Self::IntoIter { self.blocks.iter().flatten().chain(&self.tail) }
}
impl<'a, T> IntoIterator for &'a mut Results<T> {
    // Path relocation preserves classification. Rollback refreshes the facts.
    type Item = &'a mut T;
    type IntoIter = std::iter::Chain<std::iter::Flatten<std::collections::linked_list::IterMut<'a, Vec<T>>>, std::slice::IterMut<'a, T>>;
    fn into_iter(self) -> Self::IntoIter { self.blocks.iter_mut().flatten().chain(&mut self.tail) }
}

#[derive(Debug, Default)]
pub(super) struct RunOutcome {
    pub archives: Results<ArchiveResult>,
    pub errors: Results<InputError>,
    pub scan_failures: Vec<ScanTaskFailure>,
    pub checkpoints: Results<InputCheckpoint>,
    pub cleanup_results: Results<CleanupResult>,
    pub generated_sources: Results<GeneratedSource>,
    pub deferred_flatten: LinkedList<PathBuf>,
    pub scan_incomplete: bool,
    pub uncommitted: bool,
}
impl RunOutcome {
    pub fn settled(&self) -> bool { !self.uncommitted && self.archives.cancelled == 0 }
    pub fn subtree_complete(&self) -> bool {
        !self.uncommitted && self.archives.incomplete == 0
            && self.errors.incomplete == 0 && self.cleanup_results.incomplete == 0
    }
}
impl From<Outcome> for RunOutcome {
    fn from(value: Outcome) -> Self {
        Self { archives: value.archives.into(), errors: value.errors.into(),
            scan_failures: value.scan_failures,
            checkpoints: value.checkpoints.into(), cleanup_results: value.cleanup_results.into(),
            generated_sources: value.generated_sources.into(),
            deferred_flatten: value.deferred_flatten,
            scan_incomplete: value.scan_incomplete, uncommitted: value.uncommitted }
    }
}
impl From<RunOutcome> for Outcome {
    fn from(value: RunOutcome) -> Self {
        Self { archives: value.archives.into_vec(), errors: value.errors.into_vec(),
            scan_failures: value.scan_failures,
            checkpoints: value.checkpoints.into_vec(), cleanup_results: value.cleanup_results.into_vec(),
            generated_sources: value.generated_sources.into_vec(), coalesced_from: None,
            deferred_flatten: value.deferred_flatten,
            scan_incomplete: value.scan_incomplete, uncommitted: value.uncommitted }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/results/tests.rs"]
mod tests;
