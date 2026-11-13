//! Request-local result blocks. Recursive returns splice ownership rather than
//! copying every descendant through every ancestor. Public results remain Vecs.
use super::{ArchiveResult, CleanupResult, CleanupStatus, FailureKind, InputError,
    InputErrorKind, InputCheckpoint, Outcome, PromotedSource, ScanTaskFailure};
use std::collections::LinkedList;
use std::ops::{Index, IndexMut};

pub(super) trait ResultFacts {
    fn incomplete(&self) -> bool { false }
    fn cancelled(&self) -> bool { false }
}
impl ResultFacts for ArchiveResult {
    fn incomplete(&self) -> bool { !self.promoted && (self.failure.is_some() || self.partial) }
    fn cancelled(&self) -> bool {
        self.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::Cancelled)
    }
}
impl ResultFacts for InputError {
    fn incomplete(&self) -> bool {
        !matches!(self.kind, InputErrorKind::Cleanup | InputErrorKind::EmbeddedDiscovery)
    }
}
impl ResultFacts for CleanupResult {
    fn incomplete(&self) -> bool { self.mode == "flatten" && self.status == CleanupStatus::Failed }
}
impl ResultFacts for InputCheckpoint {}
impl ResultFacts for PromotedSource {}
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
    pub fn first(&self) -> Option<&T> { self.iter().next() }
    #[cfg(test)]
    pub fn last(&self) -> Option<&T> { self.iter().last() }
    pub fn iter(&self) -> impl Iterator<Item = &T> { self.blocks.iter().flatten().chain(&self.tail) }
    // Mutations here relocate paths/receipts, not outcome classification. The
    // cancellation rollback is the exception and explicitly refreshes facts.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> { self.blocks.iter_mut().flatten().chain(&mut self.tail) }
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
        for block in &mut self.blocks { block.retain(&mut keep); }
        self.tail.retain(keep);
        self.len = self.blocks.iter().map(Vec::len).sum::<usize>() + self.tail.len();
        self.refresh();
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
impl<T: ResultFacts> Index<usize> for Results<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T { self.iter().nth(index).expect("result index") }
}
impl<T: ResultFacts> IndexMut<usize> for Results<T> {
    fn index_mut(&mut self, index: usize) -> &mut T { self.iter_mut().nth(index).expect("result index") }
}
impl<'a, T> IntoIterator for &'a Results<T> {
    type Item = &'a T;
    type IntoIter = std::iter::Chain<std::iter::Flatten<std::collections::linked_list::Iter<'a, Vec<T>>>, std::slice::Iter<'a, T>>;
    fn into_iter(self) -> Self::IntoIter { self.blocks.iter().flatten().chain(&self.tail) }
}
impl<'a, T> IntoIterator for &'a mut Results<T> {
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
    pub promoted_sources: Results<PromotedSource>,
    pub removed_promotion_dirs: Results<String>,
    pub scan_incomplete: bool,
    pub uncommitted: bool,
}
impl RunOutcome {
    pub fn settled(&self) -> bool { !self.uncommitted && self.archives.cancelled == 0 }
    pub fn subtree_complete(&self) -> bool {
        !self.scan_incomplete && self.archives.incomplete == 0
            && self.errors.incomplete == 0 && self.cleanup_results.incomplete == 0
    }
}
impl From<Outcome> for RunOutcome {
    fn from(value: Outcome) -> Self {
        Self { archives: value.archives.into(), errors: value.errors.into(),
            scan_failures: value.scan_failures,
            checkpoints: value.checkpoints.into(), cleanup_results: value.cleanup_results.into(),
            promoted_sources: value.promoted_sources.into(), removed_promotion_dirs: value.removed_promotion_dirs.into(),
            scan_incomplete: value.scan_incomplete, uncommitted: value.uncommitted }
    }
}
impl From<RunOutcome> for Outcome {
    fn from(value: RunOutcome) -> Self {
        Self { archives: value.archives.into_vec(), errors: value.errors.into_vec(),
            scan_failures: value.scan_failures,
            checkpoints: value.checkpoints.into_vec(), cleanup_results: value.cleanup_results.into_vec(),
            promoted_sources: value.promoted_sources.into_vec(), removed_promotion_dirs: value.removed_promotion_dirs.into_vec(),
            scan_incomplete: value.scan_incomplete, uncommitted: value.uncommitted }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[test]
    fn recursive_joins_preserve_blocks_without_revisiting_descendants() {
        #[derive(Debug)]
        struct Item { id: usize, visits: Arc<AtomicUsize> }
        impl ResultFacts for Item {
            fn incomplete(&self) -> bool {
                self.visits.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
        let visits = Arc::new(AtomicUsize::new(0));
        let mut child = Results::default();
        let mut addresses = Vec::new();
        for id in (0..64).rev() {
            let mut parent = Results::from(vec![Item { id, visits: Arc::clone(&visits) }]);
            addresses.push(parent.first().unwrap() as *const Item);
            parent.append(&mut child);
            assert_eq!(child.len(), 0);
            child = parent;
        }
        assert_eq!(visits.load(Ordering::Relaxed), 64);
        for (item, address) in child.iter().zip(addresses.into_iter().rev()) {
            assert_eq!(item as *const Item, address);
        }
        assert_eq!(child.into_vec().into_iter().map(|item| item.id).collect::<Vec<_>>(), (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn sibling_blocks_keep_order_and_detach_only_the_carrier_batch() {
        let mut results = Results::default();
        for block in [vec!["a", "b"], vec![], vec!["c"], vec!["d", "e"]] {
            results.append(&mut Results::from(block.into_iter().map(str::to_owned).collect::<Vec<_>>()));
        }
        let addresses: Vec<_> = results.iter().map(|item| item as *const String).collect();
        results.extend(["carrier-a".to_owned(), "carrier-b".to_owned()]);
        assert_eq!(results.take_tail(), ["carrier-a", "carrier-b"]);
        assert_eq!(results.len(), 5);
        assert_eq!(results.iter().map(|item| item as *const String).collect::<Vec<_>>(), addresses);
        assert_eq!(results.into_vec(), ["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn cleanup_facts_distinguish_source_warnings_from_incomplete_flatten() {
        let failure = |mode| CleanupResult {
            path: "output".into(), mode, status: CleanupStatus::Failed,
            error_code: 5, message: "locked".into(),
        };
        let mut root = RunOutcome::default();
        root.cleanup_results.push(failure("delete"));
        assert!(root.subtree_complete());
        let mut child = RunOutcome::default();
        child.cleanup_results.push(failure("flatten"));
        root.cleanup_results.append(&mut child.cleanup_results);
        assert!(!root.subtree_complete());
        assert!(root.settled());
        let roundtrip = RunOutcome::from(Outcome::from(root));
        assert!(!roundtrip.subtree_complete());
    }
}
