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
        addresses.push(parent.iter().next().unwrap() as *const Item);
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
fn undispatched_cancelled_subtree_remains_incomplete_through_result_conversion() {
    let mut root = RunOutcome::default();
    assert!(root.subtree_complete());
    root.scan_incomplete = true;
    assert!(root.subtree_complete(), "reported scan errors do not veto postprocessing");
    root.uncommitted = true;
    assert!(!root.subtree_complete());
    assert!(!root.settled());
    let restored = RunOutcome::from(Outcome::from(root));
    assert!(!restored.subtree_complete());
    assert!(!restored.settled());
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
