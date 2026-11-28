use super::*;
use crate::io::view::{ReadView, Span, ViewMethod};

#[test]
fn zip_disk_matching_counts_equivalent_views_only_once() {
    let proposal = RelationProposal {
        format: "zip", logical_name: "set".into(), style: "zip_spanned", width: 2,
        volumes: Vec::new(), companions: Vec::new(),
    };
    let source = |path: &str| AttemptSource {
        path: path.into(), view: None, start: 2, end: 8, terminal: path == "tail",
        proven_end: None, head_size: None,
    };
    let middle = Arc::new(vec![1, 3]);
    let mut attempts = VolumeAttempts {
        base_source_count: 3,
        sources: vec![source("head"), source("middle"), source("tail"), source("middle")],
        layouts: vec![AttemptLayout {
            slots: vec![(1, Arc::new(vec![0])), (2, middle.clone()), (3, middle), (4, Arc::new(vec![2]))],
            minimum_slots: 0,
        }],
        excluded_heads: Box::new([]), directory_id: None, head_size_from_total: None,
        minimum_size: None, tail_totals: Vec::new(),
    };
    for (offset, reverse) in [(2, false), (3, false), (3, true)] {
        attempts.sources[3].start = offset;
        attempts.sources[3].end = offset + 6;
        attempts.sources[3].view = Some(Arc::new(ReadView {
            method: ViewMethod::Apate, depth: 1, physical_size: 16,
            spans: vec![Span { start: 10, end: 10 + offset, reverse: true },
                        Span { start: 2, end: 8, reverse }],
        }));
        let mut plan = attempts.project(&proposal, proposal.style);
        assert_eq!(plan.prune_missing_zip_layouts(), !reverse);
    }
    // Only the unequal-length composition can supply both interior disks.
    attempts.sources[3].end -= 1;
    let ranked = attempts.with_spanned_carrier(&VolumeAnchor {
        size: 8, structure_offset: Some(2), payload_end: Some(8), ..Default::default()
    });
    assert_eq!(ranked.layouts.len(), 2);
    assert_eq!(ranked.layouts[0].slots[1].1.as_slice(), &[1]);
    let mut plan = ranked.project(&proposal, proposal.style);
    assert!(!plan.prune_missing_zip_layouts());
    assert_eq!(plan.layouts.len(), 1);
    assert_eq!(plan.domains[plan.layouts[0].slots[1].domain].choices.len(), 2);
}
