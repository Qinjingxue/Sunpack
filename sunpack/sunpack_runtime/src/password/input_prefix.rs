//! Common evidence prefix using only the head file length and layout metadata. This is not a complete input layout.
use crate::io::archive_state::{InputExtent, VolumeAttemptPlan};
use crate::io::reader::NativeArchiveSession;

pub(crate) fn common_attempt_prefix(
    head: &InputExtent,
    plan: &VolumeAttemptPlan,
    sessions: &[NativeArchiveSession],
) -> Vec<InputExtent> {
    if plan.head_size_from_total.is_some() || !plan.tail_totals.is_empty() {
        return Vec::new();
    }
    let Ok(reader) = super::InputReaders::new(sessions).open(&head.path, false) else {
        return Vec::new();
    };
    common_prefix_with_head_len(head, plan, reader.len())
}

fn common_prefix_with_head_len(
    head: &InputExtent,
    plan: &VolumeAttemptPlan,
    head_file_len: u64,
) -> Vec<InputExtent> {
    if plan.head_size_from_total.is_some() || !plan.tail_totals.is_empty() {
        return Vec::new();
    }
    let end = |extent: &InputExtent| {
        if extent.path == head.path {
            Some(extent.end.unwrap_or(head_file_len).min(head_file_len))
        } else {
            extent.end
        }
    };
    let equal = |left: &InputExtent, right: &InputExtent| {
        left.path == right.path && left.start == right.start && end(left) == end(right)
    };
    let same_extent = |domain: usize| -> Option<&InputExtent> {
        let choices = &plan.domains.get(domain)?.choices;
        let (&first, rest) = choices.split_first()?;
        let first = plan.sources.get(first)?;
        rest.iter()
            .all(|&i| {
                plan.sources
                    .get(i)
                    .is_some_and(|extent| equal(extent, first))
            })
            .then_some(first)
    };
    let minimum = |layout: &crate::io::archive_state::VolumeLayout| {
        if layout.minimum_slots == 0 {
            layout.slots.len()
        } else {
            layout.minimum_slots
        }
    };
    // Validate the fixed head before publishing any evidence. A one-slot
    // variable layout also uses its terminal domain, checked below.
    for layout in &plan.layouts {
        let count = minimum(layout);
        if count == 0
            || count > layout.slots.len()
            || !same_extent(layout.slots[0].domain).is_some_and(|first| equal(first, head))
        {
            return Vec::new();
        }
    }
    let limit = plan.layouts.iter().map(&minimum).min().unwrap_or(0);
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for position in 0..limit {
        let mut common = None;
        for layout in &plan.layouts {
            let maximum = layout.slots.len();
            // Short layouts replace only the terminal domain, not the
            // position's number/name (VolumeAttemptPlan::selected_parts).
            // A missing disk cannot become contiguous evidence by concatenation.
            if layout.slots[position].number as usize != position + 1 {
                return result;
            }
            // Counts greater than position+1 use the middle slot. The
            // shortest count can instead put the final domain here.
            let domains = [
                (maximum > position + 1).then_some(layout.slots[position].domain),
                (minimum(layout) == position + 1).then_some(layout.slots[maximum - 1].domain),
            ];
            for domain in domains.into_iter().flatten() {
                let Some(extent) = same_extent(domain) else {
                    return result;
                };
                if common.is_some_and(|previous| !equal(previous, extent)) {
                    return result;
                }
                common = Some(extent);
            }
        }
        let Some(extent) = common else {
            break;
        };
        // An unknown physical end must not make this independent probe open
        // an unrelated missing tail just to establish its length.
        let end = end(extent);
        if end.is_none_or(|end| end < extent.start) {
            break;
        }
        if !seen.insert((&extent.path, extent.start, end)) {
            break;
        }
        result.push(InputExtent {
            path: extent.path.clone(),
            start: extent.start,
            end,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    fn plan() -> VolumeAttemptPlan {
        VolumeAttemptPlan {
            sources: ["head", "middle", "tail", "other"]
                .into_iter()
                .map(|path| InputExtent {
                    path: path.into(),
                    start: 10,
                    end: Some(110),
                })
                .collect(),
            domains: (0..4)
                .map(|index| VolumeDomain {
                    choices: Arc::new(vec![index]),
                })
                .collect(),
            layouts: vec![layout(&[0, 1, 2], 0)].into_boxed_slice(),
            head_size_from_total: None,
            minimum_size: None,
            tail_totals: Box::default(),
        }
    }
    fn layout(domains: &[usize], minimum_slots: usize) -> VolumeLayout {
        VolumeLayout {
            minimum_slots,
            slots: domains
                .iter()
                .enumerate()
                .map(|(index, &domain)| VolumeSlot {
                    number: index as u32 + 1,
                    canonical_name: String::new(),
                    domain,
                })
                .collect(),
        }
    }
    #[test]
    fn retains_fixed_middle_before_unknown_tail() {
        let mut plan = plan();
        plan.sources[2].end = None;
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..2]
        );
    }
    #[test]
    fn variable_count_uses_early_terminal_domain() {
        let mut plan = plan();
        plan.layouts[0].minimum_slots = 2;
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..1]
        );
        plan.domains[2].choices = Arc::new(vec![1]);
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..2]
        );
    }
    #[test]
    fn differing_layouts_stop_at_first_ambiguity() {
        let mut plan = plan();
        plan.layouts = vec![layout(&[0, 1, 2], 0), layout(&[0, 3, 2], 0)].into_boxed_slice();
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..1]
        );
    }
    #[test]
    fn exact_extent_aliases_do_not_create_ambiguity() {
        let mut plan = plan();
        plan.sources[3] = plan.sources[1].clone();
        plan.domains[1].choices = Arc::new(vec![1, 3]);
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..3]
        );
        plan.head_size_from_total = Some(200);
        assert!(common_prefix_with_head_len(&plan.sources[0], &plan, 110).is_empty());
    }
    #[test]
    fn missing_disk_stops_before_gap_even_for_early_tail() {
        let mut plan = plan();
        plan.layouts[0].slots[1].number = 3;
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..1]
        );
        plan.layouts[0].minimum_slots = 2;
        plan.domains[2].choices = Arc::new(vec![1]);
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..1]
        );
        // The early tail inherits position 1's number, not the last slot's.
        plan.layouts[0].slots[1].number = 2;
        plan.layouts[0].slots[2].number = 9;
        assert_eq!(
            common_prefix_with_head_len(&plan.sources[0], &plan, 110),
            plan.sources[..2]
        );
        plan.layouts[0].slots[0].number = 2;
        assert!(common_prefix_with_head_len(&plan.sources[0], &plan, 110).is_empty());
    }
    #[test]
    fn head_eof_normalization_does_not_admit_shorter_subextent() {
        let path = crate::test_support::temp_file("attempt_prefix_head", &[0; 110]);
        let mut plan = plan();
        plan.sources[0].path = path.to_string_lossy().into_owned();
        let mut head = plan.sources[0].clone();
        head.end = None;
        assert_eq!(common_attempt_prefix(&head, &plan, &[]), plan.sources[..3]);
        plan.sources[0].end = Some(109);
        assert!(common_attempt_prefix(&head, &plan, &[]).is_empty());
        plan.sources[0].end = None;
        let mut expected = plan.sources[..3].to_vec();
        expected[0].end = Some(110);
        assert_eq!(common_attempt_prefix(&head, &plan, &[]), expected);
        std::fs::remove_file(path).unwrap();
    }
}
