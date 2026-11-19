use super::*;

/// The physical scope only. No filename hypotheses are created here.
#[derive(Debug, Default)]
pub(super) struct BucketIndex {
    pub rows_by_stem: HashMap<String, Vec<usize>>,
}

impl BucketIndex {
    pub(super) fn has_seed(anchor: &VolumeAnchor) -> bool {
        anchor.is_volume_entry()
            || (!anchor.standalone && anchor.needs_password
                && !anchor.continuation_from_previous
                && !anchor.has_any(MEMBER))
            || (anchor.pe_state != PeState::None && !anchor.standalone)
    }

    pub fn build(rows: &[RelationInput], filtered_keys: Option<&HashSet<String>>) -> Self {
        let selected: Option<HashSet<_>> = filtered_keys.map(|keys| {
            rows.iter()
                .filter(|r| keys.contains(&r.path_key))
                .map(|r| case_key(first_dot_stem(r.name())))
                .collect()
        });
        let mut out = Self::default();
        for row in rows.iter().filter(|r| r.anchor.as_ref().is_some_and(Self::has_seed)) {
            let stem = case_key(first_dot_stem(row.name()));
            if selected.as_ref().is_none_or(|set| set.contains(&stem)) {
                out.rows_by_stem.entry(stem).or_default();
            }
        }
        if out.rows_by_stem.is_empty() {
            return out;
        }
        for (i, row) in rows.iter().enumerate() {
            let stem = case_key(first_dot_stem(row.name()));
            if let Some(bucket) = out.rows_by_stem.get_mut(&stem) {
                bucket.push(i);
            }
        }
        out
    }
}
