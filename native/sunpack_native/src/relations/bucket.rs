use super::*;

/// The physical scope only. No filename hypotheses are created here.
#[derive(Debug, Default)]
pub(super) struct BucketIndex {
    pub entries_by_path: HashMap<String, usize>,
    pub rows_by_stem: HashMap<String, Vec<usize>>,
}

impl BucketIndex {
    pub fn build(rows: &[RelationInput], filtered_keys: Option<&HashSet<String>>) -> Self {
        let selected: Option<HashSet<_>> = filtered_keys.map(|keys| {
            rows.iter()
                .filter(|r| keys.contains(&r.path_key))
                .map(|r| first_dot_stem(&r.name).to_ascii_lowercase())
                .collect()
        });
        let stems: HashSet<_> = rows
            .iter()
            .filter(|r| {
                r.anchor.as_ref().is_some_and(|a| {
                    cheap_seed_strength(a).is_some()
                        || (!a.standalone && (a.multivolume || a.needs_password))
                })
            })
            .map(|r| first_dot_stem(&r.name).to_ascii_lowercase())
            .filter(|s| selected.as_ref().is_none_or(|set| set.contains(s)))
            .collect();
        let mut out = Self::default();
        for (i, row) in rows.iter().enumerate() {
            let stem = first_dot_stem(&row.name).to_ascii_lowercase();
            if stems.contains(&stem) {
                out.entries_by_path.insert(row.path_key.clone(), i);
                out.rows_by_stem.entry(stem).or_default().push(i);
            }
        }
        out
    }
}
