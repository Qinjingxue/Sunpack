use super::*;
use std::hash::{Hash, Hasher};

/// Borrow physical rows until a selected file or an entire active bucket needs
/// mutable structural facts. All indices belong to this source's scan lifetime.
pub(super) enum RelationSource<'a> {
    Snapshot(&'a NativeDirectorySnapshot, Option<&'a RelationCache>),
    #[cfg(test)]
    Physical(&'a [RelationInput]),
}

impl<'a> RelationSource<'a> {
    pub fn indices(&self) -> impl Iterator<Item = usize> + '_ + use<'_, 'a> {
        let len = match self {
            Self::Snapshot(snapshot, _) => snapshot.rows.len(),
            #[cfg(test)]
            Self::Physical(rows) => rows.len(),
        };
        (0..len).filter_map(|offset| match self {
            Self::Snapshot(snapshot, _) => {
                let row = snapshot.rows[offset];
                (!snapshot.table.is_dir(row)).then_some(row)
            }
            #[cfg(test)]
            Self::Physical(_) => Some(offset),
        })
    }

    pub fn path(&self, row: usize) -> &'a str {
        match self {
            Self::Snapshot(snapshot, _) => &snapshot.table.paths[row],
            #[cfg(test)]
            Self::Physical(rows) => &rows[row].path,
        }
    }

    fn name(&self, row: usize) -> &'a str {
        match self {
            Self::Snapshot(..) => Path::new(self.path(row))
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
            #[cfg(test)]
            Self::Physical(rows) => &rows[row].name,
        }
    }

    fn anchor(&self, row: usize) -> Option<&'a VolumeAnchor> {
        match self {
            Self::Snapshot(snapshot, cached) => cached
                .and_then(|cache| cache.anchors.get(&path_key(self.path(row))))
                .or(snapshot.table.relation_anchors[row]
                    .as_ref()
                    .and_then(|fact| fact.anchor())),
            #[cfg(test)]
            Self::Physical(rows) => rows[row].anchor.as_ref(),
        }
    }

    pub fn materialize(&self, row: usize) -> RelationInput {
        let (size, relation_member_eligible) = match self {
            Self::Snapshot(snapshot, _) => (
                snapshot.table.sizes[row],
                snapshot.table.relation_member_eligible(row),
            ),
            #[cfg(test)]
            Self::Physical(rows) => (rows[row].size, rows[row].relation_member_eligible),
        };
        RelationInput {
            path: self.path(row).to_owned(),
            path_key: path_key(self.path(row)),
            name: self.name(row).to_owned(),
            size,
            relation_member_eligible,
            anchor: self.anchor(row).cloned().or_else(|| match self {
                Self::Snapshot(snapshot, _) => snapshot.table.relation_anchors[row]
                    .as_ref()
                    .map(|fact| fact.materialize(self.path(row), size.unwrap_or(0))),
                #[cfg(test)]
                Self::Physical(_) => None,
            }),
            anchor_cell: match self {
                Self::Snapshot(snapshot, _) => snapshot
                    .table
                    .relation_anchor_cells
                    .get(row)
                    .cloned()
                    .flatten(),
                #[cfg(test)]
                Self::Physical(rows) => rows[row].anchor_cell.clone(),
            },
        }
    }
}

/// Keep ASCII scans allocation-free; non-ASCII names use the shared Windows map.
#[derive(Clone, Debug)]
struct CaseKey<'a>(Cow<'a, str>);

impl<'a> CaseKey<'a> {
    fn new(value: &'a str) -> Self {
        Self(if value.contains('/') {
            Cow::Owned(path_key(value))
        } else if value.is_ascii() {
            Cow::Borrowed(value)
        } else {
            Cow::Owned(case_key(value))
        })
    }
}

impl PartialEq for CaseKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}
impl Eq for CaseKey<'_> {}
impl Hash for CaseKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.len().hash(state);
        // Feed folded bytes in blocks rather than making one hash call per byte.
        let mut folded = [0u8; 64];
        for chunk in self.0.as_bytes().chunks(folded.len()) {
            for (output, input) in folded.iter_mut().zip(chunk) {
                *output = input.to_ascii_lowercase();
            }
            state.write(&folded[..chunk.len()]);
        }
    }
}

pub(super) struct RelationScopeIndex {
    pub rows: Vec<usize>,
}

impl RelationScopeIndex {
    pub fn build(
        source: &RelationSource<'_>,
        filtered_keys: &HashSet<String>,
        excluded: Option<&HashSet<String>>,
    ) -> Self {
        if filtered_keys.is_empty() {
            return Self { rows: Vec::new() };
        }
        let excluded = excluded.filter(|keys| !keys.is_empty());
        let admitted = |row| excluded.is_none_or(|keys| !keys.contains(&path_key(source.path(row))));
        let selected: HashSet<_> = filtered_keys.iter().map(|key| CaseKey::new(key)).collect();
        let mut rows = Vec::new();
        let mut all_selected = true;
        for row in source.indices() {
            if selected.contains(&CaseKey::new(source.path(row))) && admitted(row) {
                rows.push(row);
            } else {
                all_selected = false;
            }
        }
        if all_selected || rows.is_empty() {
            return Self { rows };
        }
        let stem = |row| CaseKey::new(first_dot_stem(source.name(row)));
        let stems: HashSet<_> = rows.iter().copied().map(stem).collect();
        let mut active = HashSet::new();
        // Inspect anchors and normalize ownership keys only within nominated
        // stems. Stop looking for seeds once every stem is represented.
        for row in source.indices() {
            let key = stem(row);
            if stems.contains(&key) && !active.contains(&key)
                && admitted(row) && source.anchor(row).is_some_and(BucketIndex::has_seed)
            {
                active.insert(key);
                if active.len() == stems.len() {
                    break;
                }
            }
        }
        if active.is_empty() {
            return Self { rows };
        }
        // Both iterations follow the same source order, so selected rows
        // merge back into the retained scopes without a second row index.
        let mut selected_rows = rows.into_iter().peekable();
        Self {
            rows: source
                .indices()
                .filter(|&row| {
                    selected_rows.next_if_eq(&row).is_some()
                        || (active.contains(&stem(row)) && admitted(row))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/relations/scope/tests.rs"]
mod tests;
