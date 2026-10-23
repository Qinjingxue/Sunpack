use super::*;
use std::hash::{Hash, Hasher};

/// Borrow physical rows until a selected file or an entire active bucket needs
/// mutable structural facts. All indices belong to this source's scan lifetime.
pub(super) enum RelationSource<'a> {
    Snapshot(&'a NativeDirectorySnapshot, Option<&'a RelationCache>),
    Physical(&'a [RelationInput]),
}

impl<'a> RelationSource<'a> {
    pub fn indices(&self) -> impl Iterator<Item = usize> + '_ + use<'_, 'a> {
        let len = match self {
            Self::Snapshot(snapshot, _) => snapshot.rows.len(),
            Self::Physical(rows) => rows.len(),
        };
        (0..len).filter_map(|offset| match self {
            Self::Snapshot(snapshot, _) => {
                let row = snapshot.rows[offset];
                (!snapshot.table.is_dirs[row]).then_some(row)
            }
            Self::Physical(_) => Some(offset),
        })
    }

    pub fn path(&self, row: usize) -> &'a str {
        match self {
            Self::Snapshot(snapshot, _) => &snapshot.table.paths[row],
            Self::Physical(rows) => &rows[row].path,
        }
    }

    fn name(&self, row: usize) -> &'a str {
        match self {
            Self::Snapshot(..) => Path::new(self.path(row))
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
            Self::Physical(rows) => &rows[row].name,
        }
    }

    fn anchor(&self, row: usize) -> Option<&'a VolumeAnchor> {
        match self {
            Self::Snapshot(snapshot, cached) => cached
                .and_then(|cache| cache.anchors.get(&path_key(self.path(row))))
                .or(snapshot.table.relation_anchors[row].as_ref()),
            Self::Physical(rows) => rows[row].anchor.as_ref(),
        }
    }

    pub fn materialize(&self, row: usize) -> RelationInput {
        let (size, relation_member_eligible) = match self {
            Self::Snapshot(snapshot, _) => (
                snapshot.table.sizes[row],
                snapshot.table.relation_member_eligible[row],
            ),
            Self::Physical(rows) => (rows[row].size, rows[row].relation_member_eligible),
        };
        RelationInput {
            path: self.path(row).to_owned(),
            path_key: path_key(self.path(row)),
            name: self.name(row).to_owned(),
            size,
            relation_member_eligible,
            anchor: self.anchor(row).cloned(),
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
    pub fn build(source: &RelationSource<'_>, filtered_keys: &HashSet<String>) -> Self {
        let selected: HashSet<_> = filtered_keys.iter().map(|key| CaseKey::new(key)).collect();
        let stems: HashSet<_> = source.indices().filter(|&row| selected.contains(&CaseKey::new(source.path(row))))
            .map(|row| CaseKey::new(first_dot_stem(source.name(row)))).collect();
        let active: HashSet<_> = source.indices().filter(|&row| source.anchor(row).is_some_and(BucketIndex::has_seed))
            .map(|row| CaseKey::new(first_dot_stem(source.name(row)))).filter(|stem| stems.contains(stem)).collect();
        Self { rows: source.indices().filter(|&row| selected.contains(&CaseKey::new(source.path(row)))
            || active.contains(&CaseKey::new(first_dot_stem(source.name(row))))).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str, seed: bool, eligible: bool) -> RelationInput {
        RelationInput {
            path: path.into(),
            path_key: path_key(path),
            name: basename(path).into(),
            size: Some(17),
            relation_member_eligible: eligible,
            anchor: seed.then(|| VolumeAnchor {
                multivolume: true,
                ..VolumeAnchor::default()
            }),
        }
    }

    fn scope(rows: &[RelationInput], selected: &[usize]) -> RelationScopeIndex {
        let keys = selected.iter().map(|&i| rows[i].path_key.clone()).collect();
        RelationScopeIndex::build(&RelationSource::Physical(rows), &keys)
    }

    #[test]
    fn active_bucket_keeps_unselected_competitors_and_excluded_members() {
        let rows = vec![
            row(r"C:\game\Payload.part1.fake", true, true),
            row(r"c:\GAME\payload.7z.001", true, true),
            row(r"C:\game\PAYLOAD.part2.photo", false, true),
            row(r"C:\game\payload.part3.hard_excluded", false, false),
            row(r"C:\game\other.part1.fake", true, true),
        ];
        let index = scope(&rows, &[0]);
        assert_eq!(index.rows, vec![0, 1, 2, 3]);
        let member = RelationSource::Physical(&rows).materialize(3);
        assert!(!member.relation_member_eligible);
        assert_eq!(member.size, Some(17));
    }

    #[test]
    fn selecting_a_member_or_launcher_can_activate_an_unselected_head() {
        let rows = vec![
            row(r"C:\game\payload.part1.disguised", true, true),
            row(r"C:\other\payload.part2.fake", false, true),
            row(r"C:\game\payload.exe", false, true),
        ];
        for selected in [1, 2] {
            assert_eq!(scope(&rows, &[selected]).rows, vec![0, 1, 2]);
        }
    }

    #[test]
    fn selected_rows_preserve_source_order_across_directories() {
        let rows = vec![
            row(r"C:\first\ignored.txt", false, true),
            row(r"C:\second\selected.zip", false, true),
            row(r"C:\first\selected.zip", false, true),
            row(r"C:\unselected\payload.part1.rar", true, true),
        ];
        assert_eq!(scope(&rows, &[1, 2]).rows, vec![1, 2]);
    }

    #[test]
    fn standalone_anchor_does_not_activate_siblings() {
        let mut rows = vec![
            row(r"C:\game\payload.zip", true, true),
            row(r"C:\game\payload.001", false, true),
        ];
        rows[0].anchor.as_mut().unwrap().standalone = true;
        assert_eq!(scope(&rows, &[0]).rows, vec![0]);
        assert!(scope(&rows, &[]).rows.is_empty());
    }

    #[test]
    fn borrowed_keys_follow_windows_case_equality_across_hash_blocks() {
        let upper = format!("{}Ä", "A".repeat(130));
        let lower = format!("{}Ä", "a".repeat(130));
        let unicode_lower = format!("{}ä", "a".repeat(130));
        let keys = HashSet::from([CaseKey::new(&upper)]);
        assert!(keys.contains(&CaseKey::new(&lower)));
        assert_eq!(keys.contains(&CaseKey::new(&unicode_lower)), cfg!(windows));
    }
}
