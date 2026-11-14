//! Compact resident rows. Accepted file baselines are durable; scan anchors are disposable.
use super::directory::DirectoryEntryRecord;
use crate::analysis_native::volume_anchor::CheapAnchorCell;
use crate::path_keys::path_key;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

const DIRECTORY: u8 = 1;
const HAS_SIZE: u8 = 2;
const HAS_MTIME: u8 = 4;
const TRANSIENT: u8 = 8;

#[derive(Clone, Eq, PartialEq)]
enum FileId {
    Ntfs { bytes: [u8; 16], len: u8 },
    Other(Box<str>),
}

impl FileId {
    fn new(value: &str) -> Self {
        if matches!(value.len(), 16 | 32)
            && value
                .bytes()
                .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
        {
            let mut bytes = [0; 16];
            for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                let digit = |ch: u8| {
                    if ch <= b'9' {
                        ch - b'0'
                    } else {
                        ch - b'a' + 10
                    }
                };
                bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
            }
            Self::Ntfs {
                bytes,
                len: (value.len() / 2) as u8,
            }
        } else {
            Self::Other(value.into())
        }
    }
    fn text(&self) -> String {
        match self {
            Self::Other(value) => value.to_string(),
            Self::Ntfs { bytes, len } => {
                const HEX: &[u8] = b"0123456789abcdef";
                let mut text = String::with_capacity(*len as usize * 2);
                for byte in &bytes[..*len as usize] {
                    text.push(HEX[(byte >> 4) as usize] as char);
                    text.push(HEX[(byte & 15) as usize] as char);
                }
                text
            }
        }
    }
}

/// Accepted-event metadata, independent of a newer directory scan.
#[derive(Clone)]
pub(crate) struct NativeWatchObservation {
    // Accepted-event metadata must survive a newer scan until admission. It is
    // a different version from the directory view, not a second directory row.
    pub size: u64,
    pub mtime: f64,
    file_id: FileId,
    pub change_usn: i64,
    pub quiet_seconds: f64,
    pub cadence_seconds: f64,
    pub pending_interval_seconds: f64,
    pub last_content_event_at: Option<f64>,
}

impl NativeWatchObservation {
    pub(crate) fn file_id(&self) -> String {
        self.file_id.text()
    }
}

impl NativeWatchObservation {
    fn new(size: u64, mtime: f64, file_id: FileId, change_usn: i64) -> Self {
        Self {
            size,
            mtime,
            file_id,
            change_usn,
            quiet_seconds: 0.0,
            cadence_seconds: 0.0,
            pending_interval_seconds: 0.0,
            last_content_event_at: None,
        }
    }
    fn update(&mut self, size: u64, mtime: f64, file_id: FileId, change_usn: i64) {
        self.size = size;
        self.mtime = mtime;
        self.file_id = file_id;
        self.change_usn = change_usn;
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct GeneratedBaseline {
    size: u64,
    mtime: f64,
    file_id: String,
    usn: i64,
}

pub(super) struct CatalogRow {
    parent: Arc<str>,
    name: Box<str>,
    size: u64,
    mtime_ns: u64,
    flags: u8,
    pub cheap_anchor: Option<CheapAnchorCell>,
    pub observation: Option<Box<NativeWatchObservation>>,
    pub generated: Option<Box<GeneratedBaseline>>,
}

impl CatalogRow {
    pub fn remember_generated(&mut self, size: u64, mtime: f64, id: &str, usn: i64) {
        self.generated = Some(Box::new(GeneratedBaseline { size, mtime, file_id: id.to_owned(), usn }));
    }
    pub fn generated_observation(&self) -> Option<NativeWatchObservation> {
        self.generated.as_ref().map(|g| NativeWatchObservation::new(g.size, g.mtime, FileId::new(&g.file_id), g.usn))
    }

    pub fn remember_observation(
        &mut self,
        size: u64,
        mtime: f64,
        file_id: &str,
        change_usn: i64,
        phase_boundary: bool,
    ) {
        let file_id = FileId::new(file_id);
        let unchanged = self.observation.as_ref().is_some_and(|old| {
            old.size == size
                && old.mtime == mtime
                && old.change_usn == change_usn
                && old.file_id == file_id
        });
        if !unchanged {
            self.cheap_anchor = None;
            crate::io::reader::invalidate_reader_path(Path::new(&self.path()));
        }
        if let Some(observation) = self.observation.as_mut() {
            observation.update(size, mtime, file_id, change_usn);
        } else {
            self.observation = Some(Box::new(NativeWatchObservation::new(
                size, mtime, file_id, change_usn,
            )));
        }
        if phase_boundary {
            if let Some(observation) = self.observation.as_mut() {
                observation.last_content_event_at = None;
                observation.pending_interval_seconds = 0.0;
            }
        }
    }
    pub fn path(&self) -> String {
        let mut path = String::with_capacity(self.parent.len() + self.name.len());
        path.push_str(&self.parent);
        path.push_str(&self.name);
        path
    }
    pub fn is_dir(&self) -> bool {
        self.flags & DIRECTORY != 0
    }
    pub fn persistent(&self) -> bool {
        self.flags & TRANSIENT == 0
    }
    pub fn size(&self) -> Option<u64> {
        (self.flags & HAS_SIZE != 0).then_some(self.size)
    }
    pub fn mtime_ns(&self) -> Option<u64> {
        (self.flags & HAS_MTIME != 0).then_some(self.mtime_ns)
    }
    pub fn matches(&self, record: &DirectoryEntryRecord) -> bool {
        self.persistent()
            && self.is_dir() == record.is_dir
            && self.size() == record.size
            && self.mtime_ns() == record.mtime_ns
            && record.path.strip_prefix(self.parent.as_ref()) == Some(self.name.as_ref())
    }
    pub fn record(&self) -> DirectoryEntryRecord {
        DirectoryEntryRecord {
            path: self.path(),
            is_dir: self.is_dir(),
            size: self.size(),
            mtime_ns: self.mtime_ns(),
            relation_member_eligible: false,
            relation_anchor: None,
        }
    }
}

impl Serialize for CatalogRow {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Row<'a> {
            #[serde(flatten)]
            record: DirectoryEntryRecord,
            #[serde(skip_serializing_if = "Option::is_none")]
            observed: Option<(u64, f64, String, i64)>,
            #[serde(skip_serializing_if = "Option::is_none")]
            generated: Option<&'a GeneratedBaseline>,
        }
        Row { record: self.record(), observed: self.observation.as_ref().map(|o|
            (o.size, o.mtime, o.file_id(), o.change_usn)), generated: self.generated.as_deref() }.serialize(serializer)
    }
}

enum BucketRows {
    One(Arc<str>),
    Many(Vec<Arc<str>>),
}
impl BucketRows {
    pub fn iter(&self) -> std::slice::Iter<'_, Arc<str>> {
        match self {
            Self::One(key) => std::slice::from_ref(key).iter(),
            Self::Many(keys) => keys.iter(),
        }
    }
    fn push(&mut self, key: Arc<str>) {
        match self {
            Self::One(first) => *self = Self::Many(vec![Arc::clone(first), key]),
            Self::Many(keys) => keys.push(key),
        }
    }
    fn remove(&mut self, key: &str) -> bool {
        self.retain(|value| value.as_ref() != key)
    }
    fn retain(&mut self, mut keep: impl FnMut(&Arc<str>) -> bool) -> bool {
        match self {
            Self::One(first) => !keep(first),
            Self::Many(keys) => {
                keys.retain(|value| keep(value));
                if keys.is_empty() {
                    return true;
                }
                if keys.len() == 1 {
                    *self = Self::One(keys.pop().unwrap());
                } else if keys.capacity() > keys.len().saturating_mul(2).max(4) {
                    keys.shrink_to_fit();
                }
                false
            }
        }
    }
}

pub(super) struct CatalogBucket {
    rows: BucketRows,
    pub revision: u64,
}
fn next_revision() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
impl CatalogBucket {
    fn new(key: Arc<str>) -> Self { Self { rows: BucketRows::One(key), revision: next_revision() } }
    pub fn iter(&self) -> std::slice::Iter<'_, Arc<str>> { self.rows.iter() }
    fn touch(&mut self) { self.revision = next_revision(); }
    fn push(&mut self, key: Arc<str>) { self.rows.push(key); self.touch(); }
    fn remove(&mut self, key: &str) -> bool { self.touch(); self.rows.remove(key) }
    fn retain(&mut self, keep: impl FnMut(&Arc<str>) -> bool) -> bool { self.touch(); self.rows.retain(keep) }
}

#[derive(Default)]
pub(super) struct ScopeCatalog {
    pub rows: BTreeMap<Arc<str>, CatalogRow>,
    pub buckets: HashMap<Box<str>, CatalogBucket>,
    parents: HashSet<Arc<str>>,
    pub persistent_len: usize,
}

pub(crate) fn catalog_stem(path: &str) -> String {
    crate::path_keys::case_key(crate::relations::first_dot_stem(
        std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    ))
}

impl ScopeCatalog {
    pub fn touch(&mut self, path: &str) {
        if let Some(bucket) = self.buckets.get_mut(catalog_stem(path).as_str()) { bucket.touch(); }
    }
    pub fn insert(&mut self, row: DirectoryEntryRecord) {
        self.insert_key(Arc::from(path_key(&row.path)), row);
    }
    pub fn insert_key(&mut self, key: Arc<str>, record: DirectoryEntryRecord) {
        self.touch(&record.path);
        self.insert_row(key, record, false);
    }
    pub fn insert_transient(&mut self, key: Arc<str>, record: DirectoryEntryRecord) {
        self.insert_row(key, record, true);
    }
    fn insert_row(&mut self, mut key: Arc<str>, record: DirectoryEntryRecord, transient: bool) {
        if let Some(old) = self.rows.get_mut(key.as_ref()) {
            if !transient
                && old.persistent()
                && old.is_dir() == record.is_dir
                && record.path.strip_prefix(old.parent.as_ref()) == Some(old.name.as_ref())
            {
                if old.size() != record.size || old.mtime_ns() != record.mtime_ns {
                    old.cheap_anchor = None;
                    crate::io::reader::invalidate_reader_path(Path::new(&record.path));
                }
                old.size = record.size.unwrap_or(0);
                old.mtime_ns = record.mtime_ns.unwrap_or(0);
                old.flags = u8::from(record.is_dir) * DIRECTORY
                    | u8::from(record.size.is_some()) * HAS_SIZE
                    | u8::from(record.mtime_ns.is_some()) * HAS_MTIME;
                return;
            }
        }
        let split = record.path.rfind(['\\', '/']).map_or(0, |index| index + 1);
        let (parent, name) = record.path.split_at(split);
        let parent = if let Some(value) = self.parents.get(parent) {
            Arc::clone(value)
        } else {
            let value: Arc<str> = Arc::from(parent);
            self.parents.insert(Arc::clone(&value));
            value
        };
        let mut row = CatalogRow {
            parent,
            name: name.into(),
            size: record.size.unwrap_or(0),
            mtime_ns: record.mtime_ns.unwrap_or(0),
            flags: u8::from(record.is_dir) * DIRECTORY
                | u8::from(record.size.is_some()) * HAS_SIZE
                | u8::from(record.mtime_ns.is_some()) * HAS_MTIME
                | u8::from(transient) * TRANSIENT,
            observation: None,
            generated: None,
            cheap_anchor: None,
        };
        let mut reuse_indexes = false;
        if let Some((old_key, mut old)) = self.rows.remove_entry(key.as_ref()) {
            key = old_key;
            row.observation = old.observation.take();
            row.generated = old.generated.take();
            reuse_indexes = old.persistent() && row.persistent() && old.is_dir() == row.is_dir();
            if reuse_indexes {
                self.release_parent(&old);
            } else {
                self.remove_indexes(&key, &old, None);
            }
        }
        if row.persistent() && !reuse_indexes {
            self.persistent_len += 1;
            if !row.is_dir() {
                let stem = catalog_stem(&record.path);
                match self.buckets.get_mut(stem.as_str()) {
                    Some(bucket) => bucket.push(Arc::clone(&key)),
                    None => {
                        self.buckets
                            .insert(stem.into_boxed_str(), CatalogBucket::new(Arc::clone(&key)));
                    }
                }
            }
        }
        self.rows.insert(key, row);
    }
    fn remove_indexes(&mut self, key: &str, row: &CatalogRow, dirty: Option<&mut HashSet<String>>) {
        if row.persistent() {
            self.persistent_len -= 1;
            if !row.is_dir() {
                let stem = catalog_stem(&row.name);
                if let Some(dirty) = dirty.filter(|_| {
                    matches!(
                        self.buckets.get(stem.as_str()).map(|bucket| &bucket.rows),
                        Some(BucketRows::Many(_))
                    )
                }) {
                    dirty.insert(stem);
                } else if self
                    .buckets
                    .get_mut(stem.as_str())
                    .is_some_and(|bucket| bucket.remove(key))
                {
                    self.buckets.remove(stem.as_str());
                }
            }
        }
        self.release_parent(row);
    }
    fn release_parent(&mut self, row: &CatalogRow) {
        if Arc::strong_count(&row.parent) == 2 {
            self.parents.remove(row.parent.as_ref());
        }
    }
    pub fn remove(&mut self, key: &str) {
        self.remove_many(std::iter::once(key));
    }
    pub fn remove_many<'a>(&mut self, keys: impl IntoIterator<Item = &'a str>) {
        let mut dirty = HashSet::new();
        for key in keys {
            if let Some(row) = self.rows.remove(key) {
                self.remove_indexes(key, &row, Some(&mut dirty));
            }
        }
        for stem in dirty {
            if self
                .buckets
                .get_mut(stem.as_str())
                .is_some_and(|bucket| bucket.retain(|key| self.rows.contains_key(key)))
            {
                self.buckets.remove(stem.as_str());
            }
        }
    }
    pub fn trim_capacity(&mut self) {
        if self.buckets.is_empty() {
            self.buckets = HashMap::new();
        } else if self.buckets.capacity() > self.buckets.len().saturating_mul(2).max(16) {
            self.buckets.shrink_to_fit();
        }
        if self.parents.is_empty() {
            self.parents = HashSet::new();
        } else if self.parents.capacity() > self.parents.len().saturating_mul(2).max(16) {
            self.parents.shrink_to_fit();
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_close_still_ends_saved_phase_without_relearning_cadence() {
        let mut observation = NativeWatchObservation::new(42, 10.0, FileId::new("file"), 7);
        observation.quiet_seconds = 2.0;
        observation.cadence_seconds = 1.0;
        observation.pending_interval_seconds = 4.0;
        observation.last_content_event_at = Some(10.0);
        let mut row = CatalogRow {
            parent: Arc::from("C:\\watch"), name: "input.zip".into(),
            size: 42, mtime_ns: 0, flags: HAS_SIZE | HAS_MTIME,
            cheap_anchor: None, generated: None, observation: Some(Box::new(observation)),
        };
        // Main skips activity learning for unchanged forced retries, but its
        // ordinary observation publication still honors an explicit CLOSE.
        row.remember_observation(42, 10.0, "file", 7, true);
        let saved = row.observation.as_ref().unwrap();
        assert_eq!((saved.quiet_seconds, saved.cadence_seconds), (2.0, 1.0));
        assert_eq!(saved.last_content_event_at, None);
        assert_eq!(saved.pending_interval_seconds, 0.0);
    }
}
