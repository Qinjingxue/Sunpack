//! Watch-only live logical-input index. It is a disposable cache, never a success receipt.
use super::dedup_hash::{hash_ranges, HashRange};
use crate::core::config::{WatchDeduplication, WatchDeduplicationScope};
use crate::io::archive_state::{ArchiveInput, InputRole, OpenMode, VolumeCompleteness, VolumeSelection};
use crate::io::reader::PhysicalFileGeneration;
use crate::path_keys::path_key;
use crate::postprocess::{mtime_seconds, watch_observed_content_changed};
use crate::scan::scope::NativeDiscoveryScope;
use crate::wal::{self, Kind};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{btree_set, BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Layout { format: String, mode: u8, parts: Box<[(u8, Option<u32>, u64)]> }
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Identity { volume: u64, file: [u8; 16], start: u64, len: u64 }
#[derive(Clone, Serialize, Deserialize)]
struct Source { path: String, generation: PhysicalFileGeneration, size: u64, mtime: f64, file_id: String, usn: i64 }
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    id: u64,
    owner: Arc<str>,
    scope: Arc<str>,
    layout: Arc<[Layout]>,
    admitted: bool,
    sources: Box<[Source]>,
    range_sources: Box<[u32]>,
    identities: Arc<[Identity]>,
    digest: Option<[u8; 16]>,
}
impl Record {
    fn current(&self) -> bool {
        self.sources.iter().all(|s| {
            crate::filesystem::watch_ready_file_snapshot(Path::new(&s.path), Some(s.usn))
                .ok().flatten().is_some_and(|snapshot| {
                    snapshot.generation.matches_input(&s.generation)
                        && snapshot.observation.change_usn >= s.usn
                        && !watch_observed_content_changed(
                            s.size, s.mtime, &s.file_id, s.usn, snapshot.metadata.len(),
                            mtime_seconds(&snapshot.metadata), &snapshot.observation,
                        )
                })
        })
    }
    fn hash(&mut self) -> io::Result<()> {
        if self.identities.iter().any(|range| range.len > crate::io::iocp::ORDERED_READ_CHUNK as u64)
            && self.sources.iter().any(|s| !crate::filesystem::watch_file_is_ready(&s.path).unwrap_or(false))
        {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "deduplication input is being written"));
        }
        let ranges = self.range_sources.iter().zip(self.identities.iter()).map(|(&source, extent)| {
            let source = &self.sources[source as usize];
            HashRange {
                path: Path::new(&source.path),
                generation: &source.generation,
                offset: extent.start,
                len: extent.len,
            }
        });
        self.digest = Some(hash_ranges(ranges)?);
        Ok(())
    }

    // The physical index has already matched the ordered extents. Compare
    // their sampled versions before reusing a digest through another name.
    fn same_source_versions(&self, other: &Self) -> bool {
        self.range_sources.iter().zip(other.range_sources.iter()).all(|(&left, &right)| {
            let left = &self.sources[left as usize];
            let right = &other.sources[right as usize];
            left.usn == right.usn && left.generation == right.generation
        })
    }

    fn same_source_paths_and_versions(&self, other: &Self) -> bool {
        self.sources.len() == other.sources.len()
            && self.sources.iter().zip(other.sources.iter()).all(|(left, right)| {
                left.path == right.path && left.usn == right.usn && left.generation == right.generation
            })
    }
}
#[derive(Serialize, Deserialize)]
enum Delta<'a> {
    Begin(u8, u8),
    Put(Cow<'a, Record>),
    Remove(Vec<u64>),
    Journals(Vec<(String, String, u64)>),
    Ready,
    Pending,
}

/// Hashing is deliberately outside Index's lock and the scheduler thread.
struct Prepared {
    epoch: u64, record: Record, representative: Option<Record>, hash: bool,
}
impl Prepared {
    fn needs_hash(&self) -> bool {
        (self.hash && self.record.digest.is_none())
            || self.representative.as_ref().is_some_and(|record| record.digest.is_none())
    }

    fn hash(&mut self) -> io::Result<()> {
        if self.hash && self.record.digest.is_none() { self.record.hash()?; }
        if let Some(record) = &mut self.representative { if record.digest.is_none() { record.hash()?; } }
        Ok(())
    }
}

pub(super) fn consider(
    index: &Mutex<Index>,
    owner: &str,
    scope: &str,
    inputs: &[&ArchiveInput],
    generation: Option<u64>,
) -> io::Result<bool> {
    if inputs.is_empty() { return Ok(false); }
    let Some(epoch) = index.lock().unwrap().admission_epoch(scope, generation) else {
        return Ok(false);
    };
    // Describing the sources opens files and queries NTFS/ReFS. Each job can
    // do that under its existing Watch work budget while other jobs commit.
    let Some(record) = describe(owner, scope, inputs)? else { return Ok(false); };
    let mut locked = index.lock().unwrap();
    let Some(mut prepared) = locked.prepare(epoch, record, generation.is_some()) else {
        return Ok(false);
    };
    if !prepared.needs_hash() {
        return locked.commit(prepared);
    }
    drop(locked);
    loop {
        prepared.hash()?;
        let mut locked = index.lock().unwrap();
        if locked.refresh(&mut prepared) { continue; }
        return locked.commit(prepared);
    }
}

type Signature = (u64, Arc<[Layout]>);

// Most reverse-index keys name a single record. Allocate a tree only when
// distinct owners actually share a source, physical identity or digest.
enum RecordIds {
    One(u64),
    Many(Box<BTreeSet<u64>>),
}

impl RecordIds {
    fn insert(&mut self, id: u64) {
        match self {
            Self::One(first) if *first != id => {
                *self = Self::Many(Box::new(BTreeSet::from([*first, id])));
            }
            Self::One(_) => (),
            Self::Many(ids) => { ids.insert(id); }
        }
    }

    /// Returns true when the enclosing map entry can be removed.
    fn remove(&mut self, id: u64) -> bool {
        match self {
            Self::One(first) => *first == id,
            Self::Many(ids) => {
                ids.remove(&id);
                if ids.len() == 1 {
                    *self = Self::One(*ids.first().unwrap());
                }
                false
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        let (one, many): (_, Option<btree_set::Iter<'_, u64>>) = match self {
            Self::One(id) => (Some(*id), None),
            Self::Many(ids) => (None, Some(ids.iter())),
        };
        one.into_iter().chain(many.into_iter().flatten().copied())
    }
}

#[derive(Default)]
struct SizeBucket { count: usize, unhashed: Option<RecordIds> }

impl SizeBucket {
    fn pending(&self) -> impl Iterator<Item = u64> + '_ {
        self.unhashed.iter().flat_map(RecordIds::iter)
    }
}

pub(super) struct Index {
    path: PathBuf, mode: WatchDeduplication, scope: WatchDeduplicationScope, file: Option<File>, seq: u64,
    epoch: u64, generation: u64, next_id: u64, ready: bool, edits: usize,
    domains: HashMap<Arc<str>, u64>,
    next_domain: u64,
    journals: HashMap<String, (String, u64)>,
    records: HashMap<u64, Record>,
    // Commit removes a superseded record before writing a replacement owner.
    owners: HashMap<Arc<str>, u64>,
    paths: BTreeMap<Arc<str>, RecordIds>, sizes: HashMap<Signature, SizeBucket>,
    hashes: HashMap<(Signature, [u8; 16]), RecordIds>,
    objects: HashMap<(Signature, Arc<[Identity]>), RecordIds>, buffer: Vec<u8>,
}
impl Index {
    pub(super) fn open(folder: &Path, mode: WatchDeduplication, scope: WatchDeduplicationScope) -> io::Result<Self> {
        let mut index = Self { path: folder.join("dedup.wal.bin"), mode, scope, file: None, seq: 0,
            epoch: 0, generation: 0, next_id: 1, ready: false, edits: 0, domains: HashMap::new(), next_domain: 1, journals: HashMap::new(), records: HashMap::new(),
            owners: HashMap::new(), paths: BTreeMap::new(), sizes: HashMap::new(),
            hashes: HashMap::new(), objects: HashMap::new(), buffer: Vec::new() };
        if mode == WatchDeduplication::None { index.erase()?; return Ok(index); }
        fs::create_dir_all(folder)?;
        let loaded = (|| -> io::Result<()> {
            let mut reader = wal::Reader::new(File::open(&index.path)?, Kind::DedupWal)?;
            let mut begun = false;
            while let Some(seq) = reader.next()? {
                if seq != index.seq + 1 { return Err(wal::invalid("deduplication WAL gap")); }
                let delta: Delta = wal::decode(&reader.payload)?;
                match delta {
                    Delta::Begin(saved, saved_scope) if !begun && saved == mode_tag(mode) && saved_scope == scope_tag(scope) => begun = true,
                    Delta::Put(record) if begun => { index.insert(record.into_owned()); },
                    Delta::Remove(ids) if begun => { for id in ids { index.remove(id); } },
                    Delta::Journals(stamps) if begun => { index.apply_journals(&stamps); },
                    Delta::Ready if begun => index.ready = true,
                    Delta::Pending if begun => index.ready = false,
                    _ => return Err(wal::invalid("deduplication mode changed")),
                }
                index.seq = seq;
            }
            if reader.torn || !begun || !index.ready { return Err(wal::invalid("incomplete deduplication index")); }
            Ok(())
        })();
        if loaded.is_err() { index.erase()?; index.start()?; }
        else {
            // No rehash on restart: only validate the persisted physical generation.
            let stale: Vec<_> = index.records.values().filter(|r| !r.current()).map(|r| r.id).collect();
            index.file = Some(OpenOptions::new().append(true).open(&index.path)?);
            index.remove_ids(stale)?;
        }
        Ok(index)
    }
    pub(super) fn generation(&self) -> u64 { self.generation }
    /// Publish the unfinished scope rebuild before starting discovery. Keep
    /// valid resident records and hashes available to the rebuilding observer.
    pub(super) fn begin_rebuild(&mut self) -> io::Result<()> {
        if self.mode == WatchDeduplication::None { return Ok(()); }
        self.append(&Delta::Pending)?;
        self.ready = false; self.epoch += 1; self.generation += 1;
        if let Some(file) = &self.file { file.sync_data()?; }
        Ok(())
    }
    pub(super) fn finish_rebuild_if(&mut self, generation: u64) -> io::Result<bool> {
        if self.generation != generation { return Ok(false); }
        self.finish_rebuild()?; Ok(true)
    }
    fn admission_epoch(&self, scope: &str, generation: Option<u64>) -> Option<u64> {
        (self.mode != WatchDeduplication::None
            && generation.is_none_or(|generation| generation == self.generation)
            && self.journals.get(scope).is_some_and(|stamp| !stamp.0.is_empty()))
            .then_some(self.epoch)
    }
    pub(super) fn needs_rebuild(&self) -> bool { self.mode != WatchDeduplication::None && !self.ready }
    pub(super) fn finish_rebuild(&mut self) -> io::Result<()> {
        if self.mode != WatchDeduplication::None && !self.ready {
            if self.journals.values().any(|stamp| stamp.0.is_empty()) { return Err(io::Error::other("deduplication journal continuity unavailable")); }
            self.append(&Delta::Ready)?; self.ready = true;
            if let Some(file) = &self.file { file.sync_data()?; }
        }
        Ok(())
    }
    /// Drops all memory before deleting the old stream, even when the next mode is none.
    pub(super) fn reset(&mut self, mode: WatchDeduplication, scope: WatchDeduplicationScope) -> io::Result<()> {
        self.erase()?; self.mode = mode; self.scope = scope;
        if mode != WatchDeduplication::None { self.start()?; }
        Ok(())
    }
    fn erase(&mut self) -> io::Result<()> {
        self.file = None; self.domains = HashMap::new(); self.next_domain = 1; self.journals = HashMap::new(); self.records = HashMap::new(); self.owners = HashMap::new(); self.paths = BTreeMap::new();
        self.sizes = HashMap::new(); self.hashes = HashMap::new(); self.objects = HashMap::new(); self.buffer = Vec::new();
        self.seq = 0; self.next_id = 1; self.ready = false; self.edits = 0; self.epoch += 1; self.generation += 1;
        for path in [&self.path, &self.path.with_extension("tmp")] {
            match fs::remove_file(path) { Ok(()) => (), Err(e) if e.kind() == io::ErrorKind::NotFound => (), Err(e) => return Err(e) }
        }
        Ok(())
    }
    fn start(&mut self) -> io::Result<()> {
        if let Some(folder) = self.path.parent() { fs::create_dir_all(folder)?; }
        let mut file = File::create(&self.path)?;
        file.write_all(&wal::file_header(Kind::DedupWal))?; self.file = Some(file);
        self.append(&Delta::Begin(mode_tag(self.mode), scope_tag(self.scope)))
    }
    fn prepare(&mut self, epoch: u64, mut record: Record, baseline: bool) -> Option<Prepared> {
        // Removing a scope with no resident entries can retire its journal
        // without bumping the epoch.
        if self.admission_epoch(&record.scope, None) != Some(epoch) { return None; }
        let signature = self.signature(&record);
        if let Some(saved) = self.owners.get(&record.owner).and_then(|id| self.records.get(id)).filter(|r| {
            r.layout == record.layout && r.identities == record.identities
                && (r.same_source_paths_and_versions(&record) || r.current())
        }) {
            if saved.admitted && saved.scope == record.scope { return None; }
            record.digest = saved.digest;
        }
        if self.mode == WatchDeduplication::Hash && record.digest.is_none() {
            record.digest = self.objects.get(&(signature.clone(), Arc::clone(&record.identities))).and_then(|ids|
                ids.iter().filter_map(|id| self.records.get(&id))
                    .find(|r| record.same_source_versions(r) || r.current())
                    .and_then(|r| r.digest));
        }
        record.id = self.next_id; self.next_id += 1;
        let matching = self.sizes.get(&signature);
        let representative = if self.mode == WatchDeduplication::Hash {
            matching.and_then(|bucket| bucket.pending().filter_map(|id| self.records.get(&id)).find(|r| r.owner != record.owner)).cloned()
        } else { None };
        let hash = self.mode == WatchDeduplication::Hash && (baseline || matching.is_some());
        Some(Prepared { epoch, record, representative, hash })
    }

    #[cfg(test)]
    fn prepare_path(&mut self, owner: &str, scope: &str, inputs: &[&ArchiveInput], baseline: bool) -> io::Result<Option<Prepared>> {
        let Some(epoch) = self.admission_epoch(scope, None) else { return Ok(None); };
        Ok(describe(owner, scope, inputs)?.and_then(|record| self.prepare(epoch, record, baseline)))
    }
    /// Repeat only work newly made necessary by a concurrent admission. The caller
    /// holds the same lock from a false return through commit.
    fn refresh(&self, prepared: &mut Prepared) -> bool {
        if self.mode != WatchDeduplication::Hash
            || self.admission_epoch(&prepared.record.scope, None) != Some(prepared.epoch)
        {
            return false;
        }
        let Some(bucket) = self.sizes.get(&self.signature(&prepared.record)) else { return false; };
        let mut changed = false;
        if prepared.record.digest.is_none() { prepared.hash = true; changed = true; }
        if let Some(rep) = bucket.pending().filter_map(|id| self.records.get(&id)).find(|r| r.owner != prepared.record.owner) {
            if prepared.representative.as_ref().is_none_or(|r| r.id != rep.id) {
                prepared.representative = Some(rep.clone()); changed = true;
            }
        }
        changed
    }
    fn commit(&mut self, mut prepared: Prepared) -> io::Result<bool> {
        if self.admission_epoch(&prepared.record.scope, None) != Some(prepared.epoch)
            || !prepared.record.current()
        {
            return Ok(false);
        }
        if let Some(rep) = prepared.representative.take() {
            if self.records.get(&rep.id).is_some_and(|old| old.digest.is_none() && old.sources.iter().map(|s| &s.generation).eq(rep.sources.iter().map(|s| &s.generation))) && rep.current() {
                self.append(&Delta::Put(Cow::Borrowed(&rep)))?;
                self.insert(rep);
            }
        }
        let mut record = prepared.record;
        // A retry by its original owner is never suppressed by an alias that arrived later.
        let replaced = self.owners.get(&record.owner).copied();
        let own = replaced.and_then(|id| self.records.get(&id)).is_some_and(|r| {
            r.admitted && r.scope == record.scope && r.layout == record.layout && r.identities == record.identities
                && (r.same_source_paths_and_versions(&record) || r.current())
        });
        if own { return Ok(false); }
        let matches = if self.mode == WatchDeduplication::FileId {
            self.objects.get(&(self.signature(&record), Arc::clone(&record.identities)))
        } else { record.digest.and_then(|d| self.hashes.get(&(self.signature(&record), d))) };
        let mut stale = Vec::new();
        let representative = matches.and_then(|ids| ids.iter().find_map(|id| {
            let r = self.records.get(&id)?;
            if r.current() { Some(r.owner.as_ref()) } else { stale.push(id); None }
        }));
        let duplicate = representative.is_some_and(|owner| owner != record.owner.as_ref());
        self.remove_ids(stale)?;
        record.admitted = !duplicate;
        // Superseded owner layouts must not retain an obsolete signature indefinitely.
        if let Some(id) = replaced.filter(|id| self.records.contains_key(id)) {
            self.remove_ids(vec![id])?;
        }
        self.append(&Delta::Put(Cow::Borrowed(&record)))?; self.insert(record);
        self.compact()?;
        Ok(duplicate)
    }
    pub(super) fn invalidate(&mut self, paths: &[String]) -> io::Result<()> {
        let ids = paths.iter()
            .filter_map(|path| self.paths.get(path_key(path).as_str()))
            .flat_map(RecordIds::iter)
            .collect();
        self.invalidate_ids(ids, None)
    }
    /// The scheduler supplies its already queried per-volume cursors. USNs are
    /// comparable only within the same journal incarnation.
    pub(super) fn reconcile_journals(&mut self, stamps: &[(String, String, u64)]) -> io::Result<bool> {
        if self.mode == WatchDeduplication::None { return Ok(false); }
        let changed = self.apply_journals(stamps);
        if changed { self.append(&Delta::Journals(stamps.to_vec()))?; }
        Ok(changed)
    }
    fn apply_journals(&mut self, stamps: &[(String, String, u64)]) -> bool {
        let volumes: HashMap<_, _> = stamps.iter().filter(|(_, volume, _)| !volume.is_empty()).map(|(_, volume, journal)| (volume.as_str(), *journal)).collect();
        let mut changed: HashSet<String> = stamps.iter().filter(|(scope, volume, journal)| self.journals.get(scope).is_none_or(|old| old.0 != *volume || old.1 != *journal)).map(|(scope, _, _)| scope.clone()).collect();
        // A journal belongs to a volume, not to a monitored root. A checkpoint
        // may probe just one root; invalidate every old incarnation on that
        // volume before Global comparisons can observe another root's record.
        for (scope, (volume, old_journal)) in &mut self.journals {
            if let Some(&journal) = volumes.get(volume.as_str()) {
                if *old_journal != journal { changed.insert(scope.clone()); *old_journal = journal; }
            }
        }
        if changed.is_empty() { return false; }
        let ids: Vec<_> = self.records.values().filter(|r| changed.contains(r.scope.as_ref())).map(|r| r.id).collect();
        for id in ids { self.remove(id); }
        for (scope, volume, journal) in stamps { self.domain(scope); self.journals.insert(scope.clone(), (volume.clone(), *journal)); }
        self.ready = false; self.epoch += 1; self.generation += 1;
        true
    }
    pub(super) fn reconcile_scopes(&mut self, scopes: &[NativeDiscoveryScope]) -> io::Result<()> {
        if scopes.is_empty() {
            if !self.journals.is_empty() || self.records.capacity() != 0 || self.needs_rebuild() {
                self.reset(self.mode, self.scope)?; self.finish_rebuild()?;
            }
            return Ok(());
        }
        self.journals.retain(|key, _| scopes.iter().any(|scope| scope.key() == key));
        let mut removed = Vec::new();
        let mut rebound = Vec::new();
        for r in self.records.values() {
            // A nested root changing ownership must not turn the same physical
            // input into a second candidate or discard a still-monitored alias.
            let target = scopes.iter().filter(|scope| r.sources.iter().all(|s| scope.contains(&s.path))).max_by_key(|scope| scope.key().len());
            match target {
                Some(scope) if scope.key() != r.scope.as_ref() => rebound.push((r.id, scope.key())),
                Some(_) => (),
                None => removed.push(r.id),
            }
        }
        if !removed.is_empty() || !rebound.is_empty() { self.epoch += 1; }
        self.remove_ids(removed)?;
        for (id, scope) in rebound {
            let mut record = self.records[&id].clone();
            record.scope = self.domain(scope);
            self.append(&Delta::Put(Cow::Borrowed(&record)))?;
            self.insert(record);
        }
        self.domains.retain(|key, _| scopes.iter().any(|scope| scope.key() == key.as_ref()));
        Ok(())
    }
    pub(super) fn invalidate_tree(&mut self, path: &str) -> io::Result<()> {
        let key = path_key(path);
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        let descendants = self.paths.range(Arc::from(prefix.as_str())..)
            .take_while(|(path, _)| path.starts_with(&prefix))
            .map(|(_, ids)| ids);
        let ids: HashSet<_> = self.paths.get(key.as_str()).into_iter()
            .chain(descendants)
            .flat_map(RecordIds::iter)
            .collect();
        if ids.is_empty() { return Ok(()); }
        // An absent directory proves its lexical children are absent too.
        // The index folds case, so still validate paths with a different spelling.
        let subtree = Path::new(path);
        let missing = matches!(subtree.try_exists(), Ok(false)).then_some(subtree);
        self.invalidate_ids(ids, missing)
    }
    fn invalidate_ids(&mut self, ids: HashSet<u64>, missing_subtree: Option<&Path>) -> io::Result<()> {
        let stale = ids.into_iter()
            .filter(|id| self.records.get(id).is_some_and(|record| {
                missing_subtree.is_some_and(|path| {
                    record.sources.iter().any(|source| {
                        Path::new(&source.path).strip_prefix(path).is_ok_and(|tail| {
                            tail.components().all(|part| matches!(part, std::path::Component::Normal(_)))
                        })
                    })
                }) || !record.current()
            }))
            .collect();
        self.remove_ids(stale)
    }
    fn remove_ids(&mut self, ids: Vec<u64>) -> io::Result<()> {
        if ids.is_empty() { return Ok(()); }
        // Remove memory first: failed persistence may lose suppression but cannot cause a stale skip.
        for id in &ids { self.remove(*id); }
        self.append(&Delta::Remove(ids))?;
        shrink(&mut self.records); shrink(&mut self.owners);
        shrink(&mut self.sizes); shrink(&mut self.hashes); shrink(&mut self.objects);
        self.compact()
    }
    fn domain(&mut self, scope: &str) -> Arc<str> {
        if let Some((scope, _)) = self.domains.get_key_value(scope) { return Arc::clone(scope); }
        let scope: Arc<str> = Arc::from(scope);
        self.domains.insert(Arc::clone(&scope), self.next_domain);
        self.next_domain += 1;
        scope
    }
    fn signature(&self, r: &Record) -> Signature {
        (match self.scope { WatchDeduplicationScope::Root => self.domains[&r.scope], WatchDeduplicationScope::Global => 0 }, Arc::clone(&r.layout))
    }
    fn insert(&mut self, mut r: Record) {
        r.scope = self.domain(&r.scope);
        let mut signature = self.signature(&r);
        self.remove(r.id); self.next_id = self.next_id.max(r.id + 1);
        self.owners.insert(Arc::clone(&r.owner), r.id);
        for s in r.sources.iter() {
            let path = path_key(&s.path);
            let path = if path == r.owner.as_ref() { Arc::clone(&r.owner) } else { Arc::from(path) };
            self.paths.entry(path).or_insert(RecordIds::One(r.id)).insert(r.id);
        }
        if self.mode == WatchDeduplication::Hash {
            if let Some((saved, _)) = self.sizes.get_key_value(&signature) {
                r.layout = Arc::clone(&saved.1);
                signature.1 = Arc::clone(&saved.1);
            }
            let bucket = self.sizes.entry(signature.clone()).or_default();
            bucket.count += 1;
            if let Some(digest) = r.digest {
                self.hashes.entry((signature.clone(), digest)).or_insert(RecordIds::One(r.id)).insert(r.id);
            } else {
                bucket.unhashed.get_or_insert(RecordIds::One(r.id)).insert(r.id);
            }
        }
        if self.mode == WatchDeduplication::FileId || r.digest.is_some() {
            self.objects.entry((signature, Arc::clone(&r.identities))).or_insert(RecordIds::One(r.id)).insert(r.id);
        }
        self.records.insert(r.id, r);
    }
    fn remove(&mut self, id: u64) {
        let Some(r) = self.records.remove(&id) else { return; };
        let signature = self.signature(&r);
        self.owners.remove(&r.owner);
        for s in r.sources.iter() {
            let key = path_key(&s.path);
            if self.paths.get_mut(key.as_str()).is_some_and(|ids| ids.remove(id)) {
                self.paths.remove(key.as_str());
            }
        }
        if let Some(bucket) = self.sizes.get_mut(&signature) {
            bucket.count -= 1;
            if r.digest.is_none() && bucket.unhashed.as_mut().is_some_and(|ids| ids.remove(id)) {
                bucket.unhashed = None;
            }
            if bucket.count == 0 { self.sizes.remove(&signature); }
        }
        if self.mode == WatchDeduplication::FileId || r.digest.is_some() {
            remove_bucket(&mut self.objects, &(signature.clone(), r.identities), id);
        }
        if let Some(d) = r.digest { remove_bucket(&mut self.hashes, &(signature, d), id); }
    }
    fn append(&mut self, delta: &Delta<'_>) -> io::Result<()> {
        let Some(file) = &mut self.file else {
            return if self.mode == WatchDeduplication::None { Ok(()) }
                else { Err(io::Error::other("deduplication index is not writable")) };
        };
        let seq = self.seq + 1;
        wal::append_frame(file, &mut self.buffer, seq, |out| rmp_serde::encode::write(out, delta).map_err(wal::invalid))?;
        self.seq = seq; self.edits += 1; Ok(())
    }
    fn compact(&mut self) -> io::Result<()> {
        if self.edits < self.records.len().saturating_mul(2).saturating_add(1024) || self.file.as_ref().map_or(0, |f| f.metadata().map_or(0, |m| m.len())) < 4 * 1024 * 1024 { return Ok(()); }
        let temp = self.path.with_extension("tmp");
        let mut file = File::create(&temp)?; file.write_all(&wal::file_header(Kind::DedupWal))?;
        let mut seq = 0;
        let mut write = |d: &Delta<'_>| -> io::Result<()> { seq += 1; wal::append_frame(&mut file, &mut self.buffer, seq, |out| rmp_serde::encode::write(out, d).map_err(wal::invalid)) };
        write(&Delta::Begin(mode_tag(self.mode), scope_tag(self.scope)))?;
        write(&Delta::Journals(self.journals.iter().map(|(scope, (volume, id))| (scope.clone(), volume.clone(), *id)).collect()))?;
        for r in self.records.values() { write(&Delta::Put(Cow::Borrowed(r)))?; }
        if self.ready { write(&Delta::Ready)?; }
        file.sync_all()?; drop(file); self.file = None;
        crate::io::atomic_file::replace(&temp, &self.path)?;
        self.file = Some(OpenOptions::new().append(true).open(&self.path)?); self.seq = seq; self.edits = 0; Ok(())
    }
}
fn remove_bucket<K: std::hash::Hash + Eq>(map: &mut HashMap<K, RecordIds>, key: &K, id: u64) {
    if map.get_mut(key).is_some_and(|ids| ids.remove(id)) { map.remove(key); }
}
fn describe(owner: &str, scope: &str, inputs: &[&ArchiveInput]) -> io::Result<Option<Record>> {
    let mut layouts = Vec::with_capacity(inputs.len());
    let mut identities = Vec::new();
    let mut sources: Vec<Source> = Vec::new();
    let mut range_sources = Vec::new();
    let mut physical = HashMap::<String, u32>::new();
    for original in inputs {
        if original.analysis.missing_volume_evidence.is_some() { return Ok(None); }
        // A singleton fixed plan has no selection ambiguity. Reuse the canonical
        // materializer (including head trimming); never enumerate alternatives.
        let materialized;
        let input = if let Some(plan) = original.volume_attempts.as_deref() {
            if plan.layouts.len() != 1 { return Ok(None); }
            let layout = &plan.layouts[0];
            if layout.slots.is_empty() || (layout.minimum_slots != 0 && layout.minimum_slots != layout.slots.len()) { return Ok(None); }
            let Some(sources) = layout.slots.iter().map(|slot| plan.domains.get(slot.domain).and_then(|d| (d.choices.len() == 1).then(|| d.choices[0]))).collect::<Option<Vec<_>>>() else { return Ok(None); };
            let mut fixed = (*original).clone();
            if fixed.select_volumes(&VolumeSelection { layout: 0, sources }).is_err() { return Ok(None); }
            materialized = fixed; &materialized
        } else { *original };
        if input.format_hint.is_empty() || input.volume_attempts.is_some() || matches!(input.analysis.volume_completeness, Some(VolumeCompleteness::Missing | VolumeCompleteness::Unknown)) { return Ok(None); }
        let mode = match input.mode { OpenMode::File => 0, OpenMode::FileRange => 1, OpenMode::ConcatRanges => 2, OpenMode::NativeVolumes => 3, OpenMode::SfxWithVolumes => 4 };
        let mut parts = Vec::with_capacity(match input.mode {
            OpenMode::File => 1,
            OpenMode::ConcatRanges => input.ranges.len(),
            _ => input.parts.len(),
        });
        let mut push = |path: &str, start: u64, end: Option<u64>, role: u8, number: Option<u32>, whole: bool| -> io::Result<bool> {
            // Whole files and carriers with one spelling need no lookup table.
            let (existing, path_id) = match sources.first() {
                None => (None, None),
                Some(first) if first.path == path => (Some(0), None),
                Some(first) => {
                    if physical.is_empty() {
                        physical.insert(path_key(&first.path), 0);
                    }
                    let path_id = path_key(path);
                    (physical.get(&path_id).copied(), Some(path_id))
                }
            };
            let source = if let Some(id) = existing { id } else {
                let Some(snapshot) = crate::filesystem::watch_ready_file_snapshot(Path::new(path), None)? else { return Ok(false); };
                let id = sources.len() as u32;
                sources.push(Source {
                    path: path.into(),
                    generation: snapshot.generation,
                    size: snapshot.metadata.len(),
                    mtime: mtime_seconds(&snapshot.metadata),
                    file_id: snapshot.observation.file_id,
                    usn: snapshot.observation.change_usn,
                });
                if let Some(path_id) = path_id {
                    physical.insert(path_id, id);
                }
                id
            };
            let observed = &sources[source as usize];
            let Some((volume, file)) = observed.generation.object_id() else { return Ok(false); };
            let end = match end { Some(end) => end, None if whole => observed.size, None => return Ok(false) };
            let Some(len) = end.checked_sub(start) else { return Ok(false); };
            if len == 0 || end > observed.size { return Ok(false); }
            parts.push((role, number, len));
            identities.push(Identity { volume, file, start, len });
            range_sources.push(source);
            Ok(true)
        };
        if input.mode == OpenMode::File {
            if !push(&input.entry_path, 0, None, 0, None, true)? { return Ok(None); }
        } else if input.mode == OpenMode::ConcatRanges {
            if input.ranges.is_empty() { return Ok(None); }
            for p in input.ranges.iter() { if !push(&p.path, p.start, p.end, 0, None, false)? { return Ok(None); } }
        } else {
            if input.parts.is_empty() { return Ok(None); }
            for p in input.parts.iter() {
                let role = match p.role { InputRole::Main => 0, InputRole::First => 1, InputRole::Member => 2, InputRole::Terminal => 3 };
                if !push(&p.extent.path, p.extent.start, p.extent.end, role, p.volume_number, input.mode.structured())? { return Ok(None); }
            }
        }
        layouts.push(Layout { format: input.format_hint.clone(), mode, parts: parts.into_boxed_slice() });
    }
    Ok(Some(Record {
        id: 0,
        owner: Arc::from(path_key(owner)),
        scope: Arc::from(scope),
        layout: layouts.into(),
        admitted: false,
        sources: sources.into_boxed_slice(),
        range_sources: range_sources.into_boxed_slice(),
        identities: identities.into(),
        digest: None,
    }))
}

fn mode_tag(mode: WatchDeduplication) -> u8 { match mode { WatchDeduplication::None => 0, WatchDeduplication::FileId => 1, WatchDeduplication::Hash => 2 } }

fn scope_tag(scope: WatchDeduplicationScope) -> u8 { match scope { WatchDeduplicationScope::Root => 0, WatchDeduplicationScope::Global => 1 } }

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_tests.rs"]
mod tests;

fn shrink<K: std::hash::Hash + Eq, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > 1024 && map.len().saturating_mul(4) < map.capacity() { map.shrink_to(map.len().saturating_mul(2)); }
}


#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_bench.rs"]
mod bench;
