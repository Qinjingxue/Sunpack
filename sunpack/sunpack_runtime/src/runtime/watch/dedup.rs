//! Watch-only live logical-input index. It is a disposable cache, never a success receipt.
use super::dedup_hash::{hash_ranges, HashRange};
use crate::core::config::{WatchDeduplication, WatchDeduplicationScope};
use crate::io::archive_state::{ArchiveInput, OpenMode, VolumeCompleteness, VolumeSelection};
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
struct Identity { volume: u64, file: [u8; 16], start: u64, len: u64 }
#[derive(Clone, Serialize, Deserialize)]
struct Source { path: String, generation: PhysicalFileGeneration, size: u64, mtime: f64, file_id: String, usn: i64 }
impl Source {
    fn current_snapshot(&self) -> Option<crate::filesystem::WatchFileSnapshot> {
        crate::filesystem::watch_ready_file_snapshot(Path::new(&self.path), Some(self.usn))
            .ok().flatten().filter(|snapshot| {
                snapshot.generation.object_id() == self.generation.object_id()
                    && snapshot.observation.change_usn >= self.usn
                    && !watch_observed_content_changed(
                        self.size, self.mtime, &self.file_id, self.usn, snapshot.metadata.len(),
                        mtime_seconds(&snapshot.metadata), &snapshot.observation,
                    )
            })
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    id: u64,
    owner: Arc<str>,
    scope: Arc<str>,
    bytes: u64,
    admitted: bool,
    sources: Box<[Source]>,
    range_sources: Box<[u32]>,
    identities: Arc<[Identity]>,
    digest: Option<[u8; 16]>,
}
impl Record {
    fn current(&self) -> bool {
        self.sources.iter().all(|s| s.current_snapshot().is_some())
    }
    fn hash(&mut self) -> io::Result<()> {
        // USN metadata changes preserve content, but an IOCP read must use the
        // current physical generation (which includes LastWriteTime). Refresh
        // that evidence only when actual hashing is needed, not on each event.
        for source in &mut self.sources {
            let Some(snapshot) = source.current_snapshot() else {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "deduplication input changed or is being written"));
            };
            source.generation = snapshot.generation;
            source.mtime = mtime_seconds(&snapshot.metadata);
            source.usn = snapshot.observation.change_usn;
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
    epoch: u64, record: Record, representative: Option<Record>, baseline: bool,
}
impl Prepared {
    fn hash(&mut self) -> io::Result<()> {
        if self.record.digest.is_none() { self.record.hash()?; }
        if let Some(record) = &mut self.representative { if record.digest.is_none() { record.hash()?; } }
        Ok(())
    }
}

enum Admission {
    Hash(Prepared),
    Rescan(Prepared),
    Finished(bool),
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
    let Some(prepared) = locked.prepare(epoch, record, generation.is_some()) else {
        return Ok(false);
    };
    let mut admission = locked.advance(prepared)?;
    drop(locked);
    loop {
        let prepared = match admission {
            Admission::Hash(mut prepared) => {
                prepared.hash()?;
                prepared
            }
            Admission::Rescan(prepared) => prepared,
            Admission::Finished(duplicate) => return Ok(duplicate),
        };
        admission = index.lock().unwrap().advance(prepared)?;
    }
}

type Signature = (u64, u64);
const STALE_BATCH: usize = 16;

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

    fn iter(&self) -> impl DoubleEndedIterator<Item = u64> + '_ {
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
        if let Some(saved) = self.owners.get(&record.owner).and_then(|id| self.records.get(id)).filter(|r| {
            r.bytes == record.bytes && r.identities == record.identities
                && (r.same_source_paths_and_versions(&record) || r.current())
        }) {
            if saved.admitted && saved.scope == record.scope { return None; }
            record.digest = saved.digest;
        }
        if self.mode == WatchDeduplication::Hash && record.digest.is_none() {
            record.digest = self.cached_digest(&record, |other| record.same_source_versions(other));
        }
        record.id = self.next_id; self.next_id += 1;
        Some(Prepared { epoch, record, representative: None, baseline })
    }
    fn other_sized(&self, record: &Record) -> bool {
        self.sizes.get(&self.signature(record)).is_some_and(|bucket| {
            let own = self.owners.get(&record.owner).and_then(|id| self.records.get(id))
                .is_some_and(|old| self.signature(old) == self.signature(record));
            bucket.count > usize::from(own)
        })
    }
    fn cached_digest(&self, record: &Record, valid: impl Fn(&Record) -> bool) -> Option<[u8; 16]> {
        if self.hashes.is_empty() { return None; }
        self.objects.get(&(self.signature(record), Arc::clone(&record.identities)))?
            .iter().filter_map(|id| self.records.get(&id))
            .find(|other| other.digest.is_some() && valid(other))
            .and_then(|other| other.digest)
    }
    fn unhashed_representative(&self, record: &Record) -> Option<Record> {
        let mut representative = self.sizes.get(&self.signature(record))?.pending()
            .filter_map(|id| self.records.get(&id)).find(|other| other.owner != record.owner)?.clone();
        representative.digest = self.cached_digest(&representative, |other| {
            representative.same_source_versions(other) || other.current()
        });
        Some(representative)
    }
    fn publish_representative(&mut self, prepared: &mut Prepared) -> io::Result<()> {
        if let Some(rep) = prepared.representative.take() {
            // IDs are never reused: replacing a source retires the old record.
            // Metadata-only generation refresh is allowed on this same ID.
            if rep.digest.is_some() && self.records.get(&rep.id).is_some_and(|old| old.digest.is_none()) {
                if rep.current() {
                    self.append(&Delta::Put(Cow::Borrowed(&rep)))?;
                    self.insert(rep);
                } else { self.remove_ids(vec![rep.id])?; }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn prepare_path(&mut self, owner: &str, scope: &str, inputs: &[&ArchiveInput], baseline: bool) -> io::Result<Option<Prepared>> {
        let Some(epoch) = self.admission_epoch(scope, None) else { return Ok(None); };
        Ok(describe(owner, scope, inputs)?.and_then(|record| self.prepare(epoch, record, baseline)))
    }
    /// Advance from one locked decision to the next. A live match is checked
    /// after the candidate and used immediately, without a second probe.
    fn advance(&mut self, mut prepared: Prepared) -> io::Result<Admission> {
        let record = &mut prepared.record;
        if self.admission_epoch(&record.scope, None) != Some(prepared.epoch) {
            return Ok(Admission::Finished(false));
        }
        // A retry by its original owner is never suppressed by an alias that arrived later.
        let replaced = self.owners.get(&record.owner).copied();
        let own = replaced.and_then(|id| self.records.get(&id)).is_some_and(|r| {
            r.admitted && r.scope == record.scope && r.bytes == record.bytes && r.identities == record.identities
                && (r.same_source_paths_and_versions(record) || r.current())
        });
        self.publish_representative(&mut prepared)?;
        if own { return Ok(Admission::Finished(false)); }
        loop {
            let record = &mut prepared.record;
            let signature = self.signature(record);
            let objects = self.objects.get(&(signature, Arc::clone(&record.identities)));
            let hashes = if self.mode == WatchDeduplication::Hash {
                record.digest.and_then(|digest| self.hashes.get(&(signature, digest)))
            } else {
                None
            };
            let checked = objects.is_some() || hashes.is_some();
            if checked && !record.current() {
                return Ok(Admission::Finished(false));
            }
            let mut stale = Vec::new();
            let mut matching = None;
            'buckets: for (ids, digest_only) in [(objects, false), (hashes, true)] {
                let Some(ids) = ids else { continue };
                let mut ids = ids.iter().filter_map(|id| self.records.get(&id)).filter(|other| {
                    other.owner != record.owner && (!digest_only || other.identities != record.identities)
                });
                // Prefer the original representative, then try the newest
                // arrival once before continuing in the original order.
                for probe in 0.. {
                    let other = if probe == 1 { ids.next_back() } else { ids.next() };
                    let Some(other) = other else { break };
                    // After a miss, cheaply reject absent paths before the
                    // tracked open and USN query. A hit still needs full proof.
                    let missing = !stale.is_empty() && other.sources.iter().any(|source| {
                        matches!(Path::new(&source.path).try_exists(), Ok(false))
                    });
                    if !missing && other.current() {
                        matching = Some(other);
                        break 'buckets;
                    }
                    stale.push(other.id);
                    if stale.len() == STALE_BATCH {
                        break 'buckets;
                    }
                }
            }
            let duplicate = matching.is_some();
            record.digest = record.digest.or_else(|| matching.and_then(|other| other.digest));
            let rescan = stale.len() == STALE_BATCH;
            self.remove_ids(stale)?;
            if rescan {
                // Let other Watch work acquire the lock before the next
                // batch, which checks the candidate again.
                return Ok(Admission::Rescan(prepared));
            }

            // A rebuild records byte streams without reading their content.
            if !duplicate && !prepared.baseline && self.mode == WatchDeduplication::Hash
                && self.other_sized(record)
            {
                prepared.representative = self.unhashed_representative(record);
                if record.digest.is_none() || prepared.representative.as_ref().is_some_and(|r| r.digest.is_none()) {
                    return Ok(Admission::Hash(prepared));
                }
                if prepared.representative.is_some() {
                    self.publish_representative(&mut prepared)?;
                    continue;
                }
            }
            if !checked && !record.current() {
                return Ok(Admission::Finished(false));
            }
            return self.commit(prepared.record, replaced, duplicate);
        }
    }
    fn commit(&mut self, mut record: Record, replaced: Option<u64>, duplicate: bool) -> io::Result<Admission> {
        record.admitted = !duplicate;
        // Superseded owner layouts must not retain an obsolete signature indefinitely.
        if let Some(id) = replaced.filter(|id| self.records.contains_key(id)) {
            self.remove_ids(vec![id])?;
        }
        self.append(&Delta::Put(Cow::Borrowed(&record)))?; self.insert(record);
        self.compact()?;
        Ok(Admission::Finished(duplicate))
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
        (match self.scope { WatchDeduplicationScope::Root => self.domains[&r.scope], WatchDeduplicationScope::Global => 0 }, r.bytes)
    }
    fn insert(&mut self, mut r: Record) {
        r.scope = self.domain(&r.scope);
        let signature = self.signature(&r);
        self.remove(r.id); self.next_id = self.next_id.max(r.id + 1);
        self.owners.insert(Arc::clone(&r.owner), r.id);
        for s in r.sources.iter() {
            let path = path_key(&s.path);
            let path = if path == r.owner.as_ref() { Arc::clone(&r.owner) } else { Arc::from(path) };
            self.paths.entry(path).or_insert(RecordIds::One(r.id)).insert(r.id);
        }
        if self.mode == WatchDeduplication::Hash {
            let bucket = self.sizes.entry(signature.clone()).or_default();
            bucket.count += 1;
            if let Some(digest) = r.digest {
                self.hashes.entry((signature.clone(), digest)).or_insert(RecordIds::One(r.id)).insert(r.id);
            } else {
                bucket.unhashed.get_or_insert(RecordIds::One(r.id)).insert(r.id);
            }
        }
        self.objects.entry((signature, Arc::clone(&r.identities))).or_insert(RecordIds::One(r.id)).insert(r.id);
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
        remove_bucket(&mut self.objects, &(signature, r.identities), id);
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
        let mut push = |path: &str, start: u64, end: Option<u64>, whole: bool| -> io::Result<bool> {
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
            // Physical segmentation is not content identity. Adjacent extents
            // of the same opened source can share one read and identity range.
            if range_sources.last() == Some(&source)
                && identities.last().is_some_and(|last: &Identity| last.start + last.len == start) {
                identities.last_mut().unwrap().len += len;
            } else {
                identities.push(Identity { volume, file, start, len });
                range_sources.push(source);
            }
            Ok(true)
        };
        if input.mode == OpenMode::File {
            if !push(&input.entry_path, 0, None, true)? { return Ok(None); }
        } else if input.mode == OpenMode::ConcatRanges {
            if input.ranges.is_empty() { return Ok(None); }
            for p in input.ranges.iter() { if !push(&p.path, p.start, p.end, false)? { return Ok(None); } }
        } else {
            if input.parts.is_empty() { return Ok(None); }
            for p in input.parts.iter() {
                if !push(&p.extent.path, p.extent.start, p.extent.end, input.mode.structured())? { return Ok(None); }
            }
        }
    }
    Ok(Some(Record {
        id: 0,
        owner: Arc::from(path_key(owner)),
        scope: Arc::from(scope),
        bytes: identities.iter().try_fold(0u64, |total, range| total.checked_add(range.len))
            .ok_or_else(|| io::Error::other("deduplication byte length overflow"))?,
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
