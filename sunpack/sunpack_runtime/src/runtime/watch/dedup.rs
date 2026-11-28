//! Watch-only live logical-input index. It is a disposable cache, never a success receipt.
use super::dedup_hash::StreamHash;
use crate::core::config::{WatchDeduplication, WatchDeduplicationScope};
use crate::io::archive_state::{ArchiveInput, OpenMode, VolumeCompleteness};
use crate::io::view::{ConfiguredViews, ReadView, Span};
use crate::io::reader::{physical_file_generation_from_metadata, PhysicalFileGeneration};
use crate::collections::{trim_map, SmallOrderedSet};
use crate::path_keys::{path_ancestors, path_key};
use crate::postprocess::{mtime_seconds, watch_usn_content_changed};
use crate::scan::scope::NativeDiscoveryScope;
use crate::wal::{self, Kind};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Identity {
    volume: u64, file: [u8; 16], start: u64, len: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reversed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct Source { path: Arc<str>, generation: PhysicalFileGeneration, mtime: f64, usn: i64 }
type SourceSnapshot = crate::filesystem::WatchFileSnapshot<PhysicalFileGeneration>;

impl Source {
    fn current_snapshot(&self) -> Option<SourceSnapshot> {
        crate::filesystem::watch_ready_file_snapshot(
            Path::new(self.path.as_ref()), Some(self.usn), physical_file_generation_from_metadata,
        )
            .ok().flatten().filter(|snapshot| {
                snapshot.captured.object_id() == self.generation.object_id()
                    && snapshot.captured.len == self.generation.len
                    && snapshot.change_usn() >= self.usn
                    && !watch_usn_content_changed(
                        self.mtime, self.usn, mtime_seconds(&snapshot.metadata),
                        snapshot.change_usn(), snapshot.change_reasons,
                    )
            })
    }

    fn hash_snapshot(&self) -> io::Result<SourceSnapshot> {
        self.current_snapshot().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "deduplication input changed or is being written")
        })
    }

    fn update_snapshot(&mut self, snapshot: SourceSnapshot) {
        self.mtime = mtime_seconds(&snapshot.metadata);
        self.usn = snapshot.change_usn();
        self.generation = snapshot.captured;
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    id: u64,
    owner: Arc<str>,
    scope: Arc<str>,
    bytes: u64,
    layout: LogicalLayout,
    admitted: bool,
    sources: Arc<[Source]>,
    // All extents use source zero when there is only one physical source.
    range_sources: Box<[u32]>,
    identities: Arc<[Identity]>,
    digest: Option<[u8; 16]>,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum LogicalLayout {
    Single(u64),
    SingleLong(Arc<str>),
    Archives(Arc<[LogicalArchive]>),
}

impl LogicalLayout {
    fn single(format: &str) -> Self {
        let mut tag = [0; 8];
        let bytes = format.as_bytes();
        if bytes.len() <= tag.len() && !bytes.contains(&0) {
            tag[..bytes.len()].copy_from_slice(bytes);
            Self::Single(u64::from_le_bytes(tag))
        } else {
            Self::SingleLong(Arc::from(format))
        }
    }
}

#[derive(PartialEq, Eq, Hash, Serialize, Deserialize)]
struct LogicalArchive {
    format: Box<str>,
    len: u64,
    named_parts: Option<NamedParts>,
}

#[derive(PartialEq, Eq, Hash, Serialize, Deserialize)]
struct NamedParts {
    mode: OpenMode,
    parts: Box<[(Option<u32>, u64)]>,
}

impl Record {
    fn source_index(&self, range: usize) -> usize {
        if self.range_sources.is_empty() { 0 } else { self.range_sources[range] as usize }
    }

    fn current(&self) -> bool {
        self.sources.iter().all(|s| s.current_snapshot().is_some())
    }
    fn hash(&mut self) -> io::Result<()> {
        let short = self.identities.iter().all(|extent| extent.len <= crate::io::iocp::ORDERED_READ_CHUNK as u64);
        if !short {
            // Long IOCP reads share writes and renames. Confirm readiness
            // once per source before opening those streams.
            for source in Arc::make_mut(&mut self.sources) {
                source.update_snapshot(source.hash_snapshot()?);
            }
        }
        let mut hash = StreamHash::new();
        for (range, extent) in self.identities.iter().enumerate() {
            let source_index = self.source_index(range);
            let source = &self.sources[source_index];
            let mut refreshed = None;
            hash.read(Path::new(source.path.as_ref()), extent.start, extent.len, extent.reversed, |opened| {
                if short {
                    // The short read handle itself excludes writers and
                    // renames. Consult the USN journal only on a changed generation.
                    if opened == &source.generation { return Ok(()); }
                    let snapshot = source.hash_snapshot()?;
                    if opened == &snapshot.captured {
                        refreshed = Some(snapshot);
                        return Ok(());
                    }
                } else if opened.matches_input(&source.generation) {
                    return Ok(());
                }
                Err(io::Error::other("file changed before streaming range"))
            })?;
            if let Some(snapshot) = refreshed {
                Arc::make_mut(&mut self.sources)[source_index].update_snapshot(snapshot);
            }
        }
        self.digest = Some(hash.finish());
        Ok(())
    }

    // The physical index has already matched the ordered extents. Compare
    // their sampled versions before reusing a digest through another name.
    fn same_source_versions(&self, other: &Self) -> bool {
        let ranges = if self.range_sources.is_empty() && other.range_sources.is_empty() {
            1
        } else {
            self.identities.len()
        };
        (0..ranges).all(|range| {
            let left = &self.sources[self.source_index(range)];
            let right = &other.sources[other.source_index(range)];
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
    Begin(u8, u8, ConfiguredViews),
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
    generation: u64,
    baseline: bool,
) -> io::Result<bool> {
    if inputs.is_empty() { return Ok(false); }
    // Both baseline and active requests may outlive a view-policy reset.
    let Some(epoch) = index.lock().unwrap().admission_epoch(scope, Some(generation)) else {
        return Ok(false);
    };
    // Describing the sources opens files and queries NTFS/ReFS. Each job can
    // do that under its existing Watch work budget while other jobs commit.
    let Some(record) = describe(owner, scope, inputs)? else { return Ok(false); };
    let mut locked = index.lock().unwrap();
    let Some(prepared) = locked.prepare(epoch, record, baseline) else {
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

pub(super) fn invalidate<'a>(
    index: &Mutex<Index>,
    paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    invalidate_records(index, None, |index| {
        paths.into_iter()
            .filter_map(|path| index.paths.get(path_key(path).as_str()))
            .flat_map(RecordIds::iter).copied().collect()
    })
}

pub(super) fn invalidate_tree(index: &Mutex<Index>, path: &str) -> io::Result<()> {
    let key = path_key(path);
    let range = crate::path_keys::descendant_key_range(&key);
    use std::ops::Bound::{Excluded, Included};
    invalidate_records(index, Some(Path::new(path)), |index| {
        let descendants = index.paths.range::<str, _>((Included(range.start.as_str()), Excluded(range.end.as_str())))
            .map(|(_, ids)| ids);
        index.paths.get(key.as_str()).into_iter().chain(descendants)
            .flat_map(RecordIds::iter).copied().collect()
    })
}

fn invalidate_records(
    index: &Mutex<Index>,
    subtree: Option<&Path>,
    matching: impl FnOnce(&Index) -> HashSet<u64>,
) -> io::Result<()> {
    let records: Vec<_> = {
        let index = index.lock().unwrap();
        matching(&index).into_iter()
            .filter_map(|id| index.records.get(&id).map(|record| (id, Arc::clone(&record.sources))))
            .collect()
    };
    if records.is_empty() { return Ok(()); }
    let missing = subtree.filter(|path| matches!(path.try_exists(), Ok(false)));
    let stale: Vec<_> = records.into_iter().filter(|(_, sources)| {
        // A missing directory proves absence only for its literal children.
        // The key index also includes case-folded spellings.
        missing.is_some_and(|path| sources.iter().any(|source| {
            Path::new(source.path.as_ref()).strip_prefix(path).is_ok_and(|tail| {
                tail.components().all(|part| matches!(part, std::path::Component::Normal(_)))
            })
        })) || sources.iter().any(|source| source.current_snapshot().is_none())
    }).collect();
    if stale.is_empty() { return Ok(()); }
    let mut index = index.lock().unwrap();
    // Hash publication can refresh an existing ID, and a reset can recycle
    // IDs. Retire only the source snapshot actually checked outside the lock.
    let ids = stale.into_iter().filter_map(|(id, sources)| {
        index.records.get(&id).is_some_and(|record| Arc::ptr_eq(&record.sources, &sources)).then_some(id)
    }).collect();
    index.remove_ids(ids)
}

type Signature = (u64, u64, LogicalLayout);
const STALE_BATCH: usize = 16;

type RecordIds = SmallOrderedSet<u64>;

#[derive(Default)]
struct SizeBucket { count: usize, unhashed: Option<RecordIds> }

impl SizeBucket {
    fn pending(&self) -> impl Iterator<Item = &u64> + '_ {
        self.unhashed.iter().flat_map(RecordIds::iter)
    }

    fn remove_pending(&mut self, id: u64) {
        if self.unhashed.as_mut().is_some_and(|ids| ids.remove(&id)) {
            self.unhashed = None;
        }
    }
}

pub(super) struct Index {
    views: ConfiguredViews,
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
    pub(super) fn open(folder: &Path, mode: WatchDeduplication, scope: WatchDeduplicationScope, views: ConfiguredViews) -> io::Result<Self> {
        let mut index = Self { path: folder.join("dedup.wal.bin"), mode, scope, views, file: None, seq: 0,
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
                    Delta::Begin(saved, saved_scope, views) if !begun && saved == mode_tag(mode)
                        && saved_scope == scope_tag(scope) && views == index.views => begun = true,
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
            // A successful replay can end with few live records even when
            // historical puts grew the in-memory indexes substantially.
            index.trim_record_indices();
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
    pub(super) fn reset(&mut self, mode: WatchDeduplication, scope: WatchDeduplicationScope, views: ConfiguredViews) -> io::Result<()> {
        self.erase()?; self.mode = mode; self.scope = scope; self.views = views;
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
        self.append(&self.begin_record())
    }
    fn begin_record(&self) -> Delta<'static> {
        Delta::Begin(mode_tag(self.mode), scope_tag(self.scope), self.views.clone())
    }
    fn prepare(&mut self, epoch: u64, mut record: Record, baseline: bool) -> Option<Prepared> {
        // Removing a scope with no resident entries can retire its journal
        // without bumping the epoch.
        if self.admission_epoch(&record.scope, None) != Some(epoch) { return None; }
        if let Some(saved) = self.owners.get(&record.owner).and_then(|id| self.records.get(id)).filter(|r| {
            r.bytes == record.bytes && r.layout == record.layout && r.identities == record.identities
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
            .iter().filter_map(|id| self.records.get(id))
            .find(|other| other.digest.is_some() && valid(other))
            .and_then(|other| other.digest)
    }
    fn unhashed_representative(&self, record: &Record) -> Option<Record> {
        let mut representative = self.sizes.get(&self.signature(record))?.pending()
            .filter_map(|id| self.records.get(id)).find(|other| other.owner != record.owner)?.clone();
        representative.digest = self.cached_digest(&representative, |other| {
            representative.same_source_versions(other) || other.current()
        });
        Some(representative)
    }
    fn publish_representative(&mut self, prepared: &mut Prepared) -> io::Result<()> {
        let Some(rep) = prepared.representative.take() else { return Ok(()); };
        let Some(digest) = rep.digest else { return Ok(()); };
        // Within this epoch a live ID still has the same paths, scope and
        // physical ranges. Hashing can only refresh its source versions.
        if !self.records.get(&rep.id).is_some_and(|old| old.digest.is_none()) {
            return Ok(());
        }
        if !rep.current() {
            return self.remove_ids(vec![rep.id]);
        }
        let signature = self.signature(&rep);
        self.append(&Delta::Put(Cow::Borrowed(&rep)))?;
        self.sizes.get_mut(&signature).expect("indexed size bucket").remove_pending(rep.id);
        self.hashes.entry((signature, digest)).or_insert(RecordIds::One(rep.id)).insert(rep.id);
        self.records.insert(rep.id, rep);
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
            r.admitted && r.scope == record.scope && r.bytes == record.bytes
                && r.layout == record.layout && r.identities == record.identities
                && (r.same_source_paths_and_versions(record) || r.current())
        });
        self.publish_representative(&mut prepared)?;
        if own { return Ok(Admission::Finished(false)); }
        loop {
            let record = &mut prepared.record;
            let signature = self.signature(record);
            let objects = self.objects.get(&(signature.clone(), Arc::clone(&record.identities)));
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
                let mut ids = ids.iter().filter_map(|id| self.records.get(id)).filter(|other| {
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
                        matches!(Path::new(source.path.as_ref()).try_exists(), Ok(false))
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
    /// The scheduler supplies its already queried per-volume cursors. USNs are
    /// comparable only within the same journal incarnation.
    pub(super) fn reconcile_journals(&mut self, stamps: &[(String, String, u64)]) -> io::Result<bool> {
        if self.mode == WatchDeduplication::None { return Ok(false); }
        let changed = self.apply_journals(stamps);
        if changed { self.append(&Delta::Journals(stamps.to_vec()))?; }
        Ok(changed)
    }
    fn apply_journals(&mut self, stamps: &[(String, String, u64)]) -> bool {
        // Every previously reconciled scope on a volume already shares its
        // journal ID. A normal checkpoint therefore needs only exact lookups.
        let mut changed: HashSet<&str> = stamps.iter()
            .filter(|(scope, volume, journal)| self.journals.get(scope).is_none_or(|old| old.0 != *volume || old.1 != *journal))
            .map(|(scope, _, _)| scope.as_str()).collect();
        if changed.is_empty() { return false; }
        let volumes: HashMap<_, _> = stamps.iter().filter(|(_, volume, _)| !volume.is_empty()).map(|(_, volume, journal)| (volume.as_str(), *journal)).collect();
        // A journal belongs to a volume, not to a monitored root. A checkpoint
        // may probe just one root; invalidate every old incarnation on that
        // volume before Global comparisons can observe another root's record.
        for (scope, (volume, old_journal)) in &mut self.journals {
            if let Some(&journal) = volumes.get(volume.as_str()) {
                if *old_journal != journal { changed.insert(scope.as_str()); *old_journal = journal; }
            }
        }
        let ids: Vec<_> = self.records.values().filter(|r| changed.contains(r.scope.as_ref())).map(|r| r.id).collect();
        drop(changed);
        for id in ids { self.remove(id); }
        self.trim_record_indices();
        for (scope, volume, journal) in stamps { self.domain(scope); self.journals.insert(scope.clone(), (volume.clone(), *journal)); }
        self.ready = false; self.epoch += 1; self.generation += 1;
        true
    }
    pub(super) fn reconcile_scopes<'a>(
        &mut self, scopes: impl IntoIterator<Item = &'a NativeDiscoveryScope>,
    ) -> io::Result<()> {
        let scopes: HashMap<_, _> = scopes.into_iter().map(|scope| (scope.key(), scope)).collect();
        if scopes.is_empty() {
            if !self.journals.is_empty() || self.records.capacity() != 0 || self.needs_rebuild() {
                self.reset(self.mode, self.scope, self.views.clone())?; self.finish_rebuild()?;
            }
            return Ok(());
        }
        self.journals.retain(|key, _| scopes.contains_key(key.as_str()));
        trim_map(&mut self.journals);
        let mut removed = Vec::new();
        let mut rebound = Vec::new();
        for r in self.records.values() {
            // A nested root changing ownership must not turn the same physical
            // input into a second candidate or discard a still-monitored alias.
            let target = r.sources.split_first().and_then(|(first, remaining)| {
                let path = path_key(&first.path);
                let others = std::cell::OnceCell::new();
                // Any scope covering all members must first cover this one.
                // Ancestors already visit the most specific roots first.
                let target = path_ancestors(&path).filter_map(|ancestor| scopes.get(ancestor).copied())
                    .find(|scope| scope.contains_key(&path) && others
                        .get_or_init(|| remaining.iter().map(|source| path_key(&source.path)).collect::<Vec<_>>())
                        .iter().all(|source| scope.contains_key(source)));
                target
            });
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
        self.domains.retain(|key, _| scopes.contains_key(key.as_ref()));
        trim_map(&mut self.domains);
        Ok(())
    }
    fn remove_ids(&mut self, ids: Vec<u64>) -> io::Result<()> {
        if ids.is_empty() { return Ok(()); }
        // Remove memory first: failed persistence may lose suppression but cannot cause a stale skip.
        for id in &ids { self.remove(*id); }
        self.trim_record_indices();
        self.append(&Delta::Remove(ids))?;
        self.compact()
    }
    fn trim_record_indices(&mut self) {
        trim_map(&mut self.records);
        trim_map(&mut self.owners);
        trim_map(&mut self.sizes);
        trim_map(&mut self.hashes);
        trim_map(&mut self.objects);
    }

    pub(super) fn release_write_buffer(&mut self) {
        self.buffer = Vec::new();
    }
    fn domain(&mut self, scope: &str) -> Arc<str> {
        if let Some((scope, _)) = self.domains.get_key_value(scope) { return Arc::clone(scope); }
        let scope: Arc<str> = Arc::from(scope);
        self.domains.insert(Arc::clone(&scope), self.next_domain);
        self.next_domain += 1;
        scope
    }
    fn signature(&self, r: &Record) -> Signature {
        let scope = match self.scope {
            WatchDeduplicationScope::Root => self.domains[&r.scope],
            WatchDeduplicationScope::Global => 0,
        };
        (scope, r.bytes, r.layout.clone())
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
            if self.paths.get_mut(key.as_str()).is_some_and(|ids| ids.remove(&id)) {
                self.paths.remove(key.as_str());
            }
        }
        if let Some(bucket) = self.sizes.get_mut(&signature) {
            bucket.count -= 1;
            if r.digest.is_none() { bucket.remove_pending(id); }
            if bucket.count == 0 { self.sizes.remove(&signature); }
        }
        remove_bucket(&mut self.objects, &(signature.clone(), r.identities), id);
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
        let begin = self.begin_record();
        let mut seq = 0;
        let mut write = |d: &Delta<'_>| -> io::Result<()> { seq += 1; wal::append_frame(&mut file, &mut self.buffer, seq, |out| rmp_serde::encode::write(out, d).map_err(wal::invalid)) };
        write(&begin)?;
        write(&Delta::Journals(self.journals.iter().map(|(scope, (volume, id))| (scope.clone(), volume.clone(), *id)).collect()))?;
        for r in self.records.values() { write(&Delta::Put(Cow::Borrowed(r)))?; }
        if self.ready { write(&Delta::Ready)?; }
        file.sync_all()?;
        drop(file);
        self.file = None;
        match crate::io::atomic_file::replace_once(&temp, &self.path) {
            Ok(()) => self.seq = seq,
            Err(error) if crate::io::atomic_file::sharing_conflict(&error) => {
                let _ = fs::remove_file(&temp);
            }
            Err(error) => return Err(error),
        }
        self.file = Some(OpenOptions::new().append(true).open(&self.path)?);
        self.edits = 0;
        Ok(())
    }
}
fn remove_bucket<K: std::hash::Hash + Eq>(map: &mut HashMap<K, RecordIds>, key: &K, id: u64) {
    if map.get_mut(key).is_some_and(|ids| ids.remove(&id)) { map.remove(key); }
}
fn describe(owner: &str, scope: &str, inputs: &[&ArchiveInput]) -> io::Result<Option<Record>> {
    describe_with_snapshots(owner, scope, inputs, |path| {
        crate::filesystem::watch_ready_file_snapshot(path, None, physical_file_generation_from_metadata)
    })
}

fn describe_with_snapshots(
    owner: &str,
    scope: &str,
    inputs: &[&ArchiveInput],
    mut snapshot: impl FnMut(&Path) -> io::Result<Option<SourceSnapshot>>,
) -> io::Result<Option<Record>> {
    let Some(first) = inputs.first() else { return Ok(None); };
    let mut identities = Vec::<Identity>::new();
    let mut sources: Vec<Source> = Vec::new();
    let mut range_sources = Vec::new();
    let mut physical = HashMap::<Arc<str>, u32>::new();
    let mut bytes = 0u64;
    let mut archives = Vec::new();
    for &input in inputs {
        if input.format_hint.is_empty() || input.analysis.missing_volume_evidence.is_some() { return Ok(None); }
        let base = bytes;
        // A singleton fixed plan has no selection ambiguity. Reuse the canonical
        // materializer (including head trimming); never enumerate alternatives.
        let materialized;
        let parts = if let Some(plan) = &input.volume_attempts {
            let Some(parts) = plan.sole_parts() else { return Ok(None); };
            materialized = parts;
            &materialized
        } else {
            if matches!(input.analysis.volume_completeness, Some(VolumeCompleteness::Missing | VolumeCompleteness::Unknown)) { return Ok(None); }
            &input.parts
        };
        let mut named_parts = input.uses_named_volumes().then(|| Vec::with_capacity(parts.len()));
        let mut push = |path: &str, start: u64, end: Option<u64>, whole: bool, reversed: bool, view: Option<&ReadView>| -> io::Result<Option<u64>> {
            // Consecutive spans usually share one exact descriptor path.
            // Different case spellings can address distinct files on Windows.
            let recent = range_sources.last().copied().unwrap_or(0);
            let existing = match sources.get(recent as usize) {
                Some(source) if source.path.as_ref() == path => Some(recent),
                _ if sources.first().is_some_and(|source| source.path.as_ref() == path) => Some(0),
                _ => physical.get(path).copied(),
            };
            let source = if let Some(id) = existing { id } else {
                let Some(snapshot) = snapshot(Path::new(path))? else { return Ok(None); };
                let id = sources.len() as u32;
                let path: Arc<str> = Arc::from(path);
                if id != 0 {
                    physical.insert(Arc::clone(&path), id);
                }
                sources.push(Source {
                    path,
                    mtime: mtime_seconds(&snapshot.metadata),
                    usn: snapshot.change_usn(),
                    generation: snapshot.captured,
                });
                id
            };
            let observed = &sources[source as usize];
            let Some((volume, file)) = observed.generation.object_id() else { return Ok(None); };
            let size = observed.generation.len;
            if view.is_some_and(|view| view.physical_size != size || !view.matches_generation(Some(&observed.generation))) {
                return Ok(None);
            }
            let end = match end { Some(end) => end, None if whole => size, None => return Ok(None) };
            let Some(len) = end.checked_sub(start) else { return Ok(None); };
            if len == 0 || end > size { return Ok(None); }
            // Adjacent runs from the same source share one identity and read.
            if recent == source {
                if let Some(last) = identities.last_mut() {
                    let last_end = last.start + last.len;
                    if !reversed && !last.reversed && last_end == start {
                        last.len += len;
                        return Ok(Some(len));
                    }
                    if view.is_some() || last.reversed || (last.len == 1 && len == 1) {
                        let mut run = Span { start: last.start, end: last_end, reverse: last.reversed };
                        if run.join(&Span { start, end, reverse: reversed }) {
                            last.start = run.start;
                            last.len = run.end - run.start;
                            last.reversed = run.reverse;
                            return Ok(Some(len));
                        }
                    }
                }
            }
            if source != 0 && range_sources.is_empty() {
                range_sources.resize(identities.len(), 0);
            }
            if !range_sources.is_empty() { range_sources.push(source); }
            identities.push(Identity { volume, file, start, len, reversed: reversed && len > 1 });
            Ok(Some(len))
        };
        if input.mode == OpenMode::File {
            let Some(len) = push(&input.entry_path, 0, None, true, false, None)? else { return Ok(None); };
            bytes = bytes.checked_add(len).ok_or_else(|| io::Error::other("deduplication byte length overflow"))?;
        } else {
            if parts.is_empty() { return Ok(None); }
            for p in parts.iter() {
                let len = if let Some(view) = &p.extent.view {
                    let length = view.len();
                    let end = p.extent.end.unwrap_or(length);
                    if end <= p.extent.start || end > length { return Ok(None); }
                    let mut valid = true;
                    view.visit(p.extent.start, end, |span| {
                        if valid {
                            valid = push(&p.extent.path, span.start, Some(span.end), false, span.reverse, Some(view))?.is_some();
                        }
                        Ok(())
                    })?;
                    if !valid { return Ok(None); }
                    end - p.extent.start
                } else {
                    let Some(len) = push(&p.extent.path, p.extent.start, p.extent.end, input.mode.structured(), false, None)? else { return Ok(None); };
                    len
                };
                bytes = bytes.checked_add(len).ok_or_else(|| io::Error::other("deduplication byte length overflow"))?;
                if let Some(named_parts) = &mut named_parts { named_parts.push((p.volume_number, len)); }
            }
        }
        if inputs.len() > 1 || named_parts.is_some() {
            archives.push(LogicalArchive {
                format: input.format_hint.as_str().into(), len: bytes - base,
                named_parts: named_parts.map(|parts| NamedParts { mode: input.mode, parts: parts.into_boxed_slice() }),
            });
        }
    }
    // Preserve the boundaries seen by the decoder, including named volumes.
    // Physical carriers and raw chunking leave the logical stream unchanged.
    let layout = if archives.is_empty() {
        LogicalLayout::single(&first.format_hint)
    } else {
        LogicalLayout::Archives(archives.into())
    };
    Ok(Some(Record {
        id: 0,
        owner: Arc::from(path_key(owner)),
        scope: Arc::from(scope),
        bytes,
        layout,
        admitted: false,
        sources: sources.into(),
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

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_bench.rs"]
mod bench;
