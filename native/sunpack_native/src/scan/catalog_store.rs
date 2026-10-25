//! Disposable filename cache. Reuses the Watch journal writer on a separate stream.
use super::catalog::{CatalogRow, ScopeCatalog};
use super::directory::DirectoryEntryRecord;
use crate::wal::{self, Kind};
use crate::watch_journal::{self, NativeJournalStream};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Stamp {
    pub identity: String,
    pub depth: Option<usize>,
    pub excluded: Vec<String>,
    pub cursor: Option<(String, u64, i64)>,
}
#[derive(Deserialize)]
struct Delta {
    pub scope: String,
    pub removed: Vec<String>,
    pub rows: Vec<DirectoryEntryRecord>,
    pub stamp: Option<Stamp>,
}
#[derive(Serialize)]
pub(super) struct DeltaView<'a> {
    pub scope: &'a str,
    pub removed: &'a [String],
    pub rows: Vec<&'a CatalogRow>,
    pub stamp: Option<Stamp>,
}
const BATCH_BYTES: usize = 256 * 1024;
const BATCH_DELTAS: usize = 64;
const MIN_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Deserialize)]
struct Snapshot {
    stamps: HashMap<String, Stamp>,
    rows: HashMap<String, ScopeInput>,
}

struct ScopeInput(ScopeCatalog);
impl<'de> Deserialize<'de> for ScopeInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ScopeInput;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("catalog rows")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut catalog = ScopeCatalog::default();
                while let Some(row) = seq.next_element::<DirectoryEntryRecord>()? {
                    catalog.insert(row);
                }
                Ok(ScopeInput(catalog))
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

pub(super) struct CatalogStore {
    folder: PathBuf,
    stream: String,
    handle: Option<NativeJournalStream>,
    seq: u64,
    edits: usize,
    wal_bytes: u64,
    snapshot_bytes: u64,
    pending: Vec<u8>,
    pending_deltas: usize,
    pub stamps: HashMap<String, Stamp>,
    // Drop after the writer handle. Windows also removes this file on a crash.
    _ownership: File,
}
impl CatalogStore {
    pub fn open(folder: &Path, catalogs: &mut HashMap<String, ScopeCatalog>) -> io::Result<Self> {
        fs::create_dir_all(folder)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0).custom_flags(0x04000000); // FILE_FLAG_DELETE_ON_CLOSE
        }
        let ownership = options.open(folder.join("catalog.lock"))?;
        #[cfg(not(windows))]
        ownership.try_lock()?;
        // Only the owner may touch a checkpoint interrupted before publication.
        let _ = fs::remove_file(folder.join("catalog.snapshot.bin.tmp"));
        let mut store = Self {
            folder: folder.to_owned(),
            stream: folder
                .join("catalog.wal.bin")
                .to_string_lossy()
                .into_owned(),
            handle: None,
            seq: 0,
            edits: 0,
            wal_bytes: 0,
            snapshot_bytes: 0,
            pending: Vec::new(),
            pending_deltas: 0,
            stamps: HashMap::new(),
            _ownership: ownership,
        };
        let load = (|| -> io::Result<()> {
            let snapshot = folder.join("catalog.snapshot.bin");
            if snapshot.exists() {
                store.snapshot_bytes = fs::metadata(&snapshot)?.len();
                let (seq, snapshot): (_, Snapshot) =
                    wal::read_snapshot(File::open(snapshot)?, Kind::CatalogSnapshot)?;
                store.seq = seq;
                store.stamps = snapshot.stamps;
                catalogs.extend(
                    snapshot
                        .rows
                        .into_iter()
                        .map(|(scope, rows)| (scope, rows.0)),
                );
            }
            let wal = folder.join("catalog.wal.bin");
            if wal.exists() {
                store.wal_bytes = fs::metadata(&wal)?.len();
                let mut reader = wal::Reader::new(File::open(wal)?, Kind::CatalogWal)?;
                while let Some(seq) = reader.next()? {
                    let deltas: Vec<Delta> = wal::decode(&reader.payload)?;
                    if deltas.is_empty() {
                        return Err(wal::invalid("empty catalog transaction"));
                    }
                    if seq <= store.seq {
                        continue;
                    }
                    if store.seq.checked_add(1) != Some(seq) {
                        return Err(wal::invalid("catalog WAL gap"));
                    }
                    for delta in deltas {
                        store.edits += delta.rows.len() + delta.removed.len() + 1;
                        let catalog = catalogs.entry(delta.scope.clone()).or_default();
                        catalog.remove_many(delta.removed.iter().map(String::as_str));
                        for row in delta.rows {
                            catalog.insert(row);
                        }
                        if let Some(stamp) = delta.stamp {
                            store.stamps.insert(delta.scope, stamp);
                        }
                    }
                    store.seq = seq;
                }
                if reader.torn {
                    return Err(wal::invalid("torn catalog WAL"));
                }
            }
            Ok(())
        })();
        if load.is_err() {
            // A cache never controls the task WAL. Discard it as a unit.
            catalogs.clear();
            store.stamps.clear();
            store.seq = 0;
            store.edits = 0;
            store.wal_bytes = 0;
            store.snapshot_bytes = 0;
            for name in ["catalog.snapshot.bin", "catalog.wal.bin"] {
                let path = folder.join(name);
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
        } else if store.snapshot_bytes != 0 && store.edits == 0 {
            // Successful replay proved that every complete transaction was
            // already covered. Do not rewrite an unchanged snapshot to retire it.
            if fs::remove_file(folder.join("catalog.wal.bin")).is_ok() {
                store.wal_bytes = 0;
            }
        }
        store.handle = Some(
            watch_journal::open_cache(store.stream.clone(), store.seq).map_err(io::Error::other)?,
        );
        Ok(store)
    }
    pub fn append(&mut self, delta: DeltaView<'_>) -> io::Result<()> {
        if self.pending_deltas == 0 {
            // One array32 header allows borrowed deltas to be encoded in place.
            self.pending.extend_from_slice(&[0xdd, 0, 0, 0, 0]);
        }
        rmp_serde::encode::write(
            &mut wal::Bounded(&mut self.pending, wal::MAX_FRAME_BYTES),
            &delta,
        )
        .map_err(wal::invalid)?;
        self.edits += delta.rows.len() + delta.removed.len() + 1;
        let cursor_barrier = delta
            .stamp
            .as_ref()
            .is_some_and(|stamp| stamp.cursor.is_some());
        if let Some(stamp) = delta.stamp {
            self.stamps.insert(delta.scope.to_owned(), stamp);
        }
        self.pending_deltas += 1;
        if cursor_barrier
            || self.pending_deltas >= BATCH_DELTAS
            || self.pending.len() >= BATCH_BYTES
        {
            self.commit()?;
        }
        Ok(())
    }
    pub fn commit(&mut self) -> io::Result<()> {
        if self.pending_deltas == 0 {
            return Ok(());
        }
        self.pending[1..5].copy_from_slice(&(self.pending_deltas as u32).to_be_bytes());
        let bytes = std::mem::take(&mut self.pending);
        let next = self.seq + 1;
        let written = watch_journal::append_cache(
            &self.stream,
            &self.folder.join("catalog.wal.bin"),
            next,
            bytes,
        )
        .map_err(io::Error::other)?;
        self.wal_bytes = self.wal_bytes.saturating_add(written);
        self.seq = next;
        self.pending_deltas = 0;
        Ok(())
    }
    pub fn checkpoint(&mut self, catalogs: &HashMap<String, ScopeCatalog>) -> io::Result<()> {
        if self.edits == 0 {
            return Ok(());
        }
        self.commit()?;
        watch_journal::flush_cache(&self.stream, self.seq).map_err(io::Error::other)?;
        #[derive(Serialize)]
        struct View<'a> {
            stamps: &'a HashMap<String, Stamp>,
            rows: CatalogRows<'a>,
        }
        let view = View {
            stamps: &self.stamps,
            rows: CatalogRows(catalogs),
        };
        let temp = self.folder.join("catalog.snapshot.bin.tmp");
        let mut file = File::create(&temp)?;
        let snapshot_bytes =
            wal::write_snapshot(&mut file, Kind::CatalogSnapshot, self.seq, &view)?;
        file.sync_all()?;
        drop(file);
        replace(&temp, &self.folder.join("catalog.snapshot.bin"))?;
        if let Some(mut handle) = self.handle.take() {
            watch_journal::close_cache(&mut handle).map_err(io::Error::other)?;
        }
        let wal = self.folder.join("catalog.wal.bin");
        if wal.exists() {
            fs::remove_file(wal)?;
        }
        self.handle = Some(
            watch_journal::open_cache(self.stream.clone(), self.seq).map_err(io::Error::other)?,
        );
        self.edits = 0;
        self.wal_bytes = 0;
        self.snapshot_bytes = snapshot_bytes;
        Ok(())
    }
    pub fn mark_rebuilt(&mut self) {
        self.edits += 1;
    }
    pub fn checkpoint_due(&self, idle: bool) -> bool {
        self.wal_bytes >= MAX_WAL_BYTES
            || (idle
                && self.edits >= 1024
                && self.wal_bytes >= self.snapshot_bytes.max(MIN_CHECKPOINT_BYTES))
    }
}

impl Drop for CatalogStore {
    fn drop(&mut self) {
        if let Some(mut handle) = self.handle.take() {
            // The writer must release its stream before another owner loads
            // and retires the WAL. Drop of a bare stream queues this asynchronously.
            let _ = watch_journal::close_cache(&mut handle);
        }
    }
}

// Stream the existing maps without a second O(N) collection of row pointers.
struct CatalogRows<'a>(&'a HashMap<String, ScopeCatalog>);
impl Serialize for CatalogRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map =
            serializer.serialize_map(Some(self.0.keys().filter(|key| !key.is_empty()).count()))?;
        for (scope, table) in self.0.iter().filter(|(key, _)| !key.is_empty()) {
            map.serialize_entry(scope, &ScopeRows(table))?;
        }
        map.end()
    }
}
struct ScopeRows<'a>(&'a ScopeCatalog);
impl Serialize for ScopeRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.persistent_len))?;
        for row in self.0.rows.values().filter(|row| row.persistent()) {
            rows.serialize_element(row)?;
        }
        rows.end()
    }
}
#[cfg(windows)]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
    }
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 1 | 8) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}
