//! Disposable filename cache. Reuses the Watch journal writer on a separate stream.
use super::directory::{DirectoryEntryRecord, ScopeCatalog};
use crate::watch_journal::{self, NativeJournalStream};
use crate::watch_state::JsonValue;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
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
    pub rows: Vec<&'a DirectoryEntryRecord>,
    pub stamp: Option<Stamp>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Operations {
    Single(Delta),
    Batch(Vec<Delta>),
}
#[derive(Deserialize)]
struct Transaction {
    seq: u64,
    operations: Operations,
}
const BATCH_BYTES: usize = 256 * 1024;
const BATCH_DELTAS: usize = 64;
const MIN_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Deserialize)]
struct Snapshot {
    format: u32,
    seq: u64,
    stamps: HashMap<String, Stamp>,
    rows: HashMap<String, Vec<DirectoryEntryRecord>>,
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
}
impl CatalogStore {
    pub fn open(folder: &Path, catalogs: &mut HashMap<String, ScopeCatalog>) -> io::Result<Self> {
        fs::create_dir_all(folder)?;
        let mut store = Self {
            folder: folder.to_owned(),
            stream: folder.join("catalog.wal").to_string_lossy().into_owned(),
            handle: None,
            seq: 0,
            edits: 0,
            wal_bytes: 0,
            snapshot_bytes: 0,
            pending: Vec::new(),
            pending_deltas: 0,
            stamps: HashMap::new(),
        };
        let load = (|| -> io::Result<()> {
            let snapshot = folder.join("catalog.snapshot");
            if snapshot.exists() {
                store.snapshot_bytes = fs::metadata(&snapshot)?.len();
                let snapshot: Snapshot =
                    serde_json::from_reader(BufReader::new(File::open(snapshot)?))?;
                if snapshot.format != 1 {
                    return Err(io::Error::other("unsupported catalog format"));
                }
                store.seq = snapshot.seq;
                store.stamps = snapshot.stamps;
                for (scope, rows) in snapshot.rows {
                    let catalog = catalogs.entry(scope).or_default();
                    for row in rows {
                        catalog.insert(row);
                    }
                }
            }
            let wal = folder.join("catalog.wal");
            if wal.exists() {
                store.wal_bytes = fs::metadata(&wal)?.len();
                for line in BufReader::new(File::open(wal)?).lines() {
                    let tx: Transaction = serde_json::from_str(&line?)?;
                    if tx.seq <= store.seq {
                        continue;
                    }
                    if tx.seq != store.seq + 1 {
                        return Err(io::Error::other("catalog WAL gap"));
                    }
                    let deltas = match tx.operations {
                        Operations::Single(delta) => vec![delta],
                        Operations::Batch(deltas) => deltas,
                    };
                    for delta in deltas {
                        store.edits += delta.rows.len() + delta.removed.len() + 1;
                        let catalog = catalogs.entry(delta.scope.clone()).or_default();
                        for key in delta.removed {
                            catalog.remove(&key);
                        }
                        for row in delta.rows {
                            catalog.insert(row);
                        }
                        if let Some(stamp) = delta.stamp {
                            store.stamps.insert(delta.scope, stamp);
                        }
                    }
                    store.seq = tx.seq;
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
            for name in ["catalog.snapshot", "catalog.wal"] {
                let path = folder.join(name);
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
        }
        store.handle = Some(
            watch_journal::open_cache(store.stream.clone(), store.seq).map_err(io::Error::other)?,
        );
        Ok(store)
    }
    pub fn append(&mut self, delta: DeltaView<'_>) -> io::Result<()> {
        if self.pending_deltas == 0 {
            self.pending.push(b'[');
        } else {
            self.pending.push(b',');
        }
        // Serialize borrowed rows directly; do not clone records or build a JSON tree.
        serde_json::to_writer(&mut self.pending, &delta)?;
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
        self.pending.push(b']');
        let bytes = std::mem::take(&mut self.pending);
        let next = self.seq + 1;
        let written = watch_journal::append_cache(
            &self.stream,
            &self.folder.join("catalog.wal"),
            next,
            JsonValue::Encoded(bytes),
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
            format: u32,
            seq: u64,
            stamps: &'a HashMap<String, Stamp>,
            rows: CatalogRows<'a>,
        }
        let view = View {
            format: 1,
            seq: self.seq,
            stamps: &self.stamps,
            rows: CatalogRows(catalogs),
        };
        let temp = self.folder.join("catalog.snapshot.tmp");
        let mut writer = BufWriter::with_capacity(1024 * 1024, File::create(&temp)?);
        serde_json::to_writer(&mut writer, &view)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        let snapshot_bytes = writer.get_ref().metadata()?.len();
        drop(writer);
        replace(&temp, &self.folder.join("catalog.snapshot"))?;
        if let Some(mut handle) = self.handle.take() {
            watch_journal::close_cache(&mut handle).map_err(io::Error::other)?;
        }
        let wal = self.folder.join("catalog.wal");
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

// Stream the existing maps without a second O(N) collection of row pointers.
struct CatalogRows<'a>(&'a HashMap<String, ScopeCatalog>);
impl Serialize for CatalogRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (scope, table) in self.0 {
            map.serialize_entry(scope, &ScopeRows(table))?;
        }
        map.end()
    }
}
struct ScopeRows<'a>(&'a ScopeCatalog);
impl Serialize for ScopeRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.rows.len()))?;
        for row in self.0.rows.values() {
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
