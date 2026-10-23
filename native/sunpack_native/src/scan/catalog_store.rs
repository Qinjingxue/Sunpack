//! Disposable filename cache. Reuses the Watch journal writer on a separate stream.
use super::directory::{DirectoryEntryRecord, ScopeCatalog};
use crate::watch_journal::{self, NativeJournalStream};
use crate::watch_state::JsonValue;
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
#[derive(Serialize, Deserialize)]
pub(super) struct Delta {
    pub scope: String,
    pub removed: Vec<String>,
    pub rows: Vec<DirectoryEntryRecord>,
    pub stamp: Option<Stamp>,
}
#[derive(Deserialize)]
struct Transaction {
    seq: u64,
    operations: Delta,
}
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
            stamps: HashMap::new(),
        };
        let load = (|| -> io::Result<()> {
            let snapshot = folder.join("catalog.snapshot");
            if snapshot.exists() {
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
                for line in BufReader::new(File::open(wal)?).lines() {
                    let tx: Transaction = serde_json::from_str(&line?)?;
                    if tx.seq <= store.seq {
                        continue;
                    }
                    if tx.seq != store.seq + 1 {
                        return Err(io::Error::other("catalog WAL gap"));
                    }
                    let delta = tx.operations;
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
                    store.seq = tx.seq;
                    store.edits += 1;
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
    pub fn append(&mut self, delta: Delta) -> io::Result<()> {
        let next = self.seq + 1;
        let value = to_journal(serde_json::to_value(&delta)?);
        watch_journal::append_cache(&self.stream, &self.folder.join("catalog.wal"), next, value)
            .map_err(io::Error::other)?;
        if let Some(stamp) = delta.stamp {
            self.stamps.insert(delta.scope, stamp);
        }
        self.seq = next;
        self.edits += delta.rows.len() + delta.removed.len() + 1;
        Ok(())
    }
    pub fn checkpoint(&mut self, catalogs: &HashMap<String, ScopeCatalog>) -> io::Result<()> {
        if self.edits == 0 {
            return Ok(());
        }
        watch_journal::flush_cache(&self.stream, self.seq).map_err(io::Error::other)?;
        #[derive(Serialize)]
        struct View<'a> {
            format: u32,
            seq: u64,
            stamps: &'a HashMap<String, Stamp>,
            rows: HashMap<&'a str, Vec<&'a DirectoryEntryRecord>>,
        }
        let view = View {
            format: 1,
            seq: self.seq,
            stamps: &self.stamps,
            rows: catalogs
                .iter()
                .map(|(key, table)| (key.as_str(), table.rows.values().collect()))
                .collect(),
        };
        let temp = self.folder.join("catalog.snapshot.tmp");
        let mut writer = BufWriter::with_capacity(1024 * 1024, File::create(&temp)?);
        serde_json::to_writer(&mut writer, &view)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
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
        Ok(())
    }
    pub fn mark_rebuilt(&mut self) {
        self.edits += 1;
    }
    pub fn checkpoint_due(&self) -> bool {
        self.edits >= 16384
    }
}
fn to_journal(value: serde_json::Value) -> JsonValue {
    use serde_json::Value;
    match value {
        Value::Null => JsonValue::Null,
        Value::Bool(v) => JsonValue::Bool(v),
        Value::String(v) => JsonValue::String(v),
        Value::Number(v) => {
            if let Some(v) = v.as_u64() {
                JsonValue::Unsigned(v.into())
            } else if let Some(v) = v.as_i64() {
                JsonValue::Signed(v.into())
            } else {
                JsonValue::Float(v.as_f64().unwrap())
            }
        }
        Value::Array(v) => JsonValue::Array(v.into_iter().map(to_journal).collect()),
        Value::Object(v) => {
            JsonValue::Object(v.into_iter().map(|(k, v)| (k, to_journal(v))).collect())
        }
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
