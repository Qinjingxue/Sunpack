//! Disposable display history: compressed records and a fixed-width disk index.
//! Runs are ordered by UTC; clock rollback starts another run. No WAL or replay.
use super::resource_lifecycle::{NativeResourceGuard, TrackedFile};
use serde::{Deserialize, Serialize};
use serde::ser::SerializeMap;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) const ENTRY_BYTES: usize = 64;
const RECORD_BLOCK_BYTES: usize = 1024 * 1024;
const REUSABLE_COMPRESS_BYTES: usize = 64 * 1024;
pub(crate) const DAY_US: i64 = 86_400_000_000;
unsafe extern "C" {
    fn LZ4_compressBound(size: i32) -> i32;
    fn LZ4_compress_default(src: *const u8, dst: *mut u8, size: i32, capacity: i32) -> i32;
}
pub(crate) fn utc_us() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(time) => time.as_micros().min(i64::MAX as u128) as i64,
        Err(error) => -(error.duration().as_micros().min(i64::MAX as u128) as i64),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Run {
    pub name: String,
    pub first: i64,
    pub last: i64,
    pub head: u64,
    pub count: u64,
    #[serde(default)]
    pub unordered: bool,
}
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub format: u32,
    #[serde(default)]
    pub task_revision: u64,
    pub runs: Vec<Run>,
    pub live: Option<Run>,
}
struct Live {
    data: TrackedFile,
    index: TrackedFile,
    rows: HashMap<Arc<str>, LiveRow>,
    time: BTreeMap<(i64, u64), Arc<str>>,
    free: Vec<u64>,
    bytes: u64,
    revision: u64,
}

struct LiveRow {
    slot: u64,
    stamp: i64,
    offset: u64,
    size: u64,
}

struct HistoryRun {
    data: TrackedFile,
    index: TrackedFile,
    end: u64,
}

impl HistoryRun {
    fn open(folder: &Path, run: &Run) -> io::Result<Self> {
        let (data, index) = files(folder, &run.name);
        let mut data = open_sparse(&data)?;
        let index = open_sparse(&index)?;
        let end = data.seek(SeekFrom::End(0))?;
        Ok(Self { data, index, end })
    }
}

impl Live {
    fn set_revision(&mut self, revision: u64) -> io::Result<()> {
        if self.revision != revision {
            self.index.seek(SeekFrom::Start(0))?;
            self.index.write_all(&revision.to_le_bytes())?;
            self.revision = revision;
        }
        Ok(())
    }
    fn remove(&mut self, id: &str) -> io::Result<bool> {
        if let Some(row) = self.rows.remove(id) {
            self.set_revision(0)?;
            let slot = row.slot;
            zero(
                &mut self.index,
                slot * ENTRY_BYTES as u64,
                (slot + 1) * ENTRY_BYTES as u64,
            )?;
            self.release_data(row)?;
            self.free.push(slot);
            return Ok(true);
        }
        Ok(false)
    }

    fn release_data(&mut self, row: LiveRow) -> io::Result<()> {
        zero(&mut self.data, row.offset, row.offset + row.size)?;
        self.bytes -= row.size;
        self.time.remove(&(row.stamp, row.slot));
        Ok(())
    }
}
pub(crate) struct Store {
    path: PathBuf,
    folder: PathBuf,
    pub manifest: Manifest,
    oldest_history: Option<i64>,
    current: Option<HistoryRun>,
    compressed: Vec<u8>,
    obsolete: Vec<String>,
    live: Option<Live>,
    pub(crate) expired_live: Vec<Arc<str>>,
}
fn files(folder: &Path, name: &str) -> (PathBuf, PathBuf) {
    (
        folder.join(format!("{name}.data")),
        folder.join(format!("{name}.index")),
    )
}
fn open_sparse(path: &Path) -> io::Result<TrackedFile> {
    let file = TrackedFile::open_with(path, |o| {
        o.read(true).write(true).create(true);
    })?;
    sparse(&file)?;
    Ok(file)
}
#[cfg(windows)]
fn control(
    file: &TrackedFile,
    code: u32,
    input: *const std::ffi::c_void,
    size: u32,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            h: *mut std::ffi::c_void,
            code: u32,
            input: *const std::ffi::c_void,
            size: u32,
            out: *mut std::ffi::c_void,
            out_size: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut returned = 0;
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input,
            size,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(windows)]
fn sparse(file: &TrackedFile) -> io::Result<()> {
    control(file, 0x900c4, std::ptr::null(), 0)
}
#[cfg(not(windows))]
fn sparse(_: &TrackedFile) -> io::Result<()> {
    Ok(())
}
fn zero(file: &mut TrackedFile, start: u64, end: u64) -> io::Result<()> {
    if start >= end {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let range = [start as i64, end as i64];
        control(file, 0x980c8, range.as_ptr().cast(), 16)
    }
    #[cfg(not(windows))]
    {
        file.seek(SeekFrom::Start(start))?;
        let zeros = [0u8; 65536];
        let mut remaining = end - start;
        while remaining > 0 {
            let n = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }
}
fn compress_block<'a>(raw: &[u8], compressed: &'a mut Vec<u8>) -> io::Result<&'a [u8]> {
    let bound = unsafe { LZ4_compressBound(raw.len() as i32) };
    if bound <= 0 {
        return Err(invalid("display block cannot be compressed"));
    }
    compressed.clear();
    compressed.try_reserve(bound as usize).map_err(|error|
        io::Error::new(io::ErrorKind::OutOfMemory, error))?;
    let len = unsafe {
        LZ4_compress_default(
            raw.as_ptr(),
            compressed.as_mut_ptr(),
            raw.len() as i32,
            bound,
        )
    };
    if len <= 0 {
        return Err(invalid("display compression failed"));
    }
    // LZ4 initializes the prefix it reports on success.
    unsafe { compressed.set_len(len as usize) };
    Ok(compressed)
}
fn record_size(data: &mut TrackedFile, entry: &[u8]) -> io::Result<u64> {
    let size = u32::from_le_bytes(entry[16..20].try_into().unwrap());
    if size != 0 {
        return Ok(size as u64);
    }
    data.seek(SeekFrom::Start(offset(entry)))?;
    let mut header = [0; 24];
    data.read_exact(&mut header)?;
    let size = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if &header[..4] != b"SPDC"
        || size < 24
        || offset(entry)
            .checked_add(size)
            .is_none_or(|end| end > data.metadata().map(|meta| meta.len()).unwrap_or(0))
    {
        return Err(invalid("invalid chunked display record"));
    }
    Ok(size)
}
fn entry(file: &mut TrackedFile, index: u64) -> io::Result<[u8; ENTRY_BYTES]> {
    file.seek(SeekFrom::Start(index * ENTRY_BYTES as u64))?;
    let mut bytes = [0; ENTRY_BYTES];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn stamp(bytes: &[u8]) -> i64 {
    i64::from_le_bytes(bytes[..8].try_into().unwrap())
}
fn offset(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[8..16].try_into().unwrap())
}
fn mix(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846ca68b);
    value ^ (value >> 16)
}
fn add_path(bits: &mut [u64; 4], path: &str) {
    const SLASH: u16 = b'/' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let mut add = |token| {
        let hash = mix(token);
        for bit in [hash & 255, (hash >> 8) & 255] {
            bits[(bit / 64) as usize] |= 1 << (bit % 64);
        }
    };
    let normalized = |unit| if unit == SLASH { BACKSLASH } else { unit };
    let mut previous = None;
    for unit in path.encode_utf16() {
        let ch = if (0xd800..=0xdfff).contains(&unit) {
            unit
        } else {
            crate::path_keys::case_key_unit(unit)
        };
        add(u32::from(ch));
        if ch == SLASH {
            add(u32::from(BACKSLASH));
        }
        if let Some(prev) = previous {
            add(0x8000_0000 ^ (u32::from(prev) << 16) ^ u32::from(ch));
            // Only tokens touching a slash differ in the normalized spelling.
            if prev == SLASH || ch == SLASH {
                add(0x8000_0000 ^ (u32::from(normalized(prev)) << 16) ^ u32::from(normalized(ch)));
            }
        }
        previous = Some(ch);
    }
}
fn filter(value: &Value, group: Option<&Value>) -> [u64; 4] {
    let mut bits = [0; 4];
    let event_path = value["path"].as_str();
    if let Some(s) = event_path {
        add_path(&mut bits, s);
    }
    let layout = group.or_else(|| value.get("group")).unwrap_or(value);
    let group_path = layout["path"].as_str();
    if let Some(s) = group_path.filter(|s| Some(*s) != event_path) {
        add_path(&mut bits, s);
    }
    if let Some(members) = layout["members"].as_array() {
        for member in members.iter().filter_map(Value::as_str) {
            if Some(member) != event_path && Some(member) != group_path {
                add_path(&mut bits, member);
            }
        }
    }
    bits
}

fn kind(value: &Value) -> u32 {
    match value["event"].as_str().unwrap_or("") {
        "processing_started" => 1,
        "failed_password" => 2,
        "suspended_missing_volume" => 3,
        "done" | "watch_deduplicated" => 4,
        "failed_terminal" | "partial_rejected" => 5,
        _ => 0,
    }
}

struct RecordIndex {
    ts: i64,
    kind: u32,
    filter: [u64; 4],
}

impl RecordIndex {
    fn new(value: &Value, ts: i64, group: Option<&Value>) -> Self {
        let kind = kind(value);
        // The GUI discards non-task records before looking at the search bits.
        let filter = if kind == 0 { [0; 4] } else { filter(value, group) };
        Self { ts, kind, filter }
    }
}

pub(crate) struct EventField<'a, T> {
    pub fields: &'a serde_json::Map<String, Value>,
    pub name: &'static str,
    pub value: T,
}

impl<T: Serialize> Serialize for EventField<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self.fields.len() + usize::from(!self.fields.contains_key(self.name));
        let mut event = serializer.serialize_map(Some(count))?;
        for (key, value) in self.fields {
            if key != self.name {
                event.serialize_entry(key, value)?;
            }
        }
        event.serialize_entry(self.name, &self.value)?;
        event.end()
    }
}

pub(crate) struct LiveEvent {
    pub ts: i64,
    pub value: Value,
    pub group: Option<Arc<Value>>,
}

pub(crate) struct HistoryRecord {
    index: RecordIndex,
    raw: super::scratch::Blob,
}

impl HistoryRecord {
    pub(crate) fn new(value: &Value, ts: i64, payload: &impl Serialize) -> io::Result<Self> {
        Self::encode(RecordIndex::new(value, ts, None), payload)
    }

    pub(crate) fn diagnostic(ts: i64, payload: &impl Serialize) -> io::Result<Self> {
        Self::encode(RecordIndex { ts, kind: 0, filter: [0; 4] }, payload)
    }

    fn encode(index: RecordIndex, payload: &impl Serialize) -> io::Result<Self> {
        let mut raw = super::scratch::Spool::default();
        rmp_serde::encode::write_named(&mut raw, payload).map_err(io::Error::other)?;
        Ok(Self { index, raw: raw.finish()? })
    }

    pub(crate) fn timestamp(&self) -> i64 { self.index.ts }

    pub(crate) fn memory_bytes(&self) -> usize {
        let bytes = match &self.raw {
            super::scratch::Blob::Memory(raw) => raw.capacity(),
            // A mapped record occupies one batch no matter its length.
            super::scratch::Blob::Mapped(_) => super::scratch::MEMORY_BYTES,
        };
        std::mem::size_of::<Self>() + bytes
    }
}

impl Store {
    pub(crate) fn rebuild(path: PathBuf) -> io::Result<Self> {
        let folder = path.with_file_name(format!(
            "{}.store",
            path.file_name().unwrap().to_string_lossy()
        ));
        if let Err(error) = fs::remove_file(&path) {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        if let Err(error) = fs::remove_dir_all(&folder) {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        Self::open(path)
    }
    pub(crate) fn open(path: PathBuf) -> io::Result<Self> {
        let folder = path.with_file_name(format!(
            "{}.store",
            path.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir_all(&folder)?;
        let manifest = match TrackedFile::open_reader(&path) {
            Ok(file) => serde_json::from_reader(std::io::BufReader::new(file))
                .map_err(|e| invalid(&e.to_string()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Manifest {
                format: 1,
                ..Manifest::default()
            },
            Err(e) => return Err(e),
        };
        let mut store = Self {
            path,
            folder,
            oldest_history: manifest.runs.iter().map(|run| run.first).min(),
            manifest,
            current: None,
            compressed: Vec::new(),
            obsolete: Vec::new(),
            live: None,
            expired_live: Vec::new(),
        };
        if store.manifest.format != 1 {
            return Err(invalid("unsupported display history"));
        }
        // Unpublished files are disposable, not transactions to replay.
        let published: HashSet<_> = store
            .manifest
            .runs
            .iter()
            .chain(store.manifest.live.iter())
            .map(|r| r.name.as_str())
            .collect();
        for item in fs::read_dir(&store.folder)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let stem = name.rsplit_once('.').map(|p| p.0).unwrap_or("");
            if !published.contains(stem) {
                fs::remove_file(item.path())?;
            }
        }
        if let Some(run) = store.manifest.runs.last() {
            let mut current = HistoryRun::open(&store.folder, run)?;
            if run.count > 0 {
                let last = entry(&mut current.index, run.count - 1)?;
                let length = record_size(&mut current.data, &last)?;
                current.end = offset(&last).saturating_add(length);
                current.data.set_len(current.end)?;
                current.data.seek(SeekFrom::Start(current.end))?;
            }
            current.index.set_len(run.count * ENTRY_BYTES as u64)?;
            store.current = Some(current);
        }
        Ok(store)
    }
    fn create_run(&self, prefix: &str) -> Run {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_RUN: AtomicU64 = AtomicU64::new(0);
        let nonce = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(time) => time.as_nanos(),
            Err(error) => error.duration().as_nanos() | (1u128 << 127),
        };
        let serial = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        Run {
            name: format!("{prefix}-{nonce:032x}-{:x}-{serial:x}", std::process::id()),
            ..Run::default()
        }
    }

    fn write_record(
        compressed: &mut Vec<u8>,
        data: &mut TrackedFile,
        index: &mut TrackedFile,
        position: u64,
        slot: u64,
        raw: &[u8],
        record: &RecordIndex,
    ) -> io::Result<LiveRow> {
        let (packed_length, raw_length, size) = if raw.len() <= super::scratch::MEMORY_BYTES {
            let packed = compress_block(raw, compressed)?;
            data.write_all(packed)?;
            (packed.len() as u32, raw.len() as u32, packed.len() as u64)
        } else {
            // Zero sizes in the fixed index select a u64 envelope of bounded
            // LZ4 blocks. Publish the index only after the complete record.
            let mut header = [0u8; 24];
            header[..4].copy_from_slice(b"SPDC");
            header[16..24].copy_from_slice(&(raw.len() as u64).to_le_bytes());
            data.write_all(&header)?;
            let mut size = header.len() as u64;
            for block in raw.chunks(RECORD_BLOCK_BYTES) {
                let packed = compress_block(block, compressed)?;
                data.write_all(&(packed.len() as u32).to_le_bytes())?;
                data.write_all(&(block.len() as u32).to_le_bytes())?;
                data.write_all(packed)?;
                size += 8 + packed.len() as u64;
            }
            header[8..16].copy_from_slice(&size.to_le_bytes());
            data.seek(SeekFrom::Start(position))?;
            data.write_all(&header)?;
            data.seek(SeekFrom::Start(position + size))?;
            (0, 0, size)
        };
        let mut bytes = [0; ENTRY_BYTES];
        bytes[..8].copy_from_slice(&record.ts.to_le_bytes());
        bytes[8..16].copy_from_slice(&position.to_le_bytes());
        bytes[16..20].copy_from_slice(&packed_length.to_le_bytes());
        bytes[20..24].copy_from_slice(&raw_length.to_le_bytes());
        bytes[24..28].copy_from_slice(&record.kind.to_le_bytes());
        bytes[28..32].copy_from_slice(&(slot as u32).to_le_bytes());
        for (i, bits) in record.filter.iter().enumerate() {
            bytes[32 + i * 8..40 + i * 8].copy_from_slice(&bits.to_le_bytes());
        }
        index.seek(SeekFrom::Start(slot * ENTRY_BYTES as u64))?;
        index.write_all(&bytes)?;
        Ok(LiveRow {
            slot,
            stamp: record.ts,
            offset: position,
            size,
        })
    }
    pub(crate) fn append(&mut self, record: &HistoryRecord) -> io::Result<()> {
        let ts = record.timestamp();
        if record.index.kind != 0 {
            self.manifest.task_revision += 1;
        }
        let new = self
            .manifest
            .runs
            .last()
            .is_none_or(|r| ts < r.last || ts.div_euclid(DAY_US) != r.last.div_euclid(DAY_US));
        if new {
            let run = self.create_run("history");
            self.current = Some(HistoryRun::open(&self.folder, &run)?);
            self.manifest.runs.push(run);
        }
        let current = self.current.as_mut().unwrap();
        let run = self.manifest.runs.last_mut().unwrap();
        let row = Self::write_record(
            &mut self.compressed,
            &mut current.data,
            &mut current.index,
            current.end,
            run.count,
            &record.raw,
            &record.index,
        )?;
        current.end += row.size;
        if run.count == 0 {
            run.first = ts;
            self.oldest_history = Some(self.oldest_history.map_or(ts, |first| first.min(ts)));
        }
        run.last = ts;
        run.count += 1;
        Ok(())
    }
    fn new_live(&self) -> io::Result<(Run, Live)> {
        let mut run = self.create_run("live");
        run.unordered = true;
        // The first index entry is a commit marker, outside the row range.
        // Zero rejects readers while slots/data are changing; publish installs
        // the manifest's task revision before making that manifest visible.
        run.head = 1;
        run.count = 1;
        let (data, index) = files(&self.folder, &run.name);
        let mut index = open_sparse(&index)?;
        index.write_all(&[0; ENTRY_BYTES])?;
        Ok((
            run,
            Live {
                data: open_sparse(&data)?,
                index,
                rows: HashMap::new(),
                time: BTreeMap::new(),
                free: Vec::new(),
                bytes: 0,
                revision: 0,
            },
        ))
    }
    pub(crate) fn update_live(
        &mut self,
        rows: impl Iterator<Item = io::Result<(Arc<str>, Option<LiveEvent>)>>,
        reset: bool,
        cutoff: i64,
    ) -> io::Result<()> {
        let mut changed = false;
        if reset {
            self.live = None;
            if let Some(old) = self.manifest.live.take() {
                self.obsolete.push(old.name);
                changed = true;
            }
        }
        for row in rows {
            let (id, value) = row?;
            let expired = value.as_ref().is_some_and(|event| event.ts <= cutoff);
            let Some(LiveEvent { ts, value, group }) = value.filter(|_| !expired) else {
                if let Some(live) = &mut self.live {
                    changed |= live.remove(&id)?;
                }
                if expired {
                    self.expired_live.push(id);
                }
                continue;
            };
            if self.live.is_none() {
                let (run, live) = self.new_live()?;
                if let Some(old) = self.manifest.live.replace(run) {
                    self.obsolete.push(old.name);
                }
                self.live = Some(live);
            }
            let live = self.live.as_mut().unwrap();
            let run = self.manifest.live.as_mut().unwrap();
            live.set_revision(0)?;
            let slot = if let Some(row) = live.rows.remove(id.as_ref()) {
                // Readers already reject this revision. Overwrite the index slot
                // directly and reclaim only the old record's data.
                let slot = row.slot;
                live.release_data(row)?;
                slot
            } else {
                live.free.pop().unwrap_or(run.count)
            };
            let mut raw = super::scratch::Spool::default();
            let group = group.as_deref();
            match group {
                Some(group) => rmp_serde::encode::write(&mut raw, &EventField {
                    fields: value.as_object().ok_or_else(|| invalid("live event must be an object"))?,
                    name: "group",
                    value: group,
                }),
                None => rmp_serde::encode::write(&mut raw, &value),
            }
            .map_err(io::Error::other)?;
            let position = live.data.seek(SeekFrom::End(0))?;
            let row = Self::write_record(
                &mut self.compressed,
                &mut live.data,
                &mut live.index,
                position,
                slot,
                &raw.finish()?,
                &RecordIndex::new(&value, ts, group),
            )?;
            run.count = run.count.max(slot + 1);
            live.bytes += row.size;
            live.time.insert((ts, slot), Arc::clone(&id));
            live.rows.insert(id, row);
            changed = true;
        }
        if changed {
            self.manifest.task_revision += 1;
            self.finish_live()?;
        }
        Ok(())
    }
    fn finish_live(&mut self) -> io::Result<()> {
        let Some(live) = &mut self.live else {
            return Ok(());
        };
        let Some((&(first, _), _)) = live.time.first_key_value() else {
            self.live = None;
            self.obsolete.push(self.manifest.live.take().unwrap().name);
            return Ok(());
        };
        let run = self.manifest.live.as_mut().unwrap();
        run.first = first;
        let (&(last, _), _) = live.time.last_key_value().unwrap();
        run.last = last;
        if live.data.metadata()?.len() > (4 * 1024 * 1024).max(live.bytes.saturating_mul(2))
            || run.count > 256.max(live.rows.len() as u64 * 4)
        {
            self.repack_live()?;
        }
        Ok(())
    }
    fn repack_live(&mut self) -> io::Result<()> {
        let (mut run, mut new) = self.new_live()?;
        let old = self.live.as_mut().unwrap();
        let mut buffer = [0u8; 65536];
        for ((ts, _), id) in &old.time {
            let row = &old.rows[id];
            let mut bytes = entry(&mut old.index, row.slot)?;
            let position = new.bytes;
            old.data.seek(SeekFrom::Start(row.offset))?;
            let mut remaining = row.size;
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                old.data.read_exact(&mut buffer[..count])?;
                new.data.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            bytes[8..16].copy_from_slice(&position.to_le_bytes());
            bytes[28..32].copy_from_slice(&(run.count as u32).to_le_bytes());
            new.index.write_all(&bytes)?;
            new.time.insert((*ts, run.count), id.clone());
            new.rows.insert(id.clone(), LiveRow {
                slot: run.count,
                stamp: *ts,
                offset: position,
                size: row.size,
            });
            run.count += 1;
            new.bytes += row.size;
        }
        let current = self.manifest.live.as_mut().unwrap();
        run.first = current.first;
        run.last = current.last;
        self.obsolete.push(std::mem::replace(current, run).name);
        self.live = Some(new);
        Ok(())
    }
    pub(crate) fn expire(&mut self, cutoff: i64) -> io::Result<Option<i64>> {
        if self.oldest_history.is_some_and(|first| first <= cutoff) {
            self.expire_history(cutoff)?;
            self.oldest_history = self.manifest.runs.iter().map(|run| run.first).min();
        }
        let mut expired = false;
        if let Some(live) = &mut self.live {
            while let Some(((ts, _), id)) = live.time.first_key_value() {
                if *ts > cutoff {
                    break;
                }
                let id = id.clone();
                let removed = live.remove(id.as_ref())?;
                debug_assert!(removed);
                self.expired_live.push(id);
                expired = true;
            }
        }
        if expired {
            self.manifest.task_revision += 1;
            self.finish_live()?;
        }
        let oldest_live = self.live.as_ref().and(self.manifest.live.as_ref()).map(|run| run.first);
        Ok(self.oldest_history.into_iter().chain(oldest_live).min())
    }
    fn expire_history(&mut self, cutoff: i64) -> io::Result<()> {
        let runs = &mut self.manifest.runs;
        for run in runs
            .iter_mut()
            .filter(|run| run.first <= cutoff && run.last > cutoff)
        {
            let (data_path, index_path) = files(&self.folder, &run.name);
            let mut index = open_sparse(&index_path)?;
            let mut lo = run.head;
            let mut hi = run.count;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if stamp(&entry(&mut index, mid)?) <= cutoff {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let first = entry(&mut index, lo)?;
            let mut data = open_sparse(&data_path)?;
            let start = offset(&entry(&mut index, run.head)?);
            zero(
                &mut index,
                run.head * ENTRY_BYTES as u64,
                lo * ENTRY_BYTES as u64,
            )?;
            zero(&mut data, start, offset(&first))?;
            run.head = lo;
            run.first = stamp(&first);
        }
        if runs.last().is_some_and(|run| run.last <= cutoff) {
            self.current = None;
        }
        self.obsolete.extend(
            runs.extract_if(.., |run| run.last <= cutoff)
                .map(|run| run.name),
        );
        if runs.capacity() > 256.max(runs.len().saturating_mul(4)) {
            runs.shrink_to(runs.len().saturating_mul(2));
        }
        if self.current.is_none() {
            if let Some(run) = runs.last() {
                self.current = Some(HistoryRun::open(&self.folder, run)?);
            }
        }
        self.manifest.task_revision += 1;
        Ok(())
    }
    pub(crate) fn publish(&mut self) -> io::Result<()> {
        // Keep normal event scratch, but retire capacity from large groups
        // once the writer finishes the batch that needed it.
        if self.compressed.capacity() > REUSABLE_COMPRESS_BYTES {
            self.compressed = Vec::new();
        }
        if let Some(live) = &mut self.live {
            live.set_revision(self.manifest.task_revision)?;
        }
        let temp = self.path.with_file_name(format!(
            "{}.tmp",
            self.path.file_name().unwrap().to_string_lossy()
        ));
        let _publication =
            NativeResourceGuard::register([self.path.clone(), temp.clone()])?;
        let mut file = BufWriter::new(TrackedFile::open_with(&temp, |o| {
            o.write(true).create(true).truncate(true);
        })?);
        serde_json::to_writer(&mut file, &self.manifest).map_err(|e| invalid(&e.to_string()))?;
        file.flush()?;
        drop(file);
        if let Err(error) = super::atomic_file::replace_once(&temp, &self.path) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        let mut cleanup_error = None;
        // The manifest is committed. A reader can still hold an obsolete run;
        // keep its name for the next publication and retire other runs now.
        self.obsolete.retain(|name| {
            let (data, index) = files(&self.folder, name);
            let mut pending = false;
            for path in [data, index] {
                if let Err(error) = fs::remove_file(path) {
                    if error.kind() != io::ErrorKind::NotFound {
                        cleanup_error.get_or_insert(error);
                        pending = true;
                    }
                }
            }
            pending
        });
        if self.obsolete.capacity() > 256.max(self.obsolete.len().saturating_mul(4)) {
            self.obsolete.shrink_to(self.obsolete.len().saturating_mul(2));
        }
        cleanup_error.map_or(Ok(()), Err)
    }
}
