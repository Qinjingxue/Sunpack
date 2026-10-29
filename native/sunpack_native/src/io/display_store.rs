//! Disposable display history: compressed records and a fixed-width disk index.
//! Runs are ordered by UTC; clock rollback starts another run. No WAL or replay.
use super::resource_lifecycle::{NativeResourceGuard, TrackedFile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const ENTRY_BYTES: usize = 64;
const RECORD_BLOCK_BYTES: usize = 1024 * 1024;
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

#[derive(Clone, Default, Serialize, Deserialize)]
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
    pub revision: u64,
    #[serde(default)]
    pub task_revision: u64,
    pub runs: Vec<Run>,
    pub live: Option<Run>,
    pub dropped: u64,
}
struct Live {
    run: Run,
    data: TrackedFile,
    index: TrackedFile,
    rows: HashMap<String, (u64, [u8; ENTRY_BYTES])>,
    time: BTreeMap<(i64, u64), String>,
    free: Vec<u64>,
    bytes: u64,
    revision: u64,
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
    fn remove(&mut self, id: &str) -> io::Result<()> {
        if let Some((slot, bytes)) = self.rows.remove(id) {
            self.time.remove(&(stamp(&bytes), slot));
            let size = record_size(&mut self.data, &bytes)?;
            zero(
                &mut self.index,
                slot * ENTRY_BYTES as u64,
                (slot + 1) * ENTRY_BYTES as u64,
            )?;
            zero(&mut self.data, offset(&bytes), offset(&bytes) + size)?;
            self.bytes -= size;
            self.free.push(slot);
        }
        Ok(())
    }
}
pub(crate) struct Store {
    path: PathBuf,
    folder: PathBuf,
    pub manifest: Manifest,
    current: Option<(String, TrackedFile, TrackedFile)>,
    compressed: Vec<u8>,
    obsolete: Vec<String>,
    live: Option<Live>,
    pub(crate) expired_live: Vec<String>,
}
fn files(folder: &Path, name: &str) -> (PathBuf, PathBuf) {
    (
        folder.join(format!("{name}.data")),
        folder.join(format!("{name}.index")),
    )
}
fn open_sparse(path: &Path) -> io::Result<TrackedFile> {
    let file = TrackedFile::open_with(path, "display_log", |o| {
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
fn compress_block(raw: &[u8], compressed: &mut Vec<u8>) -> io::Result<usize> {
    let bound = unsafe { LZ4_compressBound(raw.len() as i32) };
    if bound <= 0 {
        return Err(invalid("display block cannot be compressed"));
    }
    compressed.resize(bound as usize, 0);
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
    Ok(len as usize)
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
fn add_text(bits: &mut [u64; 4], text: &str) {
    let text = crate::path_keys::case_key(text);
    let mut previous = None;
    for ch in text.encode_utf16() {
        for token in [
            Some(ch as u32),
            previous.map(|p: u16| 0x80000000u32 ^ ((p as u32) << 16) ^ ch as u32),
        ]
        .into_iter()
        .flatten()
        {
            let hash = mix(token);
            for bit in [hash & 255, (hash >> 8) & 255] {
                bits[(bit / 64) as usize] |= 1 << (bit % 64);
            }
        }
        previous = Some(ch);
    }
}
fn filter(value: &Value) -> [u64; 4] {
    let mut bits = [0; 4];
    let mut path = |s: &str| {
        add_text(&mut bits, s);
        if s.contains('/') {
            add_text(&mut bits, &s.replace('/', "\\"));
        }
    };
    if let Some(s) = value["path"].as_str() {
        path(s);
    }
    if let Some(group) = value.get("group") {
        if let Some(s) = group["path"].as_str() {
            path(s);
        }
        if let Some(members) = group["members"].as_array() {
            for member in members {
                if let Some(s) = member.as_str() {
                    path(s);
                }
            }
        }
        if let Some(s) = group["name"].as_str() {
            add_text(&mut bits, s);
        }
    }
    bits
}

fn kind(value: &Value) -> u32 {
    match value["event"].as_str().unwrap_or("") {
        "processing_started" => 1,
        "failed_password" => 2,
        "suspended_missing_volume" => 3,
        "done" => 4,
        "failed_terminal" | "partial_rejected" => 5,
        _ => 0,
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
        let manifest = match TrackedFile::open_reader(&path, "display_manifest") {
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
        for item in fs::read_dir(&store.folder)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let stem = name.rsplit_once('.').map(|p| p.0).unwrap_or("");
            if !store
                .manifest
                .runs
                .iter()
                .chain(store.manifest.live.iter())
                .any(|r| r.name == stem)
            {
                fs::remove_file(item.path())?;
            }
        }
        if let Some(run) = store.manifest.runs.last() {
            let (data, index) = files(&store.folder, &run.name);
            let mut data = open_sparse(&data)?;
            let mut index = open_sparse(&index)?;
            if run.count > 0 {
                let last = entry(&mut index, run.count - 1)?;
                let length = record_size(&mut data, &last)?;
                data.set_len(offset(&last).saturating_add(length))?;
            }
            index.set_len(run.count * ENTRY_BYTES as u64)?;
            store.current = Some((run.name.clone(), data, index));
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
        run: &mut Run,
        value: &Value,
        ts: i64,
    ) -> io::Result<[u8; ENTRY_BYTES]> {
        let mut raw = super::scratch::Spool::default();
        rmp_serde::encode::write(&mut raw, value).map_err(|e| invalid(&e.to_string()))?;
        let raw = raw.finish()?;
        let position = data.seek(SeekFrom::End(0))?;
        let (packed_length, raw_length) = if raw.len() <= super::scratch::MEMORY_BYTES {
            let len = compress_block(&raw, compressed)?;
            data.write_all(&compressed[..len])?;
            (len as u32, raw.len() as u32)
        } else {
            // Zero sizes in the fixed index select a u64 envelope of bounded
            // LZ4 blocks. Publish the index only after the complete record.
            let mut header = [0u8; 24];
            header[..4].copy_from_slice(b"SPDC");
            header[16..24].copy_from_slice(&(raw.len() as u64).to_le_bytes());
            data.write_all(&header)?;
            for block in raw.chunks(RECORD_BLOCK_BYTES) {
                let len = compress_block(block, compressed)?;
                data.write_all(&(len as u32).to_le_bytes())?;
                data.write_all(&(block.len() as u32).to_le_bytes())?;
                data.write_all(&compressed[..len])?;
            }
            let end = data.stream_position()?;
            header[8..16].copy_from_slice(&(end - position).to_le_bytes());
            data.seek(SeekFrom::Start(position))?;
            data.write_all(&header)?;
            data.seek(SeekFrom::Start(end))?;
            (0, 0)
        };
        let mut bytes = [0; ENTRY_BYTES];
        bytes[..8].copy_from_slice(&ts.to_le_bytes());
        bytes[8..16].copy_from_slice(&position.to_le_bytes());
        bytes[16..20].copy_from_slice(&packed_length.to_le_bytes());
        bytes[20..24].copy_from_slice(&raw_length.to_le_bytes());
        bytes[24..28].copy_from_slice(&kind(value).to_le_bytes());
        bytes[28..32].copy_from_slice(&(run.count as u32).to_le_bytes());
        for (i, bits) in filter(value).iter().enumerate() {
            bytes[32 + i * 8..40 + i * 8].copy_from_slice(&bits.to_le_bytes());
        }
        index.seek(SeekFrom::Start(run.count * ENTRY_BYTES as u64))?;
        index.write_all(&bytes)?;
        if run.count == 0 {
            run.first = ts;
        }
        run.last = ts;
        run.count += 1;
        Ok(bytes)
    }
    pub(crate) fn append(&mut self, value: &Value, ts: i64) -> io::Result<()> {
        if kind(value) != 0 {
            self.manifest.task_revision += 1;
        }
        let new = self
            .manifest
            .runs
            .last()
            .is_none_or(|r| ts < r.last || ts.div_euclid(DAY_US) != r.last.div_euclid(DAY_US));
        if new {
            let run = self.create_run("history");
            let (data, index) = files(&self.folder, &run.name);
            self.current = Some((run.name.clone(), open_sparse(&data)?, open_sparse(&index)?));
            self.manifest.runs.push(run);
        }
        let (_, data, index) = self.current.as_mut().unwrap();
        Self::write_record(
            &mut self.compressed,
            data,
            index,
            self.manifest.runs.last_mut().unwrap(),
            value,
            ts,
        )
        .map(|_| ())
    }
    fn new_live(&self) -> io::Result<Live> {
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
        Ok(Live {
            run,
            data: open_sparse(&data)?,
            index,
            rows: HashMap::new(),
            time: BTreeMap::new(),
            free: Vec::new(),
            bytes: 0,
            revision: 0,
        })
    }
    pub(crate) fn update_live(
        &mut self,
        rows: Vec<(String, Option<(i64, Value)>)>,
        reset: bool,
        cutoff: i64,
    ) -> io::Result<()> {
        if rows.is_empty() && !reset {
            return Ok(());
        }
        if reset {
            self.live = None;
            if let Some(old) = self.manifest.live.take() {
                self.obsolete.push(old.name);
            }
        }
        if let Some(live) = &mut self.live {
            live.set_revision(0)?;
        }
        for (id, value) in rows {
            if value.as_ref().is_some_and(|(ts, _)| *ts <= cutoff) {
                self.expired_live.push(id.clone());
            }
            if let Some(live) = &mut self.live {
                live.remove(&id)?;
            }
            if let Some((ts, value)) = value.filter(|(ts, _)| *ts > cutoff) {
                if self.live.is_none() {
                    self.live = Some(self.new_live()?);
                }
                let live = self.live.as_mut().unwrap();
                let slot = live.free.pop().unwrap_or(live.run.count);
                let count = live.run.count.max(slot + 1);
                live.run.count = slot;
                let bytes = Self::write_record(
                    &mut self.compressed,
                    &mut live.data,
                    &mut live.index,
                    &mut live.run,
                    &value,
                    ts,
                )?;
                live.run.count = count;
                live.bytes += record_size(&mut live.data, &bytes)?;
                live.time.insert((ts, slot), id.clone());
                live.rows.insert(id, (slot, bytes));
            }
        }
        self.manifest.task_revision += 1;
        self.finish_live()
    }
    fn finish_live(&mut self) -> io::Result<()> {
        if self.live.as_ref().is_some_and(|live| live.rows.is_empty()) {
            let live = self.live.take().unwrap();
            self.obsolete.push(live.run.name);
            self.manifest.live = None;
        }
        if let Some(live) = &mut self.live {
            let ((first, _), _) = live.time.first_key_value().unwrap();
            live.run.first = *first;
            let ((last, _), _) = live.time.last_key_value().unwrap();
            live.run.last = *last;
            let repack = live.data.metadata()?.len()
                > (4 * 1024 * 1024).max(live.bytes.saturating_mul(2))
                || live.run.count > 256.max(live.rows.len() as u64 * 4);
            if repack {
                self.repack_live()?;
            }
            self.manifest.live = self.live.as_ref().map(|live| live.run.clone());
        }
        Ok(())
    }
    fn repack_live(&mut self) -> io::Result<()> {
        let mut new = self.new_live()?;
        let old = self.live.as_mut().unwrap();
        let mut buffer = [0u8; 65536];
        for ((ts, _), id) in &old.time {
            let (_, bytes) = old.rows[id];
            let mut bytes = bytes;
            let size = record_size(&mut old.data, &bytes)?;
            let position = new.data.stream_position()?;
            old.data.seek(SeekFrom::Start(offset(&bytes)))?;
            let mut remaining = size;
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                old.data.read_exact(&mut buffer[..count])?;
                new.data.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            bytes[8..16].copy_from_slice(&position.to_le_bytes());
            bytes[28..32].copy_from_slice(&(new.run.count as u32).to_le_bytes());
            new.index.write_all(&bytes)?;
            new.time.insert((*ts, new.run.count), id.clone());
            new.rows.insert(id.clone(), (new.run.count, bytes));
            new.run.count += 1;
            new.bytes += size;
        }
        new.run.first = old.run.first;
        new.run.last = old.run.last;
        self.obsolete.push(old.run.name.clone());
        self.live = Some(new);
        Ok(())
    }
    pub(crate) fn expire(&mut self, cutoff: i64) -> io::Result<Option<i64>> {
        let mut next = None;
        let mut retained = Vec::new();
        for mut run in self.manifest.runs.clone() {
            if run.first > cutoff {
                next = Some(next.map_or(run.first, |v: i64| v.min(run.first)));
                retained.push(run);
                continue;
            }
            self.manifest.task_revision += 1;
            if self.current.as_ref().is_some_and(|r| r.0 == run.name) {
                self.current = None;
            }
            let (data_path, index_path) = files(&self.folder, &run.name);
            if run.last <= cutoff {
                self.obsolete.push(run.name);
                continue;
            }
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
            next = Some(next.map_or(run.first, |v: i64| v.min(run.first)));
            retained.push(run);
        }
        self.manifest.runs = retained;
        if self.current.is_none() {
            if let Some(run) = self.manifest.runs.last() {
                let (data, index) = files(&self.folder, &run.name);
                self.current = Some((run.name.clone(), open_sparse(&data)?, open_sparse(&index)?));
            }
        }
        let mut expired = false;
        if let Some(live) = &mut self.live {
            while let Some(((ts, _), id)) = live.time.first_key_value() {
                if *ts > cutoff {
                    break;
                }
                let id = id.clone();
                self.expired_live.push(id.clone());
                if !expired {
                    live.set_revision(0)?;
                }
                live.remove(&id)?;
                expired = true;
            }
        }
        if expired {
            self.manifest.task_revision += 1;
        }
        self.finish_live()?;
        if let Some(live) = &self.live {
            let ts = live.run.first;
            next = Some(next.map_or(ts, |n| n.min(ts)));
        }
        Ok(next)
    }
    pub(crate) fn publish(&mut self) -> io::Result<()> {
        self.manifest.revision = self.manifest.revision.wrapping_add(1);
        if let Some(live) = &mut self.live {
            live.set_revision(self.manifest.task_revision)?;
        }
        let temp = self.path.with_file_name(format!(
            "{}.tmp",
            self.path.file_name().unwrap().to_string_lossy()
        ));
        let _publication =
            NativeResourceGuard::register("display_publish", [self.path.clone(), temp.clone()])?;
        let mut file = TrackedFile::open_with(&temp, "display_publish", |o| {
            o.write(true).create(true).truncate(true);
        })?;
        serde_json::to_writer(&mut file, &self.manifest).map_err(|e| invalid(&e.to_string()))?;
        drop(file);
        super::atomic_file::replace(&temp, &self.path)?;
        for name in self.obsolete.drain(..) {
            let (data, index) = files(&self.folder, &name);
            fs::remove_file(data)?;
            fs::remove_file(index)?;
        }
        // A single unusually large group must not leave large scratch buffers resident.
        if self.compressed.capacity() > 2 * RECORD_BLOCK_BYTES {
            self.compressed = Vec::new();
        }
        Ok(())
    }
}
