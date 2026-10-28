//! Short-lived spill storage. Memory limits select storage, never truncate data.
use crate::io::resource_lifecycle::TrackedFile;
use serde::{de::DeserializeOwned, Serialize};
use std::borrow::Cow;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::windows::io::AsRawHandle;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

pub(crate) const MEMORY_BYTES: usize = 4 * 1024 * 1024;
// Small records are often accessed in hash order. Avoid the standard reader's
// 8 KiB read amplification while still combining their MessagePack fields.
const RECORD_READ_BUFFER_BYTES: usize = 256;

#[derive(Debug)]
pub(crate) enum Blob {
    Memory(Vec<u8>),
    Mapped(Mapping),
}
impl Blob {
    /// Diagnostic slice-based parsers can borrow a file mapping rather than
    /// copying the entire archive (including payload) into committed heap.
    pub(crate) fn open_read_only(path: &str) -> io::Result<Self> {
        let file = TrackedFile::open_reader(path, "analysis_mapping")?;
        if file.metadata()?.len() == 0 {
            return Ok(Self::Memory(Vec::new()));
        }
        Ok(Self::Mapped(Mapping::new(&file, false)?))
    }
}
impl Deref for Blob {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Memory(bytes) => bytes,
            Self::Mapped(map) => map,
        }
    }
}
impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl PartialEq<Vec<u8>> for Blob {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other.as_slice()
    }
}
impl<const N: usize> PartialEq<&[u8; N]> for Blob {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_ref() == other.as_slice()
    }
}
impl From<Vec<u8>> for Blob {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Memory(bytes)
    }
}

pub(crate) struct Spool {
    memory: Cursor<Vec<u8>>,
    file: Option<BufWriter<TrackedFile>>,
    position: u64,
    length: u64,
}
impl Default for Spool {
    fn default() -> Self {
        Self {
            memory: Cursor::new(Vec::new()),
            file: None,
            position: 0,
            length: 0,
        }
    }
}
impl Spool {
    pub fn len(&self) -> io::Result<u64> {
        Ok(self.length)
    }
    pub fn truncate(&mut self, len: u64) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
            file.get_ref().set_len(len)?;
        } else {
            self.memory.get_mut().truncate(len as usize);
        }
        self.length = len;
        self.seek(SeekFrom::End(0))?;
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<Blob> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
            // The file is private and immutable from this point. The mapping
            // owns the backing object until drop, including on Windows.
            Ok(Blob::Mapped(Mapping::new(file.get_ref(), false)?))
        } else {
            Ok(Blob::Memory(self.memory.into_inner()))
        }
    }
}
impl Write for Spool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.file.is_none()
            && self.memory.position().saturating_add(bytes.len() as u64) > MEMORY_BYTES as u64
        {
            let mut file = scratch_file()?;
            file.write_all(self.memory.get_ref())?;
            file.seek(SeekFrom::Start(self.memory.position()))?;
            self.memory = Cursor::new(Vec::new());
            self.file = Some(BufWriter::with_capacity(64 * 1024, file));
        }
        let written = match self.file.as_mut() {
            Some(file) => file.write(bytes),
            None => {
                let end = self.memory.position() as usize + bytes.len();
                let additional = end.saturating_sub(self.memory.get_ref().len());
                self.memory.get_mut().try_reserve(additional).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "scratch buffer allocation failed",
                    )
                })?;
                self.memory.write(bytes)
            }
        }?;
        self.position += written as u64;
        self.length = self.length.max(self.position);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}
impl Read for Spool {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let read = match self.file.as_mut() {
            Some(file) => {
                file.flush()?;
                file.get_mut().read(bytes)
            }
            None => self.memory.read(bytes),
        }?;
        self.position += read as u64;
        Ok(read)
    }
}
impl Seek for Spool {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if matches!(pos, SeekFrom::End(0)) && self.position == self.length {
            return Ok(self.position);
        }
        self.position = match self.file.as_mut() {
            Some(file) => file.seek(pos),
            None => self.memory.seek(pos),
        }?;
        Ok(self.position)
    }
}

pub(crate) struct RowBuilder<T> {
    memory: Vec<T>,
    bytes: usize,
    disk: Option<(Spool, Spool)>,
    count: usize,
}
impl<T> Default for RowBuilder<T> {
    fn default() -> Self {
        Self {
            memory: Vec::new(),
            bytes: 0,
            disk: None,
            count: 0,
        }
    }
}
impl<T: Serialize + DeserializeOwned + Clone> RowBuilder<T> {
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn push(&mut self, value: T, bytes: usize) -> io::Result<()> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.disk.is_none() && self.bytes > MEMORY_BYTES {
            let mut disk = (Spool::default(), Spool::default());
            for item in self.memory.drain(..) {
                append_row(&mut disk, &item)?;
            }
            self.disk = Some(disk);
        }
        if let Some(disk) = &mut self.disk {
            append_row(disk, &value)?;
        } else {
            self.memory.push(value);
        }
        self.count += 1;
        Ok(())
    }
    pub fn update(&mut self, index: usize, change: impl FnOnce(&mut T)) -> io::Result<()> {
        if let Some((data, offsets)) = &mut self.disk {
            offsets.seek(SeekFrom::Start(index as u64 * 8))?;
            let mut offset = [0; 8];
            offsets.read_exact(&mut offset)?;
            data.seek(SeekFrom::Start(u64::from_le_bytes(offset)))?;
            // MessagePack reads individual fields; buffer them before touching
            // the spill file. The following end seek discards any read-ahead.
            let mut value = rmp_serde::from_read::<_, T>(BufReader::with_capacity(
                RECORD_READ_BUFFER_BYTES,
                &mut *data,
            ))
            .map_err(io::Error::other)?;
            change(&mut value);
            let end = data.seek(SeekFrom::End(0))?;
            rmp_serde::encode::write(&mut *data, &value).map_err(io::Error::other)?;
            offsets.seek(SeekFrom::Start(index as u64 * 8))?;
            offsets.write_all(&end.to_le_bytes())?;
        } else {
            change(&mut self.memory[index]);
        }
        Ok(())
    }
    pub fn finish(self) -> io::Result<Rows<T>> {
        match self.disk {
            Some((data, offsets)) => Ok(Rows::Disk {
                data: data.finish()?,
                offsets: offsets.finish()?,
                count: self.count,
                marker: PhantomData,
            }),
            None => Ok(Rows::Memory(self.memory)),
        }
    }
}
fn append_row<T: Serialize>(disk: &mut (Spool, Spool), value: &T) -> io::Result<()> {
    let end = disk.0.seek(SeekFrom::End(0))?;
    disk.1.seek(SeekFrom::End(0))?;
    disk.1.write_all(&end.to_le_bytes())?;
    rmp_serde::encode::write(&mut disk.0, value).map_err(io::Error::other)
}

pub(crate) enum Rows<T> {
    Memory(Vec<T>),
    Disk {
        data: Blob,
        offsets: Blob,
        count: usize,
        marker: PhantomData<T>,
    },
}
impl<T> From<Vec<T>> for Rows<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Memory(value)
    }
}
impl<T: DeserializeOwned + Clone> Rows<T> {
    pub fn len(&self) -> usize {
        match self {
            Self::Memory(rows) => rows.len(),
            Self::Disk { count, .. } => *count,
        }
    }
    pub fn get(&self, index: usize) -> io::Result<Cow<'_, T>> {
        match self {
            Self::Memory(rows) => rows
                .get(index)
                .map(Cow::Borrowed)
                .ok_or_else(|| io::Error::other("row index out of range")),
            Self::Disk {
                data,
                offsets,
                count,
                ..
            } => {
                if index >= *count {
                    return Err(io::Error::other("row index out of range"));
                }
                let start =
                    u64::from_le_bytes(offsets[index * 8..index * 8 + 8].try_into().unwrap())
                        as usize;
                rmp_serde::from_slice(&data[start..])
                    .map(Cow::Owned)
                    .map_err(io::Error::other)
            }
        }
    }
}

/// Fixed-width mutable match slots spill independently of variable-size names.
pub(crate) enum Slots {
    Memory(Vec<u64>),
    Disk(Mapping),
}
impl Slots {
    pub fn new(count: usize) -> io::Result<Self> {
        let bytes = count
            .checked_mul(8)
            .ok_or_else(|| io::Error::other("match table overflow"))?;
        if bytes <= MEMORY_BYTES {
            return Ok(Self::Memory(vec![0; count]));
        }
        let file = scratch_file()?;
        file.set_len(bytes as u64)?;
        Ok(Self::Disk(Mapping::new(&file, true)?))
    }
    pub fn get(&self, index: usize) -> u64 {
        match self {
            Self::Memory(values) => values[index],
            Self::Disk(map) => {
                u64::from_le_bytes(map[index * 8..index * 8 + 8].try_into().unwrap())
            }
        }
    }
    pub fn set(&mut self, index: usize, value: u64) {
        match self {
            Self::Memory(values) => values[index] = value,
            Self::Disk(map) => map[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes()),
        }
    }
}

/// Exact key lookup. A private open-addressed disk index reuses the same
/// fixed-width slots, record spool, and MessagePack encoding as manifests.
pub(crate) struct SpillMap<V> {
    memory: std::collections::HashMap<String, V>,
    bytes: usize,
    disk: Option<DiskMap<V>>,
}
impl<V> Default for SpillMap<V> {
    fn default() -> Self {
        Self {
            memory: Default::default(),
            bytes: 0,
            disk: None,
        }
    }
}
impl<V: Serialize + DeserializeOwned + Clone> SpillMap<V> {
    fn spill(&mut self) -> io::Result<()> {
        if self.disk.is_some() || self.bytes <= MEMORY_BYTES {
            return Ok(());
        }
        let mut disk = DiskMap::new(
            self.memory
                .len()
                .saturating_mul(2)
                .max(16)
                .next_power_of_two(),
        )?;
        for (key, value) in &self.memory {
            disk.put(key, value, false)?;
        }
        self.memory = Default::default();
        self.disk = Some(disk);
        Ok(())
    }
    pub fn get(&self, key: &str) -> io::Result<Option<V>> {
        match &self.disk {
            Some(disk) => disk.get(key),
            None => Ok(self.memory.get(key).cloned()),
        }
    }
    pub fn put(&mut self, key: String, value: V) -> io::Result<()> {
        match &mut self.disk {
            Some(disk) => {
                disk.put(&key, &value, false)?;
            }
            None => {
                match self.memory.entry(key) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.insert(value);
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        self.bytes = self
                            .bytes
                            .saturating_add(entry.key().len() + std::mem::size_of::<V>() + 64);
                        entry.insert(value);
                    }
                }
                self.spill()?;
            }
        }
        Ok(())
    }
    pub fn insert_new(&mut self, key: String, value: V) -> io::Result<bool> {
        if self.disk.is_none() {
            let inserted = match self.memory.entry(key) {
                std::collections::hash_map::Entry::Occupied(_) => false,
                std::collections::hash_map::Entry::Vacant(entry) => {
                    self.bytes = self
                        .bytes
                        .saturating_add(entry.key().len() + std::mem::size_of::<V>() + 64);
                    entry.insert(value);
                    true
                }
            };
            self.spill()?;
            return Ok(inserted);
        }
        self.disk.as_mut().unwrap().put(&key, &value, true)
    }
}
struct DiskMap<V> {
    slots: Slots,
    capacity: usize,
    count: usize,
    data: Mutex<BufReader<Spool>>,
    marker: PhantomData<V>,
}
impl<V: Serialize + DeserializeOwned + Clone> DiskMap<V> {
    fn new(capacity: usize) -> io::Result<Self> {
        Ok(Self {
            slots: Slots::new(
                capacity
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("scratch index overflow"))?,
            )?,
            capacity,
            count: 0,
            data: Mutex::new(BufReader::with_capacity(
                RECORD_READ_BUFFER_BYTES,
                Spool::default(),
            )),
            marker: PhantomData,
        })
    }
    fn hash(key: &str) -> u64 {
        crate::fast_hash::xxh64(key.as_bytes(), 0)
    }
    fn row(&self, offset: u64) -> io::Result<(String, V)> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| io::Error::other("scratch index poisoned"))?;
        // Spool tracks the underlying position, including read-ahead. Adjacent
        // records can reuse the buffer without a file seek or another read.
        let end = data.get_ref().position;
        let start = end - data.buffer().len() as u64;
        if (start..=end).contains(&offset) {
            data.consume((offset - start) as usize);
        } else {
            data.seek(SeekFrom::Start(offset))?;
        }
        let mut length = [0; 4];
        data.read_exact(&mut length)?;
        let mut bytes = vec![0; u32::from_le_bytes(length) as usize];
        data.read_exact(&mut bytes)?;
        rmp_serde::from_slice(&bytes).map_err(io::Error::other)
    }
    fn find(&self, key: &str, hash: u64) -> io::Result<(usize, Option<V>)> {
        let mut slot = hash as usize & (self.capacity - 1);
        loop {
            let offset = self.slots.get(slot * 2);
            if offset == 0 {
                return Ok((slot, None));
            }
            // Probe and rehash fixed-width metadata without reading the spool.
            // The full key still decides equality, including hash collisions.
            if self.slots.get(slot * 2 + 1) == hash {
                let (stored, value) = self.row(offset - 1)?;
                if stored == key {
                    return Ok((slot, Some(value)));
                }
            }
            slot = (slot + 1) & (self.capacity - 1);
        }
    }
    fn get(&self, key: &str) -> io::Result<Option<V>> {
        self.find(key, Self::hash(key)).map(|(_, value)| value)
    }
    fn put(&mut self, key: &str, value: &V, only_new: bool) -> io::Result<bool> {
        let hash = Self::hash(key);
        let (mut slot, previous) = self.find(key, hash)?;
        if only_new && previous.is_some() {
            return Ok(false);
        }
        if previous.is_none() && self.count >= self.capacity / 2 {
            let capacity = self
                .capacity
                .checked_mul(2)
                .ok_or_else(|| io::Error::other("scratch index overflow"))?;
            let mut slots = Slots::new(
                capacity
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("scratch index overflow"))?,
            )?;
            for index in 0..self.capacity {
                let offset = self.slots.get(index * 2);
                if offset == 0 {
                    continue;
                }
                let hash = self.slots.get(index * 2 + 1);
                let mut slot = hash as usize & (capacity - 1);
                while slots.get(slot * 2) != 0 {
                    slot = (slot + 1) & (capacity - 1);
                }
                slots.set(slot * 2, offset);
                slots.set(slot * 2 + 1, hash);
            }
            self.capacity = capacity;
            self.slots = slots;
            slot = hash as usize & (capacity - 1);
            while self.slots.get(slot * 2) != 0 {
                slot = (slot + 1) & (capacity - 1);
            }
        }
        let data = self
            .data
            .get_mut()
            .map_err(|_| io::Error::other("scratch index poisoned"))?;
        // Discard buffered reads before appending through the inner writer.
        let offset = data.seek(SeekFrom::End(0))?;
        let data = data.get_mut();
        let bytes = rmp_serde::to_vec(&(key, value)).map_err(io::Error::other)?;
        let len = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        data.write_all(&len.to_le_bytes())?;
        data.write_all(&bytes)?;
        self.slots.set(slot * 2, offset + 1);
        self.slots.set(slot * 2 + 1, hash);
        if previous.is_none() {
            self.count += 1;
        }
        Ok(previous.is_none())
    }
}

fn scratch_file() -> io::Result<TrackedFile> {
    use std::os::windows::fs::OpenOptionsExt;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "sunpack-scratch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match TrackedFile::open_with(path, "scratch", |options| {
            options
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(7)
                .custom_flags(0x04000100);
        }) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            result => return result,
        }
    }
}
#[derive(Debug)]
pub(crate) struct Mapping {
    view: std::ptr::NonNull<u8>,
    len: usize,
    writable: bool,
}
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileMappingW(
        file: *mut std::ffi::c_void,
        attributes: *const std::ffi::c_void,
        protect: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn MapViewOfFile(
        mapping: *mut std::ffi::c_void,
        access: u32,
        high: u32,
        low: u32,
        bytes: usize,
    ) -> *mut std::ffi::c_void;
    fn UnmapViewOfFile(view: *const std::ffi::c_void) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}
impl Mapping {
    fn new(file: &TrackedFile, writable: bool) -> io::Result<Self> {
        let len = usize::try_from(file.metadata()?.len()).map_err(io::Error::other)?;
        let mapping = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                if writable { 4 } else { 2 },
                0,
                0,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }
        let view = unsafe { MapViewOfFile(mapping, if writable { 6 } else { 4 }, 0, 0, 0) };
        let error = io::Error::last_os_error();
        unsafe {
            CloseHandle(mapping);
        }
        let view = std::ptr::NonNull::new(view.cast()).ok_or(error)?;
        Ok(Self {
            view,
            len,
            writable,
        })
    }
}
impl Deref for Mapping {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.view.as_ptr(), self.len) }
    }
}
impl std::ops::DerefMut for Mapping {
    fn deref_mut(&mut self) -> &mut [u8] {
        assert!(self.writable);
        unsafe { std::slice::from_raw_parts_mut(self.view.as_ptr(), self.len) }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.view.as_ptr().cast());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small manifest tests never cross spill storage or rehash a disk index.
    // One lifecycle covers replacement, duplicate insertion, collision equality,
    // growth, mapped slots and concurrent readers at a few MiB of temporary IO.
    #[test]
    fn spill_index_keeps_exact_keys_and_updates_across_storage_and_growth() {
        let mut map = SpillMap::<usize>::default();
        for value in 0..100_000 {
            map.put("same".to_owned(), value).unwrap();
            assert!(!map.insert_new("same".to_owned(), 0).unwrap());
        }
        assert_eq!(map.get("same").unwrap(), Some(99_999));
        assert!(
            map.disk.is_none(),
            "replacement must not consume new-key budget"
        );
        let suffix = "x".repeat(20_000);
        for value in 0..400 {
            assert!(map.insert_new(format!("{value}-{suffix}"), value).unwrap());
        }
        let disk = map.disk.as_mut().unwrap();
        assert!(disk.capacity >= 1024);
        // Exercise mapped slots without a huge corpus just to fill the slot budget.
        let file = scratch_file().unwrap();
        let mut file = file;
        for index in 0..disk.capacity * 2 {
            file.write_all(&disk.slots.get(index).to_le_bytes())
                .unwrap();
        }
        disk.slots = Slots::Disk(Mapping::new(&file, true).unwrap());
        drop(file);
        let capacity = disk.capacity;
        assert!(!disk.put("same", &7, false).unwrap());
        assert!(!disk.put("same", &8, true).unwrap());
        assert_eq!(disk.capacity, capacity);
        let hash = DiskMap::<usize>::hash("same");
        assert!(disk.find("different-full-key", hash).unwrap().1.is_none());
        for value in 400..600 {
            assert!(disk
                .put(&format!("{value}-{suffix}"), &value, true)
                .unwrap());
        }
        assert!(disk.capacity > capacity);
        std::thread::scope(|scope| {
            for shard in 0..4 {
                let map = &map;
                let suffix = &suffix;
                scope.spawn(move || {
                    for value in (shard..600).step_by(4) {
                        assert_eq!(map.get(&format!("{value}-{suffix}")).unwrap(), Some(value));
                    }
                    assert_eq!(map.get("same").unwrap(), Some(7));
                    assert_eq!(map.get("absent").unwrap(), None);
                });
            }
        });
        // Short adjacent records exercise read-ahead. Interleave reverse reads
        // with appends/replacements so buffered bytes cannot hide newer rows.
        for value in 0..128 {
            assert!(map.insert_new(format!("short-{value}"), value).unwrap());
        }
        for value in 0..128 {
            assert_eq!(map.get(&format!("short-{value}")).unwrap(), Some(value));
        }
        for value in (0..128).rev() {
            assert_eq!(map.get(&format!("short-{value}")).unwrap(), Some(value));
            map.put(format!("short-{value}"), value + 1).unwrap();
            assert_eq!(map.get(&format!("short-{value}")).unwrap(), Some(value + 1));
            assert!(!map.insert_new(format!("short-{value}"), 0).unwrap());
        }
        assert_eq!(map.get("same").unwrap(), Some(7));
    }

    // Small archive fixtures never update spilled rows. This one lifecycle
    // checks variable-length replacements, offsets and shared immutable reads
    // with only a few MiB of IO; another small manifest test cannot replace it.
    #[test]
    fn spilled_rows_preserve_replacements_and_concurrent_views() {
        let mut builder = RowBuilder::<(String, u64)>::default();
        let mut expected = Vec::new();
        for index in 0..64 {
            let row = (format!("{index}:{}", "x".repeat(96 * 1024)), index);
            builder.push(row.clone(), row.0.len() + 8).unwrap();
            expected.push(row);
        }
        assert!(builder.disk.is_some());
        for (index, length) in [(0, 0), (63, 200_000), (7, 30), (0, 12_000), (31, 8192)] {
            expected[index] = ("y".repeat(length), 100 + index as u64);
            builder
                .update(index, |row| *row = expected[index].clone())
                .unwrap();
        }
        let rows = builder.finish().unwrap();
        assert!(matches!(&rows, Rows::Disk { .. }));
        std::thread::scope(|scope| {
            for shard in 0..4 {
                let rows = &rows;
                let expected = &expected;
                scope.spawn(move || {
                    for index in (shard..64).step_by(4).rev() {
                        assert_eq!(rows.get(index).unwrap().as_ref(), &expected[index]);
                    }
                    assert!(rows.get(64).is_err());
                });
            }
        });
    }
}
