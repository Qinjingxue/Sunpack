//! Short-lived spill storage. Memory limits select storage, never truncate data.
use crate::io::resource_lifecycle::TrackedFile;
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MEMORY_BYTES: usize = 4 * 1024 * 1024;
// Small records are often accessed in hash order. Avoid the standard reader's
// 8 KiB read amplification while still combining record lengths and names.
const RECORD_READ_BUFFER_BYTES: usize = 256;

#[derive(Debug)]
pub(crate) enum Blob {
    Memory(Vec<u8>),
    Mapped(Mapping),
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
    pub(crate) fn is_spilled(&self) -> bool {
        self.file.is_some()
    }

    /// Resident allocation, including capacity retained after previous writes.
    pub(crate) fn memory_bytes(&self) -> usize {
        self.file
            .as_ref()
            .map_or_else(|| self.memory.get_ref().capacity(), |file| file.capacity())
    }

    pub(crate) fn spill(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            let mut file = scratch_file()?;
            file.write_all(self.memory.get_ref())?;
            file.seek(SeekFrom::Start(self.memory.position()))?;
            self.memory = Cursor::new(Vec::new());
            self.file = Some(BufWriter::with_capacity(64 * 1024, file));
        }
        Ok(())
    }

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
            self.spill()?;
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

/// Exact name deduplication, spilling through the shared slots and spool.
pub(crate) struct SpillSet {
    memory: HashSet<String>,
    bytes: usize,
    disk: Option<DiskSet>,
}
impl Default for SpillSet {
    fn default() -> Self {
        Self {
            memory: Default::default(),
            bytes: 0,
            disk: None,
        }
    }
}
impl SpillSet {
    fn spill(&mut self) -> io::Result<()> {
        if self.disk.is_some() || self.bytes <= MEMORY_BYTES {
            return Ok(());
        }
        let mut disk = DiskSet::new(
            self.memory
                .len()
                .saturating_mul(2)
                .max(16)
                .next_power_of_two(),
        )?;
        for key in &self.memory {
            disk.insert(key)?;
        }
        self.memory = Default::default();
        self.disk = Some(disk);
        Ok(())
    }
    pub fn insert(&mut self, key: &str) -> io::Result<bool> {
        if self.disk.is_none() {
            if self.memory.contains(key) {
                return Ok(false);
            }
            self.bytes = self.bytes.saturating_add(key.len() + 64);
            self.memory.insert(key.to_owned());
            self.spill()?;
            return Ok(true);
        }
        self.disk.as_mut().unwrap().insert(key)
    }
}
struct DiskSet {
    slots: Slots,
    capacity: usize,
    count: usize,
    data: BufReader<Spool>,
}
impl DiskSet {
    fn new(capacity: usize) -> io::Result<Self> {
        Ok(Self {
            slots: Slots::new(
                capacity
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("scratch index overflow"))?,
            )?,
            capacity,
            count: 0,
            data: BufReader::with_capacity(
                RECORD_READ_BUFFER_BYTES,
                Spool::default(),
            ),
        })
    }
    fn hash(key: &str) -> u64 {
        crate::fast_hash::xxh64(key.as_bytes(), 0)
    }
    fn matches(&mut self, offset: u64, key: &str) -> io::Result<bool> {
        let data = &mut self.data;
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
        if u32::from_le_bytes(length) as usize != key.len() {
            return Ok(false);
        }
        let mut bytes = [0; RECORD_READ_BUFFER_BYTES];
        for expected in key.as_bytes().chunks(bytes.len()) {
            let actual = &mut bytes[..expected.len()];
            data.read_exact(actual)?;
            if actual != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn find(&mut self, key: &str, hash: u64) -> io::Result<(usize, bool)> {
        let mut slot = hash as usize & (self.capacity - 1);
        loop {
            let offset = self.slots.get(slot * 2);
            if offset == 0 {
                return Ok((slot, false));
            }
            // Probe and rehash fixed-width metadata without reading the spool.
            // The full key still decides equality, including hash collisions.
            if self.slots.get(slot * 2 + 1) == hash {
                if self.matches(offset - 1, key)? {
                    return Ok((slot, true));
                }
            }
            slot = (slot + 1) & (self.capacity - 1);
        }
    }
    fn insert(&mut self, key: &str) -> io::Result<bool> {
        let hash = Self::hash(key);
        let (mut slot, previous) = self.find(key, hash)?;
        if previous {
            return Ok(false);
        }
        if self.count >= self.capacity / 2 {
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
        let data = &mut self.data;
        // Discard buffered reads before appending through the inner writer.
        let offset = data.seek(SeekFrom::End(0))?;
        let data = data.get_mut();
        let len = u32::try_from(key.len()).map_err(io::Error::other)?;
        data.write_all(&len.to_le_bytes())?;
        data.write_all(key.as_bytes())?;
        self.slots.set(slot * 2, offset + 1);
        self.slots.set(slot * 2 + 1, hash);
        self.count += 1;
        Ok(true)
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

    #[test]
    fn dedup_survives_spill_and_index_growth() {
        let mut map = SpillSet::default();
        let suffix = "x".repeat(20_000);
        for index in 0..600 {
            assert!(map.insert(&format!("{index}-{suffix}")).unwrap());
        }
        assert!(map.disk.is_some());
        for index in (0..600).rev() {
            assert!(!map.insert(&format!("{index}-{suffix}")).unwrap());
        }
        let disk = map.disk.as_mut().unwrap();
        assert!(!disk.find("different-full-key", DiskSet::hash(&format!("0-{suffix}")))
            .unwrap().1);
        let mut collision = format!("0-{suffix}");
        collision.pop();
        collision.push('y');
        assert!(!disk.find(&collision, DiskSet::hash(&format!("0-{suffix}")))
            .unwrap().1);
        assert!(map.insert("").unwrap());
        assert!(!map.insert("").unwrap());
    }
}
