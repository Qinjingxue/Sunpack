//! Short-lived spill storage. Memory limits select storage, never truncate data.
use crate::io::resource_lifecycle::TrackedFile;
use std::io::{self, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MEMORY_BYTES: usize = 4 * 1024 * 1024;

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

fn scratch_file() -> io::Result<TrackedFile> {
    use std::os::windows::fs::OpenOptionsExt;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "sunpack-scratch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match TrackedFile::open_with(path, |options| {
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
