use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::resource_lifecycle::TrackedFile;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{File, Metadata};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::SystemTime;

#[cfg(test)]
thread_local! {
    static THREAD_PHYSICAL_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static THREAD_REQUEST_COALESCES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

const BLOCK_SIZE: usize = 64 * 1024;
const DEFAULT_SHARED_CACHE_BYTES: usize = 256 * 1024 * 1024;
const CACHE_SHARDS: usize = 64;
const HOT_CACHE_FRACTION: usize = 4;
const HOT_EDGE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_HANDLE_CAPACITY: usize = 256;
const MAX_CACHEABLE_READ_BYTES: usize = 4 * 1024 * 1024;
const CACHE_ORDER_COMPACT_STALE_MIN: usize = 64;

#[derive(Clone)]
enum CachedBacking {
    Shared(Arc<[u8]>),
    Owned(Arc<Vec<u8>>),
}

impl Deref for CachedBacking {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(data) => data,
            Self::Owned(data) => data,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CachedSlice {
    data: CachedBacking,
    start: usize,
    end: usize,
}

impl CachedSlice {
    fn from_shared(data: Arc<[u8]>, start: usize, end: usize) -> Self {
        Self {
            data: CachedBacking::Shared(data),
            start,
            end,
        }
    }

    fn from_vec(data: Vec<u8>) -> Self {
        let end = data.len();
        Self {
            data: CachedBacking::Owned(Arc::new(data)),
            start: 0,
            end,
        }
    }

    fn retained_bytes(&self) -> usize {
        self.data.len()
    }

    #[cfg(test)]
    fn shares_backing(&self, other: &Self) -> bool {
        match (&self.data, &other.data) {
            (CachedBacking::Shared(left), CachedBacking::Shared(right)) => Arc::ptr_eq(left, right),
            (CachedBacking::Owned(left), CachedBacking::Owned(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Deref for CachedSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[self.start..self.end]
    }
}

pub(crate) enum CachedBytes {
    Slice(CachedSlice),
    Owned(Vec<u8>),
}

impl CachedBytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self
    }
}

impl AsRef<[u8]> for CachedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Default for CachedBytes {
    fn default() -> Self {
        Self::Owned(Vec::new())
    }
}

impl Deref for CachedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Slice(slice) => slice,
            Self::Owned(data) => data,
        }
    }
}

pub(crate) trait ByteSource: Send + Sync {
    fn len(&self) -> u64;
    /// Reads at most `len` bytes. A range crossing EOF is shortened.
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.read_at(offset, buffer.len())?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        let data = self.read_at(offset, len)?;
        Ok((!data.is_empty())
            .then(|| CachedSlice::from_vec(data))
            .into_iter()
            .collect())
    }
    fn prefetch(&self, _ranges: &[(u64, usize)]) -> io::Result<()> {
        Ok(())
    }
    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.read_at(offset, len)
    }
    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.read_direct_at(offset, buffer.len())?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    #[cfg(windows)]
    fn iocp_path(&self) -> Option<&Path> {
        None
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReaderConfig {
    pub(crate) cache_bytes: usize,
    pub(crate) max_read_bytes: Option<u64>,
    pub(crate) max_concurrent_reads: usize,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            cache_bytes: 0,
            max_read_bytes: None,
            max_concurrent_reads: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReaderStats {
    pub(crate) read_bytes: u64,
    pub(crate) cache_hits: u64,
}

#[derive(Clone)]
pub(crate) struct ManagedReader {
    source: Arc<dyn ByteSource>,
    state: Arc<ReaderState>,
}

struct ReaderState {
    config: ReaderConfig,
    inner: Mutex<ReaderInner>,
    uncached_read_bytes: AtomicU64,
    gate: ReadGate,
}

#[derive(Default)]
struct ReaderInner {
    cache: HashMap<(u64, usize), CachedSlice>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    stats: ReaderStats,
}

struct ReadGate {
    limit: usize,
    active: Mutex<usize>,
    available: Condvar,
}

struct ReadPermit<'a> {
    gate: Option<&'a ReadGate>,
}

impl ManagedReader {
    pub(crate) fn new(source: Arc<dyn ByteSource>, config: ReaderConfig) -> Self {
        Self {
            source,
            state: Arc::new(ReaderState {
                gate: ReadGate {
                    limit: config.max_concurrent_reads.max(1),
                    active: Mutex::new(0),
                    available: Condvar::new(),
                },
                config,
                inner: Mutex::new(ReaderInner::default()),
                uncached_read_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn closed() -> Self {
        Self::new(Arc::new(ClosedSource), ReaderConfig::default())
    }

    pub(crate) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_config(path, ReaderConfig::default())
    }

    pub(crate) fn open_with_config(
        path: impl AsRef<Path>,
        config: ReaderConfig,
    ) -> io::Result<Self> {
        let source = manager().open_file(path.as_ref())?;
        Ok(Self::new(source, config))
    }

    pub(crate) fn open_volumes(paths: &[String], config: ReaderConfig) -> io::Result<Self> {
        let source = MultiVolumeSource::open(paths)?;
        Ok(Self::new(Arc::new(source), config))
    }

    pub(crate) fn from_bytes(data: Vec<u8>, config: ReaderConfig) -> Self {
        let data: Arc<[u8]> = Arc::from(data);
        Self::new(Arc::new(BytesSource { data }), config)
    }

    pub(crate) fn with_config(&self, config: ReaderConfig) -> Self {
        Self::new(Arc::clone(&self.source), config)
    }

    pub(crate) fn len(&self) -> u64 {
        self.source.len()
    }

    #[cfg(windows)]
    pub(crate) fn iocp_path(&self) -> Option<&Path> {
        self.source.iocp_path()
    }

    /// Reads a range into caller-owned storage and shortens it at EOF.
    ///
    /// Request-state users should prefer `read_cached_at` when they only need
    /// immutable bytes. This owned boundary deliberately performs the one copy
    /// needed to hand independent storage to its caller.
    pub(crate) fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if !self.uses_request_state() {
            let _permit = self.state.gate.acquire()?;
            let data = self.source.read_at(offset, read_len).map_err(|error| {
                ReadFault::physical("read_at", offset, read_len, 0, self.len(), &error)
                    .into_io_error()
            })?;
            self.state
                .uncached_read_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(data);
        }
        Ok(self.read_cached_at(offset, read_len)?.as_slice().to_vec())
    }

    pub(crate) fn read_exact_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let data = self.read_at(offset, len)?;
        if data.len() != len {
            return Err(ReadFault::short_read(
                "read_exact_at",
                offset,
                len,
                data.len(),
                self.len(),
            )
            .into_io_error());
        }
        Ok(data)
    }

    pub(crate) fn read_exact_field_at(
        &self,
        offset: u64,
        len: usize,
        field: &'static str,
        location: FieldLocation,
    ) -> Result<Vec<u8>, ReadFault> {
        self.read_exact_at(offset, len).map_err(|error| {
            ReadFault::from_io(error, "read_exact_at", offset, len, 0, self.len())
                .with_field(field, location)
        })
    }

    /// Reads through the shared cache directly into a caller-owned buffer.
    /// Without request state this remains the allocation-free `SourceCursor`
    /// hot path. With request state, the cache owns shared immutable data and
    /// this boundary performs only the required copy into the caller buffer.
    pub(crate) fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let read_len = buffer.len().min((self.len() - offset) as usize);
        if !self.uses_request_state() {
            let _permit = self.state.gate.acquire()?;
            let count = self
                .source
                .read_into_at(offset, &mut buffer[..read_len])
                .map_err(|error| {
                    ReadFault::physical("read_into_at", offset, read_len, 0, self.len(), &error)
                        .into_io_error()
                })?;
            self.state
                .uncached_read_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(count);
        }

        let slices = self.read_slices_at(offset, read_len)?;
        let mut written = 0usize;
        for slice in slices {
            let remaining = read_len.saturating_sub(written);
            if remaining == 0 {
                break;
            }
            let chunk = &slice[..slice.len().min(remaining)];
            buffer[written..written + chunk.len()].copy_from_slice(chunk);
            written += chunk.len();
        }
        Ok(written)
    }

    pub(crate) fn read_all(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "file is too large for memory")
        })?;
        self.read_at(0, len)
    }

    /// Returns shared slices without copying payload bytes on request-cache hits.
    ///
    /// Requests that fit the request-cache capacity are coalesced at most once
    /// so repeated reads can clone shared ownership. Oversized requests retain
    /// the source's native slice layout instead of paying for an uncacheable
    /// contiguous allocation.
    pub(crate) fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if !self.uses_request_state() {
            let _permit = self.state.gate.acquire()?;
            let slices = self
                .source
                .read_slices_at(offset, read_len)
                .map_err(|error| {
                    ReadFault::physical("read_slices_at", offset, read_len, 0, self.len(), &error)
                        .into_io_error()
                })?;
            let count = slices.iter().map(|slice| slice.len()).sum::<usize>();
            self.state
                .uncached_read_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(slices);
        }

        if self.state.config.cache_bytes > 0 && read_len <= self.state.config.cache_bytes {
            return Ok(vec![self.read_request_cached_slice_at(offset, read_len)?]);
        }
        self.read_request_source_slices_at(offset, read_len)
    }

    pub(crate) fn read_cached_at(&self, offset: u64, len: usize) -> io::Result<CachedBytes> {
        if offset >= self.len() || len == 0 {
            return Ok(CachedBytes::Owned(Vec::new()));
        }
        let read_len = len.min((self.len() - offset) as usize);
        if self.uses_request_state()
            && self.state.config.cache_bytes > 0
            && read_len <= self.state.config.cache_bytes
        {
            return Ok(CachedBytes::Slice(
                self.read_request_cached_slice_at(offset, read_len)?,
            ));
        }

        let mut slices = self.read_slices_at(offset, read_len)?;
        if slices.len() == 1 {
            return Ok(CachedBytes::Slice(slices.remove(0)));
        }
        let total = slices.iter().map(|slice| slice.len()).sum();
        let mut data = Vec::with_capacity(total);
        for slice in slices {
            data.extend_from_slice(&slice);
        }
        Ok(CachedBytes::Owned(data))
    }

    fn read_request_cached_slice_at(
        &self,
        offset: u64,
        read_len: usize,
    ) -> io::Result<CachedSlice> {
        let key = (offset, read_len);
        {
            let mut inner = self.lock_inner()?;
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.stats.cache_hits += 1;
                return Ok(data);
            }
        }

        let slices = self.read_request_source_slices_at(offset, read_len)?;
        let data = coalesce_cached_slices(slices);
        self.lock_inner()?.store_cache_entry(
            key,
            data.clone(),
            self.state.config.cache_bytes,
        );
        Ok(data)
    }

    fn read_request_source_slices_at(
        &self,
        offset: u64,
        read_len: usize,
    ) -> io::Result<Vec<CachedSlice>> {
        {
            let inner = self.lock_inner()?;
            if self
                .state
                .config
                .max_read_bytes
                .is_some_and(|limit| inner.stats.read_bytes + read_len as u64 > limit)
            {
                return Err(io::Error::other("archive analysis read budget exceeded"));
            }
        }

        let _permit = self.state.gate.acquire()?;
        let slices = self
            .source
            .read_slices_at(offset, read_len)
            .map_err(|error| {
                ReadFault::physical("read_slices_at", offset, read_len, 0, self.len(), &error)
                    .into_io_error()
            })?;
        let count = slices.iter().map(|slice| slice.len()).sum::<usize>();
        self.lock_inner()?.stats.read_bytes += count as u64;
        Ok(slices)
    }

    /// Warms every fixed block touched by the supplied ranges. Overlapping
    /// ranges are coalesced by the source before physical I/O.
    pub(crate) fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        let _permit = self.state.gate.acquire()?;
        self.source.prefetch(ranges)
    }

    pub(crate) fn read_many(&self, ranges: &[(u64, usize)]) -> io::Result<Vec<Vec<u8>>> {
        self.prefetch(ranges)?;
        ranges
            .iter()
            .map(|&(offset, len)| self.read_at(offset, len))
            .collect()
    }

    pub(crate) fn stats(&self) -> io::Result<ReaderStats> {
        let mut stats = self.lock_inner()?.stats;
        stats.read_bytes = stats
            .read_bytes
            .saturating_add(self.state.uncached_read_bytes.load(Ordering::Relaxed));
        Ok(stats)
    }

    pub(crate) fn cursor(&self) -> SourceCursor {
        SourceCursor {
            reader: self.clone(),
            position: 0,
            streaming: false,
        }
    }

    /// Sequential scans bypass the shared block cache to avoid cache pollution
    /// and preserve the existing large-buffer read pipeline.
    pub(crate) fn stream_cursor(&self) -> SourceCursor {
        SourceCursor {
            reader: self.clone(),
            position: 0,
            streaming: true,
        }
    }

    pub(crate) fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let _permit = self.state.gate.acquire()?;
        self.source
            .read_direct_into_at(offset, buffer)
            .map_err(|error| {
                ReadFault::physical(
                    "read_direct_into_at",
                    offset,
                    buffer.len(),
                    0,
                    self.len(),
                    &error,
                )
                .into_io_error()
            })
    }

    fn lock_inner(&self) -> io::Result<MutexGuard<'_, ReaderInner>> {
        self.state
            .inner
            .lock()
            .map_err(|_| io::Error::other("managed reader lock poisoned"))
    }

    fn uses_request_state(&self) -> bool {
        self.state.config.cache_bytes > 0 || self.state.config.max_read_bytes.is_some()
    }
}

#[pyclass]
pub(crate) struct NativeArchiveSession {
    path: String,
    reader: ManagedReader,
    closed: bool,
    seven_zip_password_probe:
        OnceLock<Option<Arc<crate::formats::seven_zip::SevenZipPasswordProbe>>>,
}

impl NativeArchiveSession {
    fn ensure_open(&self) -> PyResult<()> {
        if self.closed {
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "native archive session is closed",
            ))
        } else {
            Ok(())
        }
    }
}

#[pymethods]
impl NativeArchiveSession {
    #[new]
    fn new(path: String) -> PyResult<Self> {
        let reader = ManagedReader::open(&path)?;
        Ok(Self {
            path,
            reader,
            closed: false,
            seven_zip_password_probe: OnceLock::new(),
        })
    }

    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        self.ensure_open()?;
        Ok(self.reader.len())
    }

    #[getter]
    fn closed(&self) -> bool {
        self.closed
    }

    fn close(&mut self) {
        if !self.closed {
            self.reader = ManagedReader::closed();
            self.closed = true;
        }
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.ensure_open()?;
        let data = self.reader.read_cached_at(offset, len)?;
        Ok(PyBytes::new(py, data.as_slice()))
    }

    fn prefetch(&self, ranges: Vec<(u64, usize)>) -> PyResult<()> {
        self.ensure_open()?;
        self.reader.prefetch(&ranges)?;
        Ok(())
    }

    #[pyo3(signature = (cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn analysis_view(
        &self,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> PyResult<crate::analysis_native::AnalysisBinaryView> {
        if self.closed {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "native archive session is closed",
            ));
        }
        Ok(crate::analysis_native::AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.with_config(ReaderConfig {
                cache_bytes,
                max_read_bytes,
                max_concurrent_reads,
            }),
            closed: false,
        })
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let stats = self.reader.stats()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", stats.read_bytes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        Ok(dict.unbind())
    }

    fn zip_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        self.ensure_open()?;
        crate::password::zip::zip_fast_verify_passwords_with_reader(py, &self.reader, passwords)
    }

    fn seven_zip_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        self.ensure_open()?;
        crate::password::seven_zip::seven_zip_fast_verify_passwords_with_probe_cache(
            py,
            &self.reader,
            passwords,
            &self.seven_zip_password_probe,
        )
    }

    fn rar_fast_verify_passwords(
        &self,
        py: Python<'_>,
        passwords: &Bound<'_, PyList>,
    ) -> PyResult<Py<PyAny>> {
        self.ensure_open()?;
        crate::password::rar::rar_fast_verify_passwords_with_reader(py, &self.reader, passwords)
    }

    #[pyo3(signature = (iocp_chunk_bytes=2097152, iocp_buffers=2, iocp_workers=4))]
    fn scan_embedded_archives(
        &self,
        py: Python<'_>,
        iocp_chunk_bytes: usize,
        iocp_buffers: usize,
        iocp_workers: usize,
    ) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        crate::scan::embedded::scan_embedded_archives_with_reader(
            py,
            &self.reader,
            iocp_chunk_bytes,
            iocp_buffers,
            iocp_workers,
        )
    }
}

fn coalesce_cached_slices(mut slices: Vec<CachedSlice>) -> CachedSlice {
    if slices.len() == 1 {
        return slices.remove(0);
    }

    #[cfg(test)]
    if slices.len() > 1 {
        THREAD_REQUEST_COALESCES.with(|count| count.set(count.get() + 1));
    }

    let total = slices.iter().map(|slice| slice.len()).sum();
    let mut data = Vec::with_capacity(total);
    for slice in slices {
        data.extend_from_slice(&slice);
    }
    CachedSlice::from_vec(data)
}

impl ReaderInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: CachedSlice, capacity: usize) {
        let retained = data.retained_bytes();
        if capacity == 0 || retained > capacity {
            return;
        }
        if let Some(old) = self.cache.insert(key, data) {
            self.cache_size = self.cache_size.saturating_sub(old.retained_bytes());
            self.order.retain(|existing| *existing != key);
        }
        self.cache_size += self
            .cache
            .get(&key)
            .map(CachedSlice::retained_bytes)
            .unwrap_or(0);
        self.order.push_back(key);
        while self.cache_size > capacity {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.cache.remove(&old_key) {
                self.cache_size = self.cache_size.saturating_sub(old.retained_bytes());
            }
        }
    }
}

impl ReadGate {
    fn acquire(&self) -> io::Result<ReadPermit<'_>> {
        if self.limit == usize::MAX {
            return Ok(ReadPermit { gate: None });
        }
        let mut active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("reader gate lock poisoned"))?;
        while *active >= self.limit {
            active = self
                .available
                .wait(active)
                .map_err(|_| io::Error::other("reader gate wait poisoned"))?;
        }
        *active += 1;
        Ok(ReadPermit { gate: Some(self) })
    }
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        let Some(gate) = self.gate else {
            return;
        };
        if let Ok(mut active) = gate.active.lock() {
            *active = active.saturating_sub(1);
            gate.available.notify_one();
        }
    }
}

pub(crate) struct SourceCursor {
    reader: ManagedReader,
    position: u64,
    streaming: bool,
}

impl Read for SourceCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = if self.streaming {
            self.reader.read_direct_into_at(self.position, buf)?
        } else {
            self.reader.read_into_at(self.position, buf)?
        };
        self.position = self.position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::End(value) => self.reader.len() as i128 + value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

struct BytesSource {
    data: Arc<[u8]>,
}

struct ClosedSource;

impl ByteSource for ClosedSource {
    fn len(&self) -> u64 {
        0
    }

    fn read_at(&self, _offset: u64, _len: usize) -> io::Result<Vec<u8>> {
        Err(io::Error::other("resource closed"))
    }
}

impl ByteSource for BytesSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let start = offset as usize;
        let end = start.saturating_add(len).min(self.data.len());
        Ok(self.data[start..end].to_vec())
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let start = offset as usize;
        let end = start.saturating_add(len).min(self.data.len());
        Ok(vec![CachedSlice::from_shared(
            Arc::clone(&self.data),
            start,
            end,
        )])
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct FileIdentity {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

struct FileSource {
    identity: FileIdentity,
    file: RwLock<Option<TrackedFile>>,
    closed: AtomicBool,
    block_loads: Mutex<HashMap<u64, Arc<BlockLoad>>>,
}

struct BlockLoad {
    completed: Mutex<bool>,
    ready: Condvar,
}

impl BlockLoad {
    fn new() -> Self {
        Self {
            completed: Mutex::new(false),
            ready: Condvar::new(),
        }
    }

    fn wait(&self) -> io::Result<()> {
        let mut completed = self
            .completed
            .lock()
            .map_err(|_| io::Error::other("reader block-load state poisoned"))?;
        while !*completed {
            completed = self
                .ready
                .wait(completed)
                .map_err(|_| io::Error::other("reader block-load state poisoned"))?;
        }
        Ok(())
    }

    fn finish(&self) {
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *completed = true;
        self.ready.notify_all();
    }
}

enum BlockLoadClaim {
    Cached,
    Owned(Arc<BlockLoad>),
    Waiting(Arc<BlockLoad>),
}

impl FileSource {
    fn ensure_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::Error::other("resource closed"))
        } else {
            Ok(())
        }
    }

    fn with_file<T>(&self, operation: impl FnOnce(&File) -> io::Result<T>) -> io::Result<T> {
        let file = self
            .file
            .read()
            .map_err(|_| io::Error::other("reader file lock poisoned"))?;
        let file = file
            .as_ref()
            .ok_or_else(|| io::Error::other("resource closed"))?;
        operation(file)
    }

    fn close(&self) -> io::Result<bool> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(false);
        }
        let mut file = self
            .file
            .write()
            .map_err(|_| io::Error::other("reader file lock poisoned"))?;
        let closed = file.take().is_some();
        Ok(closed)
    }
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.identity.len
    }

    #[cfg(windows)]
    fn iocp_path(&self) -> Option<&Path> {
        Some(&self.identity.path)
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.ensure_open()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            let data =
                self.with_file(|file| read_file_at(file, offset, len, &manager().metrics))?;
            manager()
                .metrics
                .logical_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(data);
        }

        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let mut output = Vec::with_capacity(len);
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let from = offset.saturating_sub(block_start) as usize;
            let request_end = offset + len as u64;
            let to = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if from < to && from < block.len() {
                output.extend_from_slice(&block[from..to.min(block.len())]);
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(output.len() as u64, Ordering::Relaxed);
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.ensure_open()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            manager()
                .metrics
                .physical_reads
                .fetch_add(1, Ordering::Relaxed);
            let count = self.with_file(|file| positional_read(file, &mut buffer[..len], offset))?;
            manager()
                .metrics
                .physical_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            manager()
                .metrics
                .logical_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(count);
        }

        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let mut written = 0usize;
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let from = offset.saturating_sub(block_start) as usize;
            let request_end = offset + len as u64;
            let to = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if from < to && from < block.len() {
                let chunk = &block[from..to.min(block.len())];
                buffer[written..written + chunk.len()].copy_from_slice(chunk);
                written += chunk.len();
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        self.ensure_open()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            return Ok(vec![CachedSlice::from_vec(
                self.read_direct_at(offset, len)?,
            )]);
        }
        let first = offset / BLOCK_SIZE as u64;
        let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
        let request_end = offset + len as u64;
        let mut slices = Vec::with_capacity((last - first + 1) as usize);
        for index in first..=last {
            let block = manager().read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let start = offset.saturating_sub(block_start) as usize;
            let end = (request_end.min(block_start + block.len() as u64) - block_start) as usize;
            if start < end && start < block.len() {
                slices.push(CachedSlice::from_shared(block, start, end));
            }
        }
        manager()
            .metrics
            .logical_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
        Ok(slices)
    }

    fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        self.ensure_open()?;
        let mut blocks = BTreeSet::new();
        for &(offset, len) in ranges {
            if offset >= self.len() || len == 0 {
                continue;
            }
            let len = len.min((self.len() - offset) as usize);
            if len > MAX_CACHEABLE_READ_BYTES {
                continue;
            }
            let first = offset / BLOCK_SIZE as u64;
            let last = (offset + len as u64 - 1) / BLOCK_SIZE as u64;
            blocks.extend(first..=last);
        }
        manager().prefetch_blocks(self, blocks.into_iter().collect())
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.ensure_open()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        let data = self.with_file(|file| read_file_at(file, offset, len, &manager().metrics))?;
        manager()
            .metrics
            .logical_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data)
    }

    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.ensure_open()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        let count = self.with_file(|file| positional_read(file, &mut buffer[..len], offset))?;
        manager()
            .metrics
            .physical_reads
            .fetch_add(1, Ordering::Relaxed);
        manager()
            .metrics
            .physical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        manager()
            .metrics
            .logical_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}

struct Volume {
    start: u64,
    end: u64,
    source: Arc<FileSource>,
}

struct MultiVolumeSource {
    len: u64,
    volumes: Vec<Volume>,
}

impl MultiVolumeSource {
    fn open(paths: &[String]) -> io::Result<Self> {
        if paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multi-volume reader requires at least one volume",
            ));
        }
        let mut cursor = 0u64;
        let mut volumes = Vec::with_capacity(paths.len());
        for path in paths {
            let source = manager().open_file(path.as_ref())?;
            let end = cursor.checked_add(source.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "multi-volume size overflow")
            })?;
            volumes.push(Volume {
                start: cursor,
                end,
                source,
            });
            cursor = end;
        }
        Ok(Self {
            len: cursor,
            volumes,
        })
    }
}

impl ByteSource for MultiVolumeSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut output = Vec::with_capacity(len);
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk = volume.source.read_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut written = 0usize;
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk_len = (logical_end - logical_start) as usize;
            let count = volume.source.read_into_at(
                logical_start - volume.start,
                &mut buffer[written..written + chunk_len],
            )?;
            written += count;
            if count != chunk_len {
                break;
            }
        }
        Ok(written)
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut slices = Vec::new();
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            slices.extend(volume.source.read_slices_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?);
        }
        Ok(slices)
    }

    fn prefetch(&self, ranges: &[(u64, usize)]) -> io::Result<()> {
        for volume in &self.volumes {
            let mapped = ranges
                .iter()
                .filter_map(|&(offset, len)| {
                    let end = offset.saturating_add(len as u64).min(self.len);
                    if offset >= volume.end || end <= volume.start {
                        return None;
                    }
                    let start = offset.max(volume.start);
                    let end = end.min(volume.end);
                    Some((start - volume.start, (end - start) as usize))
                })
                .collect::<Vec<_>>();
            volume.source.prefetch(&mapped)?;
        }
        Ok(())
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut output = Vec::with_capacity(len);
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk = volume.source.read_direct_at(
                logical_start - volume.start,
                (logical_end - logical_start) as usize,
            )?;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct BlockKey {
    identity: FileIdentity,
    index: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CacheTier {
    Hot,
    General,
}

struct CacheEntry {
    data: Arc<[u8]>,
    tier: CacheTier,
    generation: u64,
}

struct CacheShard {
    entries: HashMap<BlockKey, CacheEntry>,
    by_identity: HashMap<FileIdentity, HashSet<u64>>,
    hot_order: VecDeque<(BlockKey, u64)>,
    general_order: VecDeque<(BlockKey, u64)>,
    hot_size: usize,
    general_size: usize,
    hot_stale: usize,
    general_stale: usize,
    generation: u64,
    hot_capacity: usize,
    general_capacity: usize,
}

struct HandleEntry {
    source: Arc<FileSource>,
    generation: u64,
}

struct HandlePool {
    entries: HashMap<FileIdentity, HandleEntry>,
    by_path: HashMap<PathBuf, FileIdentity>,
    order: VecDeque<(FileIdentity, u64)>,
    generation: u64,
    capacity: usize,
}

struct ReaderManager {
    handles: Mutex<HandlePool>,
    cache_shards: Box<[Mutex<CacheShard>]>,
    metrics: ManagerMetrics,
}

#[derive(Default)]
struct ManagerMetrics {
    logical_bytes: AtomicU64,
    physical_bytes: AtomicU64,
    physical_reads: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    hot_cache_hits: AtomicU64,
    handle_hits: AtomicU64,
    opens: AtomicU64,
    evictions: AtomicU64,
}

impl CacheShard {
    fn remove_entry(&mut self, key: &BlockKey, leave_order_entry: bool) -> Option<CacheEntry> {
        let entry = self.entries.remove(key)?;
        match entry.tier {
            CacheTier::Hot => {
                self.hot_size = self.hot_size.saturating_sub(entry.data.len());
                if leave_order_entry {
                    self.hot_stale += 1;
                }
            }
            CacheTier::General => {
                self.general_size = self.general_size.saturating_sub(entry.data.len());
                if leave_order_entry {
                    self.general_stale += 1;
                }
            }
        }

        let remove_identity = if let Some(indices) = self.by_identity.get_mut(&key.identity) {
            indices.remove(&key.index);
            indices.is_empty()
        } else {
            false
        };
        if remove_identity {
            self.by_identity.remove(&key.identity);
        }
        Some(entry)
    }

    fn compact_stale_orders(&mut self) {
        // Cache payloads and byte counters are removed synchronously. Only
        // obsolete LRU queue keys are compacted amortized so targeted release
        // does not turn back into a full-cache scan.
        if self.hot_stale >= CACHE_ORDER_COMPACT_STALE_MIN {
            let entries = &self.entries;
            let order = &mut self.hot_order;
            order.retain(|(key, generation)| {
                entries
                    .get(key)
                    .is_some_and(|entry| entry.generation == *generation)
            });
            self.hot_stale = 0;
        }
        if self.general_stale >= CACHE_ORDER_COMPACT_STALE_MIN {
            let entries = &self.entries;
            let order = &mut self.general_order;
            order.retain(|(key, generation)| {
                entries
                    .get(key)
                    .is_some_and(|entry| entry.generation == *generation)
            });
            self.general_stale = 0;
        }
    }
}

impl ReaderManager {
    fn clear_resources(&self) -> io::Result<(usize, usize, usize)> {
        let mut removed_entries = 0usize;
        let mut removed_bytes = 0usize;
        for shard in &self.cache_shards {
            let mut shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            removed_entries += shard.entries.len();
            removed_bytes += shard.hot_size + shard.general_size;
            shard.entries.clear();
            shard.by_identity.clear();
            shard.hot_order.clear();
            shard.general_order.clear();
            shard.hot_size = 0;
            shard.general_size = 0;
            shard.hot_stale = 0;
            shard.general_stale = 0;
            shard.generation = 0;
        }
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        let removed_handles = handles.entries.len();
        let sources = handles
            .entries
            .drain()
            .map(|(_identity, entry)| entry.source)
            .collect::<Vec<_>>();
        handles.by_path.clear();
        handles.order.clear();
        drop(handles);
        for source in sources {
            source.close()?;
        }
        Ok((removed_handles, removed_entries, removed_bytes))
    }

    fn release_resources_under_roots(
        &self,
        roots: &[PathBuf],
    ) -> io::Result<(usize, usize, usize)> {
        if roots.is_empty() {
            return Ok((0, 0, 0));
        }

        let mut removed_entries = 0usize;
        let mut removed_bytes = 0usize;
        for shard in &self.cache_shards {
            let mut shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            let identities = shard
                .by_identity
                .keys()
                .filter(|identity| path_is_under_roots(&identity.path, roots))
                .cloned()
                .collect::<Vec<_>>();
            for identity in identities {
                let indices = shard
                    .by_identity
                    .get(&identity)
                    .map(|indices| indices.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                for index in indices {
                    let key = BlockKey {
                        identity: identity.clone(),
                        index,
                    };
                    if let Some(entry) = shard.remove_entry(&key, true) {
                        removed_entries += 1;
                        removed_bytes += entry.data.len();
                    }
                }
            }
            shard.compact_stale_orders();
        }
        let removed_handles = self.release_handles_under_roots(roots)?;
        Ok((removed_handles, removed_entries, removed_bytes))
    }

    fn release_handles_under(&self, root: &Path) -> io::Result<usize> {
        self.release_handles_under_roots(&[root.to_path_buf()])
    }

    fn release_handles_under_roots(&self, roots: &[PathBuf]) -> io::Result<usize> {
        if roots.is_empty() {
            return Ok(0);
        }

        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        let identities = handles
            .entries
            .keys()
            .filter(|identity| path_is_under_roots(&identity.path, roots))
            .cloned()
            .collect::<HashSet<_>>();
        let mut sources = Vec::with_capacity(identities.len());
        for identity in &identities {
            if let Some(entry) = handles.entries.remove(identity) {
                sources.push(entry.source);
            }
            if handles.by_path.get(&identity.path) == Some(identity) {
                handles.by_path.remove(&identity.path);
            }
        }
        handles
            .order
            .retain(|(identity, _generation)| !identities.contains(identity));
        drop(handles);
        for source in sources {
            source.close()?;
        }
        Ok(identities.len())
    }

    fn open_file(&self, path: &Path) -> io::Result<Arc<FileSource>> {
        let metadata = std::fs::metadata(path)?;
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        {
            let mut handles = self
                .handles
                .lock()
                .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
            if let Some(identity) = handles.by_path.get(&canonical).cloned() {
                if identity.len == metadata.len() && identity.modified == metadata.modified().ok() {
                    if let Some(source) = handles.touch(&identity) {
                        self.metrics.handle_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(source);
                    }
                } else {
                    handles.by_path.remove(&canonical);
                }
            }
        }
        let file = open_reader_file(path)?;
        let metadata = file.metadata()?;
        let identity = file_identity(canonical, &metadata);
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        if let Some(existing) = handles.touch(&identity) {
            self.metrics.handle_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(existing);
        }
        let source = Arc::new(FileSource {
            identity: identity.clone(),
            file: RwLock::new(Some(file)),
            closed: AtomicBool::new(false),
            block_loads: Mutex::new(HashMap::new()),
        });
        handles.insert(identity, Arc::clone(&source));
        self.metrics.opens.fetch_add(1, Ordering::Relaxed);
        Ok(source)
    }

    fn claim_block_load(&self, source: &FileSource, index: u64) -> io::Result<BlockLoadClaim> {
        let key = BlockKey {
            identity: source.identity.clone(),
            index,
        };
        let mut loads = source
            .block_loads
            .lock()
            .map_err(|_| io::Error::other("reader block-load lock poisoned"))?;

        // Recheck the cache while holding the load registry. A loader publishes
        // the block before removing its registry entry, so this closes the
        // cache-check/claim race without holding any lock across physical I/O.
        if self.contains_block(&key)? {
            return Ok(BlockLoadClaim::Cached);
        }
        if let Some(load) = loads.get(&index) {
            return Ok(BlockLoadClaim::Waiting(Arc::clone(load)));
        }

        let load = Arc::new(BlockLoad::new());
        loads.insert(index, Arc::clone(&load));
        Ok(BlockLoadClaim::Owned(load))
    }

    fn finish_block_load(
        &self,
        source: &FileSource,
        index: u64,
        load: &Arc<BlockLoad>,
    ) -> io::Result<()> {
        let mut loads = match source.block_loads.lock() {
            Ok(loads) => loads,
            Err(_) => {
                load.finish();
                return Err(io::Error::other("reader block-load lock poisoned"));
            }
        };
        if loads
            .get(&index)
            .is_some_and(|current| Arc::ptr_eq(current, load))
        {
            loads.remove(&index);
        }
        // Keep the registry locked until waiters are notified so a failed load
        // cannot be immediately re-observed as the same completed entry.
        load.finish();
        Ok(())
    }

    fn finish_block_loads(
        &self,
        source: &FileSource,
        loads_to_finish: &[(u64, Arc<BlockLoad>)],
    ) -> io::Result<()> {
        let mut loads = match source.block_loads.lock() {
            Ok(loads) => loads,
            Err(_) => {
                for (_, load) in loads_to_finish {
                    load.finish();
                }
                return Err(io::Error::other("reader block-load lock poisoned"));
            }
        };
        for (index, load) in loads_to_finish {
            if loads
                .get(index)
                .is_some_and(|current| Arc::ptr_eq(current, load))
            {
                loads.remove(index);
            }
        }
        for (_, load) in loads_to_finish {
            load.finish();
        }
        Ok(())
    }

    fn read_block(&self, source: &FileSource, index: u64) -> io::Result<Arc<[u8]>> {
        let key = BlockKey {
            identity: source.identity.clone(),
            index,
        };
        let tier = cache_tier(source, index);

        loop {
            if let Some(block) = self.cached_block(&key, tier)? {
                return Ok(block);
            }

            match self.claim_block_load(source, index)? {
                BlockLoadClaim::Cached => continue,
                BlockLoadClaim::Waiting(load) => {
                    load.wait()?;
                    continue;
                }
                BlockLoadClaim::Owned(load) => {
                    self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                    let offset = index * BLOCK_SIZE as u64;
                    let len = BLOCK_SIZE.min(source.len().saturating_sub(offset) as usize);
                    let result = source
                        .with_file(|file| read_file_at(file, offset, len, &self.metrics))
                        .and_then(|data| {
                            self.insert_block(key.clone(), Arc::from(data), tier)
                        });
                    let finish_result = self.finish_block_load(source, index, &load);
                    return match result {
                        Ok(data) => {
                            finish_result?;
                            Ok(data)
                        }
                        Err(error) => {
                            let _ = finish_result;
                            Err(error)
                        }
                    };
                }
            }
        }
    }

    /// Loads adjacent missing blocks with one positional read. Batch prefetch
    /// shares the same per-block load registry as `read_block`: this caller
    /// claims only blocks that are not already cached or being loaded, merges
    /// adjacent claimed blocks into range reads, and waits for overlapping
    /// claims after its independent I/O has completed.
    fn prefetch_blocks(&self, source: &FileSource, mut blocks: Vec<u64>) -> io::Result<()> {
        blocks.sort_unstable();
        blocks.dedup();

        let mut owned = Vec::with_capacity(blocks.len());
        let mut waiting = Vec::new();
        for index in blocks {
            match self.claim_block_load(source, index) {
                Ok(BlockLoadClaim::Cached) => {}
                Ok(BlockLoadClaim::Owned(load)) => owned.push((index, load)),
                Ok(BlockLoadClaim::Waiting(load)) => waiting.push((index, load)),
                Err(error) => {
                    let _ = self.finish_block_loads(source, &owned);
                    return Err(error);
                }
            }
        }

        let max_blocks = (MAX_CACHEABLE_READ_BYTES / BLOCK_SIZE).max(1);
        let mut cursor = 0usize;
        while cursor < owned.len() {
            let range_start = cursor;
            let start = owned[cursor].0;
            cursor += 1;
            while cursor < owned.len()
                && owned[cursor].0 == owned[cursor - 1].0 + 1
                && cursor - range_start < max_blocks
            {
                cursor += 1;
            }
            let end = owned[cursor - 1].0;
            let offset = start * BLOCK_SIZE as u64;
            let requested = ((end - start + 1) * BLOCK_SIZE as u64)
                .min(source.len().saturating_sub(offset)) as usize;

            let data = match source
                .with_file(|file| read_file_at(file, offset, requested, &self.metrics))
            {
                Ok(data) => data,
                Err(error) => {
                    let _ = self.finish_block_loads(source, &owned[range_start..]);
                    return Err(error);
                }
            };
            self.metrics
                .cache_misses
                .fetch_add(end - start + 1, Ordering::Relaxed);

            for index in start..=end {
                let from = ((index - start) * BLOCK_SIZE as u64) as usize;
                if from >= data.len() {
                    break;
                }
                let to = (from + BLOCK_SIZE).min(data.len());
                let key = BlockKey {
                    identity: source.identity.clone(),
                    index,
                };
                if let Err(error) =
                    self.insert_block(key, Arc::from(&data[from..to]), cache_tier(source, index))
                {
                    let _ = self.finish_block_loads(source, &owned[range_start..]);
                    return Err(error);
                }
            }

            if let Err(error) = self.finish_block_loads(source, &owned[range_start..cursor]) {
                let _ = self.finish_block_loads(source, &owned[cursor..]);
                return Err(error);
            }
        }

        for (index, load) in waiting {
            load.wait()?;
            let key = BlockKey {
                identity: source.identity.clone(),
                index,
            };
            if !self.contains_block(&key)? {
                // The overlapping loader failed before publishing. Retry this
                // block through the normal path so prefetch keeps its
                // synchronous "ready on success" contract.
                self.read_block(source, index)?;
            }
        }
        Ok(())
    }

    fn contains_block(&self, key: &BlockKey) -> io::Result<bool> {
        let shard_index = cache_shard_index(key);
        let shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        Ok(shard.entries.contains_key(key))
    }

    fn cached_block(&self, key: &BlockKey, tier: CacheTier) -> io::Result<Option<Arc<[u8]>>> {
        let shard_index = cache_shard_index(key);
        let shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        let block = shard
            .entries
            .get(key)
            .map(|entry| Arc::clone(&entry.data));
        if block.is_some() {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            if matches!(tier, CacheTier::Hot) {
                self.metrics.hot_cache_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(block)
    }

    fn insert_block(
        &self,
        key: BlockKey,
        data: Arc<[u8]>,
        tier: CacheTier,
    ) -> io::Result<Arc<[u8]>> {
        let shard_index = cache_shard_index(&key);
        let mut shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        if let Some(existing) = shard.entries.get(&key) {
            return Ok(Arc::clone(&existing.data));
        }

        shard.generation = shard.generation.wrapping_add(1);
        let generation = shard.generation;
        shard
            .by_identity
            .entry(key.identity.clone())
            .or_default()
            .insert(key.index);
        shard.entries.insert(
            key.clone(),
            CacheEntry {
                data: Arc::clone(&data),
                tier,
                generation,
            },
        );
        match tier {
            CacheTier::Hot => {
                shard.hot_size += data.len();
                shard.hot_order.push_back((key, generation));
                while shard.hot_size > shard.hot_capacity {
                    let Some((old_key, old_generation)) = shard.hot_order.pop_front() else {
                        break;
                    };
                    let current_generation = shard
                        .entries
                        .get(&old_key)
                        .map(|entry| entry.generation);
                    if current_generation != Some(old_generation) {
                        shard.hot_stale = shard.hot_stale.saturating_sub(1);
                        continue;
                    }
                    if shard.remove_entry(&old_key, false).is_some() {
                        self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            CacheTier::General => {
                shard.general_size += data.len();
                shard.general_order.push_back((key, generation));
                while shard.general_size > shard.general_capacity {
                    let Some((old_key, old_generation)) = shard.general_order.pop_front() else {
                        break;
                    };
                    let current_generation = shard
                        .entries
                        .get(&old_key)
                        .map(|entry| entry.generation);
                    if current_generation != Some(old_generation) {
                        shard.general_stale = shard.general_stale.saturating_sub(1);
                        continue;
                    }
                    if shard.remove_entry(&old_key, false).is_some() {
                        self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(data)
    }

    fn cache_totals(&self) -> io::Result<(usize, usize, usize)> {
        let mut entries = 0usize;
        let mut hot_bytes = 0usize;
        let mut general_bytes = 0usize;
        for shard in &self.cache_shards {
            let shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            entries += shard.entries.len();
            hot_bytes += shard.hot_size;
            general_bytes += shard.general_size;
        }
        Ok((entries, hot_bytes, general_bytes))
    }
}

impl HandlePool {
    fn touch(&mut self, identity: &FileIdentity) -> Option<Arc<FileSource>> {
        let source = Arc::clone(&self.entries.get(identity)?.source);
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.entries.get_mut(identity)?.generation = generation;
        self.order.push_back((identity.clone(), generation));
        Some(source)
    }

    fn insert(&mut self, identity: FileIdentity, source: Arc<FileSource>) {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.by_path.insert(identity.path.clone(), identity.clone());
        self.entries
            .insert(identity.clone(), HandleEntry { source, generation });
        self.order.push_back((identity, generation));
        while self.entries.len() > self.capacity {
            let Some((old_identity, old_generation)) = self.order.pop_front() else {
                break;
            };
            let current = self
                .entries
                .get(&old_identity)
                .map(|entry| entry.generation);
            if current != Some(old_generation) {
                continue;
            }
            self.entries.remove(&old_identity);
            if self.by_path.get(&old_identity.path) == Some(&old_identity) {
                self.by_path.remove(&old_identity.path);
            }
        }
    }
}

fn path_is_under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

fn canonical_release_roots(paths: &[String]) -> Vec<PathBuf> {
    let mut roots = paths
        .iter()
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
        })
        .collect::<Vec<_>>();
    roots.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    roots.dedup();

    let mut merged: Vec<PathBuf> = Vec::with_capacity(roots.len());
    for root in roots {
        if merged.iter().any(|parent| root.starts_with(parent)) {
            continue;
        }
        merged.push(root);
    }
    merged
}

fn cache_shard_index(key: &BlockKey) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize & (CACHE_SHARDS - 1)
}

fn cache_tier(source: &FileSource, index: u64) -> CacheTier {
    let offset = index * BLOCK_SIZE as u64;
    if offset < HOT_EDGE_BYTES
        || offset.saturating_add(BLOCK_SIZE as u64) >= source.len().saturating_sub(HOT_EDGE_BYTES)
    {
        CacheTier::Hot
    } else {
        CacheTier::General
    }
}

#[pyfunction]
pub(crate) fn reader_cache_stats(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let manager = manager();
    let (entries, hot_bytes, general_bytes) = manager.cache_totals()?;
    let handles = manager
        .handles
        .lock()
        .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?
        .entries
        .len();
    let dict = PyDict::new(py);
    dict.set_item(
        "logical_bytes",
        manager.metrics.logical_bytes.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "physical_bytes",
        manager.metrics.physical_bytes.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "physical_reads",
        manager.metrics.physical_reads.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "cache_hits",
        manager.metrics.cache_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "hot_cache_hits",
        manager.metrics.hot_cache_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "cache_misses",
        manager.metrics.cache_misses.load(Ordering::Relaxed),
    )?;
    dict.set_item(
        "handle_hits",
        manager.metrics.handle_hits.load(Ordering::Relaxed),
    )?;
    dict.set_item("opens", manager.metrics.opens.load(Ordering::Relaxed))?;
    dict.set_item(
        "evictions",
        manager.metrics.evictions.load(Ordering::Relaxed),
    )?;
    dict.set_item("cache_entries", entries)?;
    dict.set_item("hot_cache_bytes", hot_bytes)?;
    dict.set_item("general_cache_bytes", general_bytes)?;
    dict.set_item("open_handles", handles)?;
    dict.set_item("cache_shards", CACHE_SHARDS)?;
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn clear_reader_resources(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let (handles, cache_entries, cache_bytes) = manager().clear_resources()?;
    let dict = PyDict::new(py);
    dict.set_item("handles", handles)?;
    dict.set_item("cache_entries", cache_entries)?;
    dict.set_item("cache_bytes", cache_bytes)?;
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn release_reader_handles_under(path: &str) -> PyResult<usize> {
    let root = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    Ok(manager().release_handles_under(&root)?)
}

#[pyfunction]
pub(crate) fn release_reader_resources_under_roots(
    py: Python<'_>,
    paths: Vec<String>,
) -> PyResult<Py<PyDict>> {
    let roots = canonical_release_roots(&paths);
    let (handles, cache_entries, cache_bytes) = manager().release_resources_under_roots(&roots)?;
    let dict = PyDict::new(py);
    dict.set_item("handles", handles)?;
    dict.set_item("cache_entries", cache_entries)?;
    dict.set_item("cache_bytes", cache_bytes)?;
    Ok(dict.unbind())
}

fn manager() -> &'static ReaderManager {
    static MANAGER: OnceLock<ReaderManager> = OnceLock::new();
    MANAGER.get_or_init(|| {
        let shard_capacity = DEFAULT_SHARED_CACHE_BYTES / CACHE_SHARDS;
        let hot_capacity = shard_capacity / HOT_CACHE_FRACTION;
        let cache_shards = (0..CACHE_SHARDS)
            .map(|_| {
                Mutex::new(CacheShard {
                    entries: HashMap::new(),
                    by_identity: HashMap::new(),
                    hot_order: VecDeque::new(),
                    general_order: VecDeque::new(),
                    hot_size: 0,
                    general_size: 0,
                    hot_stale: 0,
                    general_stale: 0,
                    generation: 0,
                    hot_capacity,
                    general_capacity: shard_capacity - hot_capacity,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ReaderManager {
            handles: Mutex::new(HandlePool {
                entries: HashMap::new(),
                by_path: HashMap::new(),
                order: VecDeque::new(),
                generation: 0,
                capacity: DEFAULT_HANDLE_CAPACITY,
            }),
            cache_shards,
            metrics: ManagerMetrics::default(),
        }
    })
}

fn file_identity(path: PathBuf, metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        path,
        len: metadata.len(),
        modified: metadata.modified().ok(),
    }
}

fn read_file_at(
    file: &File,
    offset: u64,
    len: usize,
    metrics: &ManagerMetrics,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        metrics.physical_reads.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        THREAD_PHYSICAL_READS.with(|reads| reads.set(reads.get() + 1));
        let count = positional_read(file, &mut data[read..], offset + read as u64)?;
        if count == 0 {
            data.truncate(read);
            break;
        }
        read += count;
    }
    metrics
        .physical_bytes
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    Ok(data)
}

fn open_reader_file(path: &Path) -> io::Result<TrackedFile> {
    TrackedFile::open_reader(path, "reader_file")
}

#[cfg(unix)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    #[test]
    fn short_and_exact_reads_preserve_eof_semantics() {
        let path = temp_file("managed_reader_eof", b"abcdef");
        let reader = ManagedReader::open(&path).unwrap();
        assert_eq!(reader.read_at(4, 8).unwrap(), b"ef");
        assert_eq!(
            reader.read_exact_at(4, 8).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(reader.stats().unwrap().read_bytes, 4);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn field_read_preserves_exact_short_read_diagnostics() {
        let path = temp_file("managed_reader_field_eof", b"abcdef");
        let reader = ManagedReader::open(&path).unwrap();
        let fault = reader
            .read_exact_field_at(4, 8, "zip.eocd", FieldLocation::Tail)
            .unwrap_err();
        assert_eq!(fault.code, "unexpected_eof");
        assert_eq!(fault.field, "zip.eocd");
        assert_eq!(fault.offset, 4);
        assert_eq!(fault.requested, 8);
        assert_eq!(fault.actual, 2);
        assert_eq!(fault.source_len, 6);
        assert!(fault.possible_missing_volume());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_cache_preserves_budget_and_hit_stats() {
        let path = temp_file("managed_reader_stats", b"abcdefgh");
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: 8,
                max_read_bytes: Some(4),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();
        assert_eq!(reader.read_at(0, 4).unwrap(), b"abcd");
        assert_eq!(reader.read_at(0, 4).unwrap(), b"abcd");
        assert!(reader.read_at(4, 1).is_err());
        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 4);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_into_preserves_request_cache_and_budget_semantics() {
        let path = temp_file("managed_reader_into_stats", b"abcdefgh");
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: 8,
                max_read_bytes: Some(4),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();
        let mut buffer = [0u8; 4];
        assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"abcd");
        buffer.fill(0);
        assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"abcd");
        assert!(reader.read_into_at(4, &mut buffer[..1]).is_err());
        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 4);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_cache_reuses_shared_backing_without_payload_copy() {
        let mut source = vec![0u8; BLOCK_SIZE + 1];
        source[..8].copy_from_slice(b"abcdefgh");
        let path = temp_file("managed_reader_shared_request", &source);
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: BLOCK_SIZE,
                max_read_bytes: Some(8),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();

        let before = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
        let first = reader.read_cached_at(0, 4).unwrap();
        let second = reader.read_cached_at(0, 4).unwrap();
        let after = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);

        let (CachedBytes::Slice(first), CachedBytes::Slice(second)) = (first, second) else {
            panic!("request cache should return shared slices");
        };
        assert_eq!(&*first, b"abcd");
        assert_eq!(&*second, b"abcd");
        assert!(first.shares_backing(&second));
        assert_eq!(after - before, 0);

        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 4);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_cache_capacity_accounts_for_retained_shared_block() {
        let mut source = vec![0u8; BLOCK_SIZE + 1];
        source[..8].copy_from_slice(b"abcdefgh");
        let path = temp_file("managed_reader_shared_capacity", &source);
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: BLOCK_SIZE - 1,
                max_read_bytes: Some(8),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();

        assert_eq!(&*reader.read_cached_at(0, 4).unwrap(), b"abcd");
        assert_eq!(&*reader.read_cached_at(0, 4).unwrap(), b"abcd");
        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 8);
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(reader.lock_inner().unwrap().cache_size, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shared_slice_remains_valid_after_request_cache_eviction() {
        let mut source = vec![0u8; BLOCK_SIZE * 2];
        source[..4].copy_from_slice(b"keep");
        source[BLOCK_SIZE..BLOCK_SIZE + 4].copy_from_slice(b"next");
        let path = temp_file("managed_reader_shared_eviction", &source);
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: BLOCK_SIZE,
                max_read_bytes: Some(8),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();

        let first = reader.read_cached_at(0, 4).unwrap();
        assert_eq!(&*first, b"keep");
        let second = reader.read_cached_at(BLOCK_SIZE as u64, 4).unwrap();
        assert_eq!(&*second, b"next");
        assert_eq!(&*first, b"keep");
        assert!(reader.lock_inner().unwrap().cache_size <= BLOCK_SIZE);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shared_request_data_survives_file_resource_release() {
        let mut source = vec![0u8; BLOCK_SIZE + 1];
        source[..7].copy_from_slice(b"payload");
        let path = temp_file("managed_reader_shared_release", &source);
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes: BLOCK_SIZE,
                max_read_bytes: Some(8),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();

        let data = reader.read_cached_at(0, 7).unwrap();
        let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let (handles, entries, _) = manager()
            .release_resources_under_roots(&[canonical])
            .unwrap();
        assert!(handles >= 1);
        assert!(entries >= 1);
        assert_eq!(&*data, b"payload");

        drop(reader);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn batched_release_removes_only_indexed_file_identities() {
        let first_path = temp_file("managed_reader_release_first", b"abcdefgh");
        let second_path = temp_file("managed_reader_release_second", b"ijklmnop");
        let other_path = temp_file("managed_reader_release_other", b"qrstuvwx");

        let first = manager().open_file(&first_path).unwrap();
        let second = manager().open_file(&second_path).unwrap();
        let other = manager().open_file(&other_path).unwrap();
        assert_eq!(first.read_at(0, 8).unwrap(), b"abcdefgh");
        assert_eq!(second.read_at(0, 8).unwrap(), b"ijklmnop");
        assert_eq!(other.read_at(0, 8).unwrap(), b"qrstuvwx");

        let first_key = BlockKey {
            identity: first.identity.clone(),
            index: 0,
        };
        let second_key = BlockKey {
            identity: second.identity.clone(),
            index: 0,
        };
        let other_key = BlockKey {
            identity: other.identity.clone(),
            index: 0,
        };
        assert!(manager().contains_block(&first_key).unwrap());
        assert!(manager().contains_block(&second_key).unwrap());
        assert!(manager().contains_block(&other_key).unwrap());

        let roots = vec![
            std::fs::canonicalize(&first_path).unwrap_or_else(|_| first_path.clone()),
            std::fs::canonicalize(&second_path).unwrap_or_else(|_| second_path.clone()),
        ];
        let (handles, entries, bytes) = manager()
            .release_resources_under_roots(&roots)
            .unwrap();

        assert_eq!(handles, 2);
        assert_eq!(entries, 2);
        assert_eq!(bytes, 16);
        assert!(!manager().contains_block(&first_key).unwrap());
        assert!(!manager().contains_block(&second_key).unwrap());
        assert!(manager().contains_block(&other_key).unwrap());
        assert_eq!(other.read_at(0, 8).unwrap(), b"qrstuvwx");

        let other_root =
            std::fs::canonicalize(&other_path).unwrap_or_else(|_| other_path.clone());
        manager()
            .release_resources_under_roots(&[other_root])
            .unwrap();
        let _ = std::fs::remove_file(first_path);
        let _ = std::fs::remove_file(second_path);
        let _ = std::fs::remove_file(other_path);
    }

    #[test]
    fn request_cache_coalesces_cross_volume_data_once() {
        let first_path = temp_file("managed_reader_shared_part1", b"abc");
        let second_path = temp_file("managed_reader_shared_part2", b"def");
        let paths = vec![
            first_path.to_string_lossy().into_owned(),
            second_path.to_string_lossy().into_owned(),
        ];
        let reader = ManagedReader::open_volumes(
            &paths,
            ReaderConfig {
                cache_bytes: 16,
                max_read_bytes: Some(16),
                max_concurrent_reads: 1,
            },
        )
        .unwrap();

        let before = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
        let first = reader.read_cached_at(2, 3).unwrap();
        let middle = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
        let second = reader.read_cached_at(2, 3).unwrap();
        let after = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);

        let (CachedBytes::Slice(first), CachedBytes::Slice(second)) = (first, second) else {
            panic!("cross-volume request should be cached as one shared slice");
        };
        assert_eq!(&*first, b"cde");
        assert_eq!(&*second, b"cde");
        assert!(first.shares_backing(&second));
        assert_eq!(middle - before, 1);
        assert_eq!(after - middle, 0);

        let stats = reader.stats().unwrap();
        assert_eq!(stats.read_bytes, 3);
        assert_eq!(stats.cache_hits, 1);
        let _ = std::fs::remove_file(first_path);
        let _ = std::fs::remove_file(second_path);
    }

    #[test]
    fn multi_volume_reads_across_boundary() {
        let first = temp_file("managed_reader_part1", b"abc");
        let second = temp_file("managed_reader_part2", b"def");
        let paths = vec![
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ];
        let reader = ManagedReader::open_volumes(&paths, ReaderConfig::default()).unwrap();
        assert_eq!(reader.read_at(2, 3).unwrap(), b"cde");
        let mut cursor = reader.cursor();
        cursor.seek(SeekFrom::Start(2)).unwrap();
        let mut data = [0u8; 3];
        cursor.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"cde");
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn readers_share_file_handle_and_block_cache() {
        let path = temp_file("managed_reader_shared", b"abcdefgh");
        let first = manager().open_file(&path).unwrap();
        assert_eq!(first.read_at(0, 4).unwrap(), b"abcd");
        let key = BlockKey {
            identity: first.identity.clone(),
            index: 0,
        };
        assert!(manager()
            .cached_block(&key, cache_tier(&first, 0))
            .unwrap()
            .is_some());
        let second = manager().open_file(&path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.read_at(2, 4).unwrap(), b"cdef");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn handle_pool_keeps_recent_file_source_alive_between_readers() {
        let path = temp_file("managed_reader_handle_pool", b"abcdefgh");
        let first = manager().open_file(&path).unwrap();
        let first_ptr = Arc::as_ptr(&first);
        drop(first);
        let second = manager().open_file(&path).unwrap();
        assert_eq!(first_ptr, Arc::as_ptr(&second));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn batched_handle_release_includes_entries_missing_from_current_path_index() {
        let path = temp_file("managed_reader_stale_handle_path", b"abcdefgh");
        let source = manager().open_file(&path).unwrap();
        let canonical = source.identity.path.clone();

        {
            let mut handles = manager().handles.lock().unwrap();
            assert_eq!(handles.by_path.remove(&canonical), Some(source.identity.clone()));
            assert!(handles.entries.contains_key(&source.identity));
        }

        let released = manager()
            .release_handles_under_roots(&[canonical])
            .unwrap();

        assert_eq!(released, 1);
        assert!(source.closed.load(Ordering::Acquire));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_slices_and_batch_reads_preserve_requested_bytes() {
        let data = vec![0x5au8; BLOCK_SIZE + 32];
        let path = temp_file("managed_reader_slices", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let slices = reader.read_slices_at(BLOCK_SIZE as u64 - 8, 16).unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices.iter().map(|slice| slice.len()).sum::<usize>(), 16);
        let cached = reader.read_cached_at(4, 8).unwrap();
        assert!(matches!(cached, CachedBytes::Slice(_)));
        assert_eq!(&*cached, &[0x5a; 8]);
        let many = reader.read_many(&[(0, 4), (BLOCK_SIZE as u64, 4)]).unwrap();
        assert_eq!(many, vec![vec![0x5a; 4], vec![0x5a; 4]]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn batch_prefetch_coalesces_adjacent_blocks_into_one_physical_read() {
        let data = vec![0x6bu8; BLOCK_SIZE * 3];
        let path = temp_file("managed_reader_batch_prefetch", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);

        let ranges = [(BLOCK_SIZE as u64 - 4, 8), ((BLOCK_SIZE * 2) as u64 - 4, 8)];
        let many = reader.read_many(&ranges).unwrap();
        let after = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);

        assert_eq!(many, vec![vec![0x6b; 8], vec![0x6b; 8]]);
        assert_eq!(after - before, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn batch_prefetch_skips_inflight_blocks_without_blocking_independent_ranges() {
        let data = vec![0x7cu8; BLOCK_SIZE * 3];
        let path = temp_file("managed_reader_batch_overlap", &data);
        let source = manager().open_file(&path).unwrap();

        let blocked_load = match manager().claim_block_load(&source, 1).unwrap() {
            BlockLoadClaim::Owned(load) => load,
            _ => panic!("test block should be newly claimed"),
        };

        let worker_source = Arc::clone(&source);
        let handle = std::thread::spawn(move || {
            let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
            worker_source
                .prefetch(&[(0, BLOCK_SIZE * 3)])
                .unwrap();
            let after = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
            after - before
        });

        let first_key = BlockKey {
            identity: source.identity.clone(),
            index: 0,
        };
        let third_key = BlockKey {
            identity: source.identity.clone(),
            index: 2,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let first_ready = manager().contains_block(&first_key).unwrap();
            let third_ready = manager().contains_block(&third_key).unwrap();
            if first_ready && third_ready {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "independent prefetch ranges were serialized behind an overlapping block"
            );
            std::thread::yield_now();
        }

        let offset = BLOCK_SIZE as u64;
        let block = source
            .with_file(|file| read_file_at(file, offset, BLOCK_SIZE, &manager().metrics))
            .unwrap();
        let blocked_key = BlockKey {
            identity: source.identity.clone(),
            index: 1,
        };
        manager()
            .insert_block(blocked_key, Arc::from(block), cache_tier(&source, 1))
            .unwrap();
        manager()
            .finish_block_load(&source, 1, &blocked_load)
            .unwrap();

        assert_eq!(handle.join().unwrap(), 2);
        assert!(source.block_loads.lock().unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_block_shares_an_existing_batch_load() {
        let data = vec![0x4du8; BLOCK_SIZE];
        let path = temp_file("managed_reader_read_overlap", &data);
        let source = manager().open_file(&path).unwrap();

        let load = match manager().claim_block_load(&source, 0).unwrap() {
            BlockLoadClaim::Owned(load) => load,
            _ => panic!("test block should be newly claimed"),
        };

        let worker_source = Arc::clone(&source);
        let handle = std::thread::spawn(move || {
            let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
            let block = manager().read_block(&worker_source, 0).unwrap();
            let after = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
            (block, after - before)
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while Arc::strong_count(&load) < 3 {
            assert!(
                std::time::Instant::now() < deadline,
                "reader did not join the existing block load"
            );
            std::thread::yield_now();
        }

        let block = source
            .with_file(|file| read_file_at(file, 0, BLOCK_SIZE, &manager().metrics))
            .unwrap();
        let key = BlockKey {
            identity: source.identity.clone(),
            index: 0,
        };
        manager()
            .insert_block(key, Arc::from(block), cache_tier(&source, 0))
            .unwrap();
        manager().finish_block_load(&source, 0, &load).unwrap();

        let (block, worker_reads) = handle.join().unwrap();
        assert_eq!(worker_reads, 0);
        assert_eq!(block.len(), BLOCK_SIZE);
        assert!(block.iter().all(|byte| *byte == 0x4d));
        assert!(source.block_loads.lock().unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_batch_prefetch_releases_claimed_blocks() {
        let data = vec![0x31u8; BLOCK_SIZE * 2];
        let path = temp_file("managed_reader_prefetch_error_cleanup", &data);
        let source = manager().open_file(&path).unwrap();
        source.close().unwrap();

        assert!(manager()
            .prefetch_blocks(&source, vec![0, 1])
            .is_err());
        assert!(source.block_loads.lock().unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn changed_file_gets_a_new_identity() {
        let path = temp_file("managed_reader_identity", b"old");
        let first = ManagedReader::open(&path).unwrap();
        assert_eq!(first.read_all().unwrap(), b"old");
        std::fs::write(&path, b"new-data").unwrap();
        let second = ManagedReader::open(&path).unwrap();
        assert_eq!(second.read_all().unwrap(), b"new-data");
        let _ = std::fs::remove_file(path);
    }
}
