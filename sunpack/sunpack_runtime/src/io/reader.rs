use crate::io::cancellation::Cancellation;
use crate::io::read_fault::ReadFault;
use crate::io::resource_lifecycle::TrackedFile;
use crate::password::attempts::AttemptCache;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::SystemTime;

#[cfg(test)]
thread_local! {
    static THREAD_PHYSICAL_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static THREAD_REQUEST_COALESCES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

const BLOCK_SIZE: usize = 64 * 1024;
const DEFAULT_SHARED_CACHE_BYTES: usize = 256 * 1024 * 1024;
const CACHE_SHARDS: usize = u64::BITS as usize;
const HOT_CACHE_FRACTION: usize = 4;
const HOT_EDGE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CACHEABLE_READ_BYTES: usize = 4 * 1024 * 1024;
const CACHE_ORDER_COMPACT_STALE_MIN: usize = 64;
static NEXT_SOURCE_ID: AtomicU64 = AtomicU64::new(1);

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
        match &self.data {
            CachedBacking::Shared(data) => data.len(),
            CachedBacking::Owned(data) => data.capacity(),
        }
    }

    fn slice(&self, start: usize, len: usize) -> Self {
        Self {
            data: self.data.clone(),
            start: self.start + start,
            end: self.start + start + len,
        }
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
    fn hint_probe_window(&self, _offset: u64) {}
    fn validate_cached_range(&self, _offset: u64, _len: usize) -> io::Result<()> {
        Ok(())
    }
    fn file_identity(&self) -> Option<FileIdentity> {
        None
    }
    fn physical_generation(&self) -> Option<&PhysicalFileGeneration> {
        None
    }
    fn attempt_cache(&self) -> Option<&AttemptCache> {
        None
    }
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

#[derive(Clone, Debug, Default)]
pub(crate) struct ReaderConfig {
    pub(crate) cache_bytes: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReaderStats {
    pub(crate) read_bytes: u64,
    pub(crate) direct_read_bytes: u64,
    pub(crate) cache_hits: u64,
}

#[derive(Clone)]
pub(crate) struct ManagedReader {
    source: Arc<dyn ByteSource>,
    cache: Option<Arc<RequestCache>>,
    shared_blocks: bool,
    #[cfg(test)]
    counters: Arc<ReaderCounters>,
}

#[derive(Default)]
struct ProbeWindow {
    previous_hit: Option<u64>,
    read_ahead: bool,
    cached: Option<(u64, CachedSlice)>,
}

struct ProbeSource {
    reader: ManagedReader,
    window: Mutex<ProbeWindow>,
}

impl ByteSource for ProbeSource {
    fn len(&self) -> u64 {
        self.reader.len()
    }
    fn file_identity(&self) -> Option<FileIdentity> {
        self.reader.source.file_identity()
    }
    fn validate_cached_range(&self, offset: u64, len: usize) -> io::Result<()> {
        self.reader.source.validate_cached_range(offset, len)
    }
    fn hint_probe_window(&self, offset: u64) {
        if let Ok(mut window) = self.window.lock() {
            window.read_ahead = window.previous_hit.is_some_and(|previous| {
                previous != offset && previous / BLOCK_SIZE as u64 == offset / BLOCK_SIZE as u64
            });
            window.previous_hit = Some(offset);
        }
    }
    #[cfg(windows)]
    fn iocp_path(&self) -> Option<&Path> {
        self.reader.iocp_path()
    }
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let slices = self.read_slices_at(offset, len)?;
        let mut out =
            crate::io::resource_error::bytes_with_capacity(slices.iter().map(|s| s.len()).sum())?;
        for slice in slices {
            out.extend_from_slice(&slice);
        }
        Ok(out)
    }
    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        let read_len = len.min(self.len().saturating_sub(offset) as usize);
        if read_len != 0 && read_len <= BLOCK_SIZE {
            let mut window = self
                .window
                .lock()
                .map_err(|_| io::Error::other("probe window lock poisoned"))?;
            if let Some((start, data)) = &window.cached {
                if let Some(relative) = offset
                    .checked_sub(*start)
                    .and_then(|n| usize::try_from(n).ok())
                {
                    if relative <= data.len() && read_len <= data.len() - relative {
                        self.validate_cached_range(offset, read_len)?;
                        return Ok(vec![data.slice(relative, read_len)]);
                    }
                }
            }
            let block = offset / BLOCK_SIZE as u64;
            let start = block * BLOCK_SIZE as u64;
            // Only distinct nearby signature facts establish density. Several
            // fields of one sparse header must remain exact reads.
            if window.read_ahead
                && window
                    .previous_hit
                    .is_some_and(|hit| hit / BLOCK_SIZE as u64 == block)
                && read_len <= 512
                && offset - start + read_len as u64 <= BLOCK_SIZE as u64
            {
                let length = BLOCK_SIZE.min((self.len() - start) as usize);
                // Speculative faults/short reads outside the requested range
                // fall back to its original IO path, including split volumes.
                if let Ok(data) = self.reader.read_cached_at(start, length) {
                    let data = match data {
                        CachedBytes::Slice(data) => data,
                        CachedBytes::Owned(data) => CachedSlice::from_vec(data),
                    };
                    let relative = (offset - start) as usize;
                    if relative <= data.len() && read_len <= data.len() - relative {
                        let result = data.slice(relative, read_len);
                        window.cached = Some((start, data));
                        return Ok(vec![result]);
                    }
                }
            }
            // Reuse bulk reads as the single scan window without another
            // payload buffer. Tiny fields must not evict a wider window.
            let slices = self.reader.read_slices_at(offset, read_len)?;
            if read_len > 512 && slices.len() == 1 {
                window.cached = Some((offset, slices[0].clone()));
            }
            return Ok(slices);
        }
        self.reader.read_slices_at(offset, read_len)
    }
    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.len() > BLOCK_SIZE {
            return self.reader.read_into_at(offset, buffer);
        }
        let mut written = 0;
        for slice in self.read_slices_at(offset, buffer.len())? {
            buffer[written..written + slice.len()].copy_from_slice(&slice);
            written += slice.len();
        }
        Ok(written)
    }
    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read_direct_into_at(offset, buffer)
    }
}

struct RequestCache {
    capacity: usize,
    inner: Mutex<ReaderInner>,
}

impl RequestCache {
    fn lock(&self) -> io::Result<MutexGuard<'_, ReaderInner>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("managed reader lock poisoned"))
    }
}

#[cfg(test)]
#[derive(Default)]
struct ReaderCounters {
    read_bytes: AtomicU64,
    direct_read_bytes: AtomicU64,
    cache_hits: AtomicU64,
}

#[derive(Default)]
struct ReaderInner {
    cache: HashMap<(u64, usize), CachedSlice>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
}

impl ManagedReader {
    pub(crate) fn new(source: Arc<dyn ByteSource>, config: ReaderConfig) -> Self {
        Self {
            source,
            shared_blocks: true,
            cache: (config.cache_bytes > 0).then(|| {
                Arc::new(RequestCache {
                    capacity: config.cache_bytes,
                    inner: Mutex::default(),
                })
            }),
            #[cfg(test)]
            counters: Arc::default(),
        }
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

    #[cfg(test)]
    pub(crate) fn from_bytes(data: Vec<u8>, config: ReaderConfig) -> Self {
        let data: Arc<[u8]> = Arc::from(data);
        Self::new(Arc::new(BytesSource { data }), config)
    }

    /// One analysis borrows the same generation, budget and request
    /// cache. Its transient reads use the existing direct source path, so
    /// search/validation windows do not become process-wide retained blocks.
    pub(crate) fn probe_reader(&self) -> Self {
        let mut probe = self.clone();
        probe.shared_blocks = false;
        probe
    }

    pub(crate) fn windowed_probe_reader(&self) -> Self {
        Self::new(
            Arc::new(ProbeSource {
                reader: self.probe_reader(),
                window: Mutex::default(),
            }),
            ReaderConfig::default(),
        )
    }

    pub(crate) fn hint_probe_window(&self, offset: u64) {
        self.source.hint_probe_window(offset);
    }

    pub(crate) fn len(&self) -> u64 {
        self.source.len()
    }

    pub(crate) fn file_identity(&self) -> io::Result<FileIdentity> {
        self.source.file_identity().ok_or_else(|| {
            io::Error::other("password context requires a physical input generation")
        })
    }

    pub(crate) fn physical_generation(&self) -> Option<&PhysicalFileGeneration> {
        self.source.physical_generation()
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
        Cancellation::check_current_io()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if self.cache.is_none() {
            let result = if self.shared_blocks {
                self.source.read_at(offset, read_len)
            } else {
                self.source.read_direct_at(offset, read_len)
            };
            let data = result.map_err(|error| {
                ReadFault::physical("read_at", offset, read_len, 0, self.len(), &error)
                    .into_io_error()
            })?;
            #[cfg(test)]
            self.counters
                .read_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(data);
        }
        let cached = self.read_cached_at(offset, read_len)?;
        let mut data = crate::io::resource_error::bytes_with_capacity(cached.len())?;
        data.extend_from_slice(cached.as_slice());
        Ok(data)
    }

    /// One-shot bounded probes bypass the shared block cache while retaining
    /// the managed file handle and resource lifecycle.
    pub(crate) fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        Cancellation::check_current_io()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        let data = self.source.read_direct_at(offset, read_len)?;
        #[cfg(test)]
        self.counters
            .read_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data)
    }

    /// Reads through the shared cache directly into a caller-owned buffer.
    /// Without request state this remains the allocation-free `SourceCursor`
    /// hot path. With request state, the cache owns shared immutable data and
    /// this boundary performs only the required copy into the caller buffer.
    pub(crate) fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        Cancellation::check_current_io()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let read_len = buffer.len().min((self.len() - offset) as usize);
        if self.cache.is_none() {
            let result = if self.shared_blocks {
                self.source.read_into_at(offset, &mut buffer[..read_len])
            } else {
                self.source
                    .read_direct_into_at(offset, &mut buffer[..read_len])
            };
            let count = result.map_err(|error| {
                ReadFault::physical("read_into_at", offset, read_len, 0, self.len(), &error)
                    .into_io_error()
            })?;
            #[cfg(test)]
            self.counters
                .read_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            return Ok(count);
        }

        if let Some(cache) = self.cache.as_deref().filter(|cache| read_len <= cache.capacity) {
            let data = self.read_request_cached_slice_at(cache, offset, read_len)?;
            buffer[..data.len()].copy_from_slice(&data);
            return Ok(data.len());
        }

        let slices = self.read_source_slices_at(offset, read_len)?;
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

    #[cfg(test)]
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
        Cancellation::check_current_io()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let read_len = len.min((self.len() - offset) as usize);
        if let Some(cache) = self.cache.as_deref().filter(|cache| read_len <= cache.capacity) {
            return Ok(vec![self.read_request_cached_slice_at(cache, offset, read_len)?]);
        }
        self.read_source_slices_at(offset, read_len)
    }

    pub(crate) fn read_cached_at(&self, offset: u64, len: usize) -> io::Result<CachedBytes> {
        Cancellation::check_current_io()?;
        if offset >= self.len() || len == 0 {
            return Ok(CachedBytes::Owned(Vec::new()));
        }
        let read_len = len.min((self.len() - offset) as usize);
        if let Some(cache) = self.cache.as_deref().filter(|cache| read_len <= cache.capacity) {
            return Ok(CachedBytes::Slice(
                self.read_request_cached_slice_at(cache, offset, read_len)?,
            ));
        }

        let mut slices = self.read_source_slices_at(offset, read_len)?;
        if slices.len() == 1 {
            return Ok(CachedBytes::Slice(slices.remove(0)));
        }
        let total = slices.iter().map(|slice| slice.len()).sum();
        let mut data = crate::io::resource_error::bytes_with_capacity(total)?;
        for slice in slices {
            data.extend_from_slice(&slice);
        }
        Ok(CachedBytes::Owned(data))
    }

    fn read_request_cached_slice_at(
        &self,
        cache: &RequestCache,
        offset: u64,
        read_len: usize,
    ) -> io::Result<CachedSlice> {
        let key = (offset, read_len);
        {
            let inner = cache.lock()?;
            if let Some(data) = inner.cache.get(&key).cloned() {
                #[cfg(test)]
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(data);
            }
        }

        let slices = self.read_source_slices_at(offset, read_len)?;
        let data = coalesce_cached_slices(slices)?;
        cache.lock()?.store_cache_entry(key, data.clone(), cache.capacity);
        Ok(data)
    }

    fn read_source_slices_at(
        &self,
        offset: u64,
        read_len: usize,
    ) -> io::Result<Vec<CachedSlice>> {
        let slices = self.source_slices_at(offset, read_len).map_err(|error| {
            ReadFault::physical("read_slices_at", offset, read_len, 0, self.len(), &error)
                .into_io_error()
        })?;
        #[cfg(test)]
        self.counters.read_bytes.fetch_add(
            slices.iter().map(|slice| slice.len() as u64).sum(),
            Ordering::Relaxed,
        );
        Ok(slices)
    }

    fn source_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if self.shared_blocks {
            self.source.read_slices_at(offset, len)
        } else {
            let data = self.source.read_direct_at(offset, len)?;
            Ok((!data.is_empty())
                .then(|| CachedSlice::from_vec(data))
                .into_iter()
                .collect())
        }
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> ReaderStats {
        ReaderStats {
            read_bytes: self.counters.read_bytes.load(Ordering::Relaxed),
            direct_read_bytes: self.counters.direct_read_bytes.load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
        }
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
        let result = self.source.read_direct_into_at(offset, buffer);
        #[cfg(test)]
        if let Ok(count) = result.as_ref() {
            self.counters
                .direct_read_bytes
                .fetch_add(*count as u64, Ordering::Relaxed);
        }
        result.map_err(|error| {
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

}

#[derive(Clone)]
pub(crate) struct NativeArchiveSession {
    path: String,
    reader: ManagedReader,
}

impl NativeArchiveSession {
    pub(crate) fn new(path: String) -> io::Result<Self> {
        let reader = ManagedReader::open(&path)?;
        Ok(Self { path, reader })
    }

    pub(crate) fn reader(&self) -> &ManagedReader {
        &self.reader
    }

    pub(crate) fn path(&self) -> &str { &self.path }

    pub(crate) fn shares_source(&self) -> bool {
        Arc::strong_count(&self.reader.source) > 1
    }

    pub(crate) fn attempt_cache(&self) -> &AttemptCache {
        self.reader.source.attempt_cache().expect("archive session has a physical source")
    }

    pub(crate) fn generation(&self) -> io::Result<(&str, u64)> {
        Ok((&self.path, self.reader.file_identity()?.source_id))
    }
}

fn coalesce_cached_slices(mut slices: Vec<CachedSlice>) -> io::Result<CachedSlice> {
    if slices.len() == 1 {
        return Ok(slices.remove(0));
    }

    #[cfg(test)]
    if slices.len() > 1 {
        THREAD_REQUEST_COALESCES.with(|count| count.set(count.get() + 1));
    }

    let total = slices.iter().map(|slice| slice.len()).sum();
    let mut data = crate::io::resource_error::bytes_with_capacity(total)?;
    for slice in slices {
        data.extend_from_slice(&slice);
    }
    Ok(CachedSlice::from_vec(data))
}

impl ReaderInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: CachedSlice, capacity: usize) {
        let retained = data.retained_bytes();
        if data.is_empty() || retained > capacity {
            return;
        }
        // A concurrent miss may already have populated this immutable range.
        // Keep its FIFO position and reuse the existing entry for later reads.
        let std::collections::hash_map::Entry::Vacant(entry) = self.cache.entry(key) else {
            return;
        };
        entry.insert(data);
        self.cache_size += retained;
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

#[cfg(test)]
struct BytesSource {
    data: Arc<[u8]>,
}

#[cfg(test)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) path: Arc<Path>,
    // One incarnation covers blocks, structure and prepared-password material.
    // It also changes when a Watch event invalidates unchanged physical metadata.
    source_id: u64,
}

/// Cached and durable generation of the same file object. Native write time
/// already records the last-write timestamp on Windows.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PhysicalFileGeneration {
    pub(crate) len: u64,
    #[cfg(not(windows))]
    modified: Option<(bool, u64, u32)>,
    created: Option<(bool, u64, u32)>,
    #[cfg(windows)]
    windows: WindowsFileGeneration,
}

impl PhysicalFileGeneration {
    pub(crate) fn object_id(&self) -> Option<(u64, [u8; 16])> {
        #[cfg(windows)]
        {
            Some((self.windows.volume, self.windows.file_id))
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
    /// Input recovery follows the source identity, size and last-write time.
    /// Cache and mutation receipts keep the stronger full-generation equality.
    pub(crate) fn matches_input(&self, saved: &Self) -> bool {
        self.len == saved.len
            && {
                #[cfg(windows)]
                { self.windows.volume == saved.windows.volume
                    && self.windows.file_id == saved.windows.file_id
                    && self.windows.write_time == saved.windows.write_time }
                #[cfg(not(windows))]
                { self.modified == saved.modified }
            }
    }
}

fn persisted_file_time(time: SystemTime) -> (bool, u64, u32) {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => (false, duration.as_secs(), duration.subsec_nanos()),
        Err(error) => (
            true,
            error.duration().as_secs(),
            error.duration().subsec_nanos(),
        ),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DirectoryIdentity {
    volume: u64,
    file_id: [u8; 16],
    created: Option<(bool, u64, u32)>,
}

impl DirectoryIdentity {
    pub(crate) fn object_id(&self) -> (u64, [u8; 16]) {
        (self.volume, self.file_id)
    }
}

#[cfg(windows)]
pub(crate) fn capture_directory_identity(path: &Path, follow_reparse: bool) -> io::Result<DirectoryIdentity> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .access_mode(0x0080) // FILE_READ_ATTRIBUTES
        .share_mode(0x0007) // read, write, delete
        .custom_flags(0x02000000 | if follow_reparse { 0 } else { 0x00200000 })
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || (!follow_reparse && metadata.file_attributes() & 0x0400 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint output is not a regular directory",
        ));
    }
    let generation = windows_file_generation(&file)?;
    Ok(DirectoryIdentity {
        volume: generation.volume,
        file_id: generation.file_id,
        created: metadata.created().ok().map(persisted_file_time),
    })
}

#[cfg(not(windows))]
pub(crate) fn capture_directory_identity(_path: &Path, _follow_reparse: bool) -> io::Result<DirectoryIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory identity requires Windows",
    ))
}

struct FileSource {
    identity: FileIdentity,
    physical: PhysicalFileGeneration,
    cached_shards: AtomicU64,
    file: RwLock<Option<TrackedFile>>,
    closed: AtomicBool,
    block_loads: Mutex<HashMap<u64, Arc<BlockLoad>>>,
    attempts: OnceLock<Box<AttemptCache>>,
}

impl Drop for FileSource {
    fn drop(&mut self) {
        let manager = manager();
        if let Ok(mut handles) = manager.handles.lock() {
            let path = self.identity.path.as_ref();
            if handles.get(path).is_some_and(|source| std::ptr::eq(source.as_ptr(), self)) {
                handles.remove(path);
                if handles.capacity() > 256 {
                    crate::collections::trim_map(&mut handles);
                }
            }
        }
        // Blocks are keyed by this source's generation, so no future reader
        // can reuse them once the last in-flight reader is gone.
        let mut shards = *self.cached_shards.get_mut();
        while shards != 0 {
            let index = shards.trailing_zeros() as usize;
            shards &= shards - 1;
            if let Ok(mut shard) = manager.cache_shards[index].lock() {
                if shard.remove_source(self.identity.source_id) {
                    shard.compact_stale_orders();
                }
            }
        }
    }
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
    Cached(Arc<[u8]>),
    Owned(Arc<BlockLoad>),
    Waiting(Arc<BlockLoad>),
}

impl FileSource {
    fn read_cached_chunks(
        &self,
        offset: u64,
        len: usize,
        mut consume: impl FnMut(Arc<[u8]>, std::ops::Range<usize>),
    ) -> io::Result<()> {
        let request_end = offset + len as u64;
        let first = offset / BLOCK_SIZE as u64;
        let last = (request_end - 1) / BLOCK_SIZE as u64;
        let manager = manager();
        for index in first..=last {
            let block = manager.read_block(self, index)?;
            let block_start = index * BLOCK_SIZE as u64;
            let start = offset.saturating_sub(block_start) as usize;
            let end = ((request_end - block_start) as usize).min(block.len());
            let short = block.len() < BLOCK_SIZE;
            if start < end {
                consume(block, start..end);
            }
            // A short block is the physical EOF observed now (the file shrank
            // after open). Later blocks must not be appended after it.
            if short {
                break;
            }
        }

        Ok(())
    }

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
    fn attempt_cache(&self) -> Option<&AttemptCache> {
        Some(self.attempts.get_or_init(Box::default))
    }

    fn validate_cached_range(&self, _offset: u64, _len: usize) -> io::Result<()> {
        self.ensure_open()
    }
    fn file_identity(&self) -> Option<FileIdentity> {
        Some(self.identity.clone())
    }
    fn physical_generation(&self) -> Option<&PhysicalFileGeneration> {
        Some(&self.physical)
    }

    fn len(&self) -> u64 {
        self.physical.len
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
            let data = self.with_file(|file| read_file_at(file, offset, len))?;

            return Ok(data);
        }

        let mut output = crate::io::resource_error::bytes_with_capacity(len)?;
        self.read_cached_chunks(offset, len, |block, range| {
            output.extend_from_slice(&block[range]);
        })?;
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.ensure_open()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        if len > MAX_CACHEABLE_READ_BYTES {
            let count = self.with_file(|file| positional_read(file, &mut buffer[..len], offset))?;

            return Ok(count);
        }

        let mut written = 0usize;
        self.read_cached_chunks(offset, len, |block, range| {
            let chunk = &block[range];
            buffer[written..written + chunk.len()].copy_from_slice(chunk);
            written += chunk.len();
        })?;
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
        let blocks = (offset as usize % BLOCK_SIZE + len).div_ceil(BLOCK_SIZE);
        let mut slices = Vec::with_capacity(blocks);
        self.read_cached_chunks(offset, len, |block, range| {
            slices.push(CachedSlice::from_shared(block, range.start, range.end));
        })?;
        Ok(slices)
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.ensure_open()?;
        if offset >= self.len() || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len() - offset) as usize);
        let data = self.with_file(|file| read_file_at(file, offset, len))?;

        Ok(data)
    }

    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.ensure_open()?;
        if offset >= self.len() || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len() - offset) as usize);
        let count = self.with_file(|file| positional_read(file, &mut buffer[..len], offset))?;

        Ok(count)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct BlockKey {
    // A reopened physical file gets a new generation even if its metadata
    // is unchanged. Only the release index needs its canonical path.
    source_id: u64,
    index: u64,
}

impl BlockKey {
    fn new(source: &FileSource, index: u64) -> Self {
        Self {
            source_id: source.identity.source_id,
            index,
        }
    }
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

// Small or empty blocks also own metadata. Charge the cleanup index per
// block even when several blocks share its canonical path and set.
const CACHE_BLOCK_METADATA_BYTES: usize = size_of::<CacheEntry>()
    + size_of::<BlockKey>()
    + size_of::<(BlockKey, u64)>()
    + size_of::<(u64, CachedSource)>()
    + size_of::<u64>();

struct CacheQueue {
    order: VecDeque<(BlockKey, u64)>,
    bytes: usize,
    stale: usize,
    capacity: usize,
}

impl CacheQueue {
    fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::new(),
            bytes: 0,
            stale: 0,
            capacity,
        }
    }

    fn over_budget(&self) -> bool {
        let blocks = self.order.len() - self.stale;
        self.bytes + blocks * CACHE_BLOCK_METADATA_BYTES > self.capacity
    }
}

struct CacheShard {
    entries: HashMap<BlockKey, CacheEntry>,
    by_source: HashMap<u64, CachedSource>,
    hot: CacheQueue,
    general: CacheQueue,
    generation: u64,
}

struct CachedSource {
    path: Arc<Path>,
    indices: HashSet<u64>,
}

struct ReaderManager {
    // Only active borrowers own a handle. The table allows concurrent readers
    // to share one source without extending the life of a completed probe.
    handles: Mutex<HashMap<Arc<Path>, Weak<FileSource>>>,
    cache_shards: Box<[Mutex<CacheShard>]>,
}

impl CacheShard {
    fn new(hot_capacity: usize, general_capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_source: HashMap::new(),
            hot: CacheQueue::new(hot_capacity),
            general: CacheQueue::new(general_capacity),
            generation: 0,
        }
    }

    fn queue(&mut self, tier: CacheTier) -> &mut CacheQueue {
        match tier {
            CacheTier::Hot => &mut self.hot,
            CacheTier::General => &mut self.general,
        }
    }

    fn insert(
        &mut self,
        key: BlockKey,
        path: &Arc<Path>,
        data: Arc<[u8]>,
        tier: CacheTier,
    ) -> Arc<[u8]> {
        if let Some(existing) = self.entries.get(&key) {
            return Arc::clone(&existing.data);
        }
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.by_source
            .entry(key.source_id)
            .or_insert_with(|| CachedSource {
                path: Arc::clone(path),
                indices: HashSet::new(),
            })
            .indices
            .insert(key.index);
        self.entries.insert(
            key,
            CacheEntry {
                data: Arc::clone(&data),
                tier,
                generation,
            },
        );
        let queue = self.queue(tier);
        queue.bytes += data.len();
        queue.order.push_back((key, generation));

        while self.queue(tier).over_budget() {
            let (key, generation) = self.queue(tier).order.pop_front().unwrap();
            if self.entries.get(&key).map(|entry| entry.generation) != Some(generation) {
                self.queue(tier).stale -= 1;
                continue;
            }
            self.remove_entry(&key, false);
        }
        data
    }

    fn remove_entry(&mut self, key: &BlockKey, source_removed: bool) {
        let entry = self.entries.remove(key).expect("tracked cache entry");
        let queue = self.queue(entry.tier);
        queue.bytes -= entry.data.len();
        queue.stale += usize::from(source_removed);

        if !source_removed {
            let source = self.by_source.get_mut(&key.source_id).expect("tracked cache source");
            source.indices.remove(&key.index);
            if source.indices.is_empty() {
                self.by_source.remove(&key.source_id);
            }
        }
    }

    fn remove_source(&mut self, source_id: u64) -> bool {
        let Some(source) = self.by_source.remove(&source_id) else {
            return false;
        };
        for index in source.indices {
            let key = BlockKey { source_id, index };
            self.remove_entry(&key, true);
        }
        true
    }

    fn compact_stale_orders(&mut self) {
        // Payloads are freed immediately. Rebuild the order only when enough
        // obsolete keys can pay for visiting the live keys too.
        for queue in [&mut self.hot, &mut self.general] {
            if queue.order.len() == queue.stale {
                queue.order.clear();
                queue.stale = 0;
            } else if queue.stale >= CACHE_ORDER_COMPACT_STALE_MIN
                && queue.stale >= queue.order.len() - queue.stale
            {
                queue.order.retain(|(key, generation)| {
                    self.entries
                        .get(key)
                        .is_some_and(|entry| entry.generation == *generation)
                });
                queue.stale = 0;
            }
            crate::collections::trim_deque(&mut queue.order);
        }
        // Targeted cleanup already runs outside the block-read hot path.
        // Release empty allocations and shrink large sparse indexes while
        // unrelated readers keep their entries and borrowed data.
        crate::collections::trim_map(&mut self.entries);
        crate::collections::trim_map(&mut self.by_source);
    }
}

impl ReaderManager {
    fn release_resources_under_roots(
        &self,
        roots: &[PathBuf],
    ) -> io::Result<()> {
        if roots.is_empty() {
            return Ok(());
        }
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        let sources: Vec<_> = handles
            .extract_if(|path, _| path_is_under_roots(path, roots))
            .filter_map(|(_, source)| source.upgrade())
            .collect();
        // Detached sources no longer have a table entry to retire on drop.
        if handles.capacity() > 256 {
            crate::collections::trim_map(&mut handles);
        }
        drop(handles);
        for source in &sources {
            source.close()?;
        }
        for shard in &self.cache_shards {
            let mut shard = shard
                .lock()
                .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
            let source_ids = shard
                .by_source
                .iter()
                .filter_map(|(&id, source)| path_is_under_roots(&source.path, roots).then_some(id))
                .collect::<Vec<_>>();
            if source_ids.is_empty() {
                continue;
            }
            for source_id in source_ids {
                shard.remove_source(source_id);
            }
            shard.compact_stale_orders();
        }
        Ok(())
    }

    fn open_file(&self, path: &Path) -> io::Result<Arc<FileSource>> {
        // Inspect the handle opened through the current path, never the pooled
        // handle: rename/replacement can leave that handle on the old file.
        let file = TrackedFile::open_reader(path)?;
        #[cfg(windows)]
        let canonical = super::resource_lifecycle::resolved_reader_path(&file)
            .unwrap_or_else(|_| path.to_path_buf());
        #[cfg(not(windows))]
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let physical = physical_file_generation(&file)?;
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| io::Error::other("reader manager handle lock poisoned"))?;
        let existing = handles.get(canonical.as_path()).and_then(Weak::upgrade);
        if let Some(existing) = &existing {
            if existing.physical == physical {
                return Ok(Arc::clone(existing));
            }
        }
        let source = Arc::new(FileSource {
            identity: FileIdentity {
                path: Arc::from(canonical),
                source_id: NEXT_SOURCE_ID.fetch_add(1, Ordering::Relaxed),
            },
            physical,
            cached_shards: AtomicU64::new(0),
            file: RwLock::new(Some(file)),
            closed: AtomicBool::new(false),
            block_loads: Mutex::new(HashMap::new()),
            attempts: OnceLock::new(),
        });
        handles.insert(Arc::clone(&source.identity.path), Arc::downgrade(&source));
        drop(handles);
        // The overlapping generation may have ended while we opened this
        // file. Drop the borrowed reference after unlocking the table.
        drop(existing);

        Ok(source)
    }

    fn claim_block_load(&self, source: &FileSource, key: &BlockKey) -> io::Result<BlockLoadClaim> {
        let mut loads = source
            .block_loads
            .lock()
            .map_err(|_| io::Error::other("reader block-load lock poisoned"))?;

        // Recheck the cache while holding the load registry. A loader publishes
        // the block before removing its registry entry, so this closes the
        // cache-check/claim race without holding any lock across physical I/O.
        if let Some(block) = self.cached_block(key)? {
            return Ok(BlockLoadClaim::Cached(block));
        }
        if let Some(load) = loads.get(&key.index) {
            return Ok(BlockLoadClaim::Waiting(Arc::clone(load)));
        }

        let load = Arc::new(BlockLoad::new());
        loads.insert(key.index, Arc::clone(&load));
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
            if loads.capacity() > 256 {
                crate::collections::trim_map(&mut loads);
            }
        }
        // Keep the registry locked until waiters are notified so a failed load
        // cannot be immediately re-observed as the same completed entry.
        load.finish();
        Ok(())
    }

    fn read_block(&self, source: &FileSource, index: u64) -> io::Result<Arc<[u8]>> {
        let key = BlockKey::new(source, index);
        let tier = cache_tier(source, index);

        loop {
            if let Some(block) = self.cached_block(&key)? {
                return Ok(block);
            }

            match self.claim_block_load(source, &key)? {
                BlockLoadClaim::Cached(block) => return Ok(block),
                BlockLoadClaim::Waiting(load) => {
                    load.wait()?;
                    continue;
                }
                BlockLoadClaim::Owned(load) => {
                    let offset = index * BLOCK_SIZE as u64;
                    let len = BLOCK_SIZE.min(source.len().saturating_sub(offset) as usize);
                    let result = source.with_file(|file| {
                        let data = read_file_at(file, offset, len)?;
                        self.insert_block(source, key, Arc::from(data), tier)
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

    fn cached_block(&self, key: &BlockKey) -> io::Result<Option<Arc<[u8]>>> {
        let shard_index = cache_shard_index(key);
        let shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        let block = shard.entries.get(key).map(|entry| Arc::clone(&entry.data));
        Ok(block)
    }

    fn insert_block(
        &self,
        source: &FileSource,
        key: BlockKey,
        data: Arc<[u8]>,
        tier: CacheTier,
    ) -> io::Result<Arc<[u8]>> {
        let shard_index = cache_shard_index(&key);
        let mut shard = self.cache_shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("shared reader cache shard poisoned"))?;
        source
            .cached_shards
            .fetch_or(1 << shard_index, Ordering::Relaxed);
        Ok(shard.insert(key, &source.identity.path, data, tier))
    }

}

fn path_is_under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
fn canonical_release_roots(paths: &[String]) -> Vec<PathBuf> {
    let roots = paths
        .iter()
        .filter(|path| !path.is_empty())
        .map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)));
    crate::path_keys::merge_roots(roots, |path| {
        crate::path_keys::path_key(&path.to_string_lossy())
    })
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

pub(crate) fn release_reader_resources_under_resolved_roots(roots: &[PathBuf]) -> io::Result<()> {
    crate::password::context::release_under_roots(roots);
    if let Some(manager) = MANAGER.get() {
        manager.release_resources_under_roots(roots)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn release_reader_resources_under_roots(paths: Vec<String>) -> io::Result<()> {
    release_reader_resources_under_resolved_roots(&canonical_release_roots(&paths))
}

static MANAGER: OnceLock<ReaderManager> = OnceLock::new();

pub(crate) fn invalidate_reader_path(path: &Path) {
    let Some(manager) = MANAGER.get() else { return };
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut handles = manager.handles.lock().unwrap_or_else(|e| e.into_inner());
    // Do not close a source used by an older request. Its late block loads
    // carry its source id and cannot repopulate the new source's cache.
    if handles.remove(path.as_path()).is_some() && handles.capacity() > 256 {
        crate::collections::trim_map(&mut handles);
    }
}

fn manager() -> &'static ReaderManager {
    MANAGER.get_or_init(|| {
        let shard_capacity = DEFAULT_SHARED_CACHE_BYTES / CACHE_SHARDS;
        let hot_capacity = shard_capacity / HOT_CACHE_FRACTION;
        let cache_shards = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(CacheShard::new(hot_capacity, shard_capacity - hot_capacity)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ReaderManager {
            handles: Mutex::default(),
            cache_shards,
        }
    })
}

/// Capture the stable physical generation independently of the reader cache.
pub(crate) fn capture_file_generation(path: &Path) -> io::Result<PhysicalFileGeneration> {
    let file = TrackedFile::open_reader(path)?;
    physical_file_generation(&file)
}

pub(crate) fn physical_file_generation(file: &File) -> io::Result<PhysicalFileGeneration> {
    physical_file_generation_from_metadata(file, &file.metadata()?)
}

pub(crate) fn physical_file_generation_from_metadata(
    file: &File,
    metadata: &std::fs::Metadata,
) -> io::Result<PhysicalFileGeneration> {
    Ok(PhysicalFileGeneration {
        len: metadata.len(),
        #[cfg(not(windows))]
        modified: metadata.modified().ok().map(persisted_file_time),
        created: metadata.created().ok().map(persisted_file_time),
        #[cfg(windows)]
        windows: windows_file_generation(file)?,
    })
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct WindowsFileGeneration {
    volume: u64,
    file_id: [u8; 16],
    change_time: i64,
    write_time: i64,
}

#[cfg(windows)]
fn windows_file_generation(file: &File) -> io::Result<WindowsFileGeneration> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileIdInfo {
        volume: u64,
        file_id: [u8; 16],
    }
    #[repr(C)]
    #[derive(Default)]
    struct FileBasicInfo {
        creation_time: i64,
        access_time: i64,
        write_time: i64,
        change_time: i64,
        attributes: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        attributes: u32,
        // FILETIME is two DWORDs (4-byte aligned): low, high.
        creation_time: [u32; 2],
        access_time: [u32; 2],
        write_time: [u32; 2],
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            information: *mut c_void,
            size: u32,
        ) -> i32;
        fn GetFileInformationByHandle(
            handle: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let handle = file.as_raw_handle();
    let mut id = FileIdInfo::default();
    let mut basic = FileBasicInfo::default();
    // Query identity and generation on the same open file. Failure must not
    // silently fall back to a timestamp-only cache key.  FAT/exFAT, SMB and
    // user-mode file systems may reject the Ex information classes; the
    // classic by-handle query still carries a real volume serial and file
    // index for those, so it is an identity-preserving fallback.
    let id_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            18,
            (&mut id as *mut FileIdInfo).cast(),
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    } != 0;
    let basic_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            0,
            (&mut basic as *mut FileBasicInfo).cast(),
            std::mem::size_of::<FileBasicInfo>() as u32,
        )
    } != 0;
    if id_ok && basic_ok {
        return Ok(WindowsFileGeneration {
            volume: id.volume,
            file_id: id.file_id,
            change_time: basic.change_time,
            write_time: basic.write_time,
        });
    }
    let mut legacy = ByHandleFileInformation::default();
    if unsafe { GetFileInformationByHandle(handle, &mut legacy) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let (volume, file_id) = if id_ok {
        (id.volume, id.file_id)
    } else {
        let index = (u64::from(legacy.file_index_high) << 32) | u64::from(legacy.file_index_low);
        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&index.to_le_bytes());
        (u64::from(legacy.volume_serial_number), file_id)
    };
    let legacy_write_time =
        ((u64::from(legacy.write_time[1]) << 32) | u64::from(legacy.write_time[0])) as i64;
    let (change_time, write_time) = if basic_ok {
        (basic.change_time, basic.write_time)
    } else {
        (legacy_write_time, legacy_write_time)
    };
    Ok(WindowsFileGeneration {
        volume,
        file_id,
        change_time,
        write_time,
    })
}

fn read_file_at(file: &File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut data = crate::io::resource_error::zeroed_bytes(len)?;
    let mut read = 0usize;
    while read < len {
        #[cfg(test)]
        THREAD_PHYSICAL_READS.with(|reads| reads.set(reads.get() + 1));
        let count = positional_read(file, &mut data[read..], offset + read as u64)?;
        if count == 0 {
            data.truncate(read);
            break;
        }
        read += count;
    }

    Ok(data)
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
#[path = "../../tests/unit/io/reader/tests.rs"]
mod tests;
