use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

#[derive(Clone)]
struct NativeResourceRecord {
    kind: &'static str,
    paths: Vec<PathBuf>,
    promotion_blocking: bool,
    // Keep diagnostics cheap while the registry lock is held. Formatting is
    // only needed when a resource snapshot is requested.
    thread: std::thread::ThreadId,
    created_from: &'static std::panic::Location<'static>,
}

#[derive(Default)]
struct NativeRegistry {
    resources: HashMap<u64, NativeResourceRecord>,
    promotions: HashMap<u64, Vec<PathBuf>>,
}

#[derive(Default)]
struct NativeRegistryState {
    registry: Mutex<NativeRegistry>,
    changed: Condvar,
}

pub(crate) struct NativeResourceGuard {
    id: u64,
}

pub(crate) struct TrackedFile {
    // Fields drop in declaration order: close the handle before unregistering it.
    file: File,
    _resource: NativeResourceGuard,
}

impl TrackedFile {
    #[track_caller]
    pub(crate) fn open(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        let file = File::open(path)?;
        Ok(Self {
            file,
            _resource: resource,
        })
    }

    #[track_caller]
    pub(crate) fn open_with<F>(
        path: impl AsRef<Path>,
        kind: &'static str,
        configure: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(&mut std::fs::OpenOptions),
    {
        Self::open_with_promotion(path, kind, true, configure)
    }

    // Passive directory observers own handles but cannot hold up file promotion.
    #[track_caller]
    pub(crate) fn open_passive_with<F>(
        path: impl AsRef<Path>,
        kind: &'static str,
        configure: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(&mut std::fs::OpenOptions),
    {
        Self::open_with_promotion(path, kind, false, configure)
    }

    #[track_caller]
    fn open_with_promotion<F>(
        path: impl AsRef<Path>,
        kind: &'static str,
        promotion_blocking: bool,
        configure: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(&mut std::fs::OpenOptions),
    {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register_with_promotion(
            kind,
            [path.to_path_buf()],
            promotion_blocking,
        )?;
        let mut options = std::fs::OpenOptions::new();
        configure(&mut options);
        let file = options.open(path)?;
        Ok(Self {
            file,
            _resource: resource,
        })
    }

    #[track_caller]
    pub(crate) fn open_reader(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path)?
        };
        #[cfg(not(windows))]
        let file = File::open(path)?;
        Ok(Self {
            file,
            _resource: resource,
        })
    }

    pub(crate) fn write_shared(&self, buffer: &[u8]) -> io::Result<()> {
        let mut file = &self.file;
        file.write_all(buffer)
    }
}

impl Deref for TrackedFile {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for TrackedFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

impl Read for TrackedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for TrackedFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for TrackedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

fn shared_utf8_text(path: PathBuf) -> io::Result<String> {
    let mut file = TrackedFile::open_reader(path, "shared_text")?;
    let mut text = String::new();
    file.file.read_to_string(&mut text)?;
    if text.starts_with('\u{feff}') {
        text.drain(..3);
    }
    Ok(text)
}

/// Read one UTF-8 snapshot without blocking an atomic replacement of its path.
#[pyfunction]
pub(crate) fn read_shared_utf8_text(py: Python<'_>, path: PathBuf) -> PyResult<String> {
    Ok(py.detach(move || shared_utf8_text(path))?)
}

/// Hash the same read used for parsing, without another file pass or Python copy.
/// Duplicate notifications do not transfer or parse the unchanged document again.
#[pyfunction]
#[pyo3(signature = (path, previous_signature))]
pub(crate) fn read_changed_shared_utf8_text(
    py: Python<'_>,
    path: PathBuf,
    previous_signature: Option<String>,
) -> PyResult<Option<(String, String)>> {
    Ok(py.detach(move || -> io::Result<Option<(String, String)>> {
        let text = shared_utf8_text(path)?;
        let data = text.as_bytes();
        let signature = format!(
            "{:016x}{:016x}",
            crate::fast_hash_core::xxh64(data, 0),
            crate::fast_hash_core::xxh64(data, 1),
        );
        Ok((previous_signature.as_ref() != Some(&signature)).then_some((signature, text)))
    })?)
}

impl NativeResourceGuard {
    #[track_caller]
    pub(crate) fn register(
        kind: &'static str,
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> io::Result<Self> {
        Self::register_with_promotion(kind, paths, true)
    }

    #[track_caller]
    fn register_with_promotion(
        kind: &'static str,
        paths: impl IntoIterator<Item = PathBuf>,
        promotion_blocking: bool,
    ) -> io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let paths = paths.into_iter().map(normalized_path).collect::<Vec<_>>();
        let mut registry = registry()
            .registry
            .lock()
            .map_err(|_| io::Error::other("native resource registry poisoned"))?;
        if promotion_blocking
            && registry
                .promotions
                .values()
                .any(|roots| paths_overlap(&paths, roots))
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("native resource registration blocked by promotion: {paths:?}"),
            ));
        }
        let caller = std::panic::Location::caller();
        registry.resources.insert(
            id,
            NativeResourceRecord {
                kind,
                paths,
                promotion_blocking,
                thread: std::thread::current().id(),
                created_from: caller,
            },
        );
        Ok(Self { id })
    }
}

impl Drop for NativeResourceGuard {
    fn drop(&mut self) {
        let state = registry();
        if let Ok(mut registry) = state.registry.lock() {
            if registry.resources.remove(&self.id).is_some() {
                // Keep small tables reusable across short-lived probes, but
                // do not retain a concurrent workload's peak allocation.
                if registry.resources.capacity() > 256 {
                    crate::collections::trim_map(&mut registry.resources);
                }
                state.changed.notify_all();
            }
        }
    }
}

fn registry() -> &'static NativeRegistryState {
    static REGISTRY: OnceLock<NativeRegistryState> = OnceLock::new();
    REGISTRY.get_or_init(NativeRegistryState::default)
}

fn normalized_path(path: PathBuf) -> PathBuf {
    let resolved = if let Ok(canonical) = std::fs::canonicalize(&path) {
        canonical
    } else if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(parent) = std::fs::canonicalize(parent) {
            parent.join(name)
        } else if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .map(|current| current.join(&path))
                .unwrap_or(path)
        }
    } else if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|current| current.join(&path))
            .unwrap_or(path)
    };
    #[cfg(windows)]
    {
        PathBuf::from(crate::path_keys::path_key(&resolved.to_string_lossy()))
    }
    #[cfg(not(windows))]
    {
        resolved
    }
}

fn paths_overlap(paths: &[PathBuf], roots: &[PathBuf]) -> bool {
    paths.iter().any(|path| {
        roots
            .iter()
            .any(|root| path.starts_with(root) || root.starts_with(path))
    })
}

fn overlaps(record: &NativeResourceRecord, roots: &[PathBuf]) -> bool {
    paths_overlap(&record.paths, roots)
}

#[pyfunction]
pub(crate) fn native_begin_promotion(roots: Vec<String>) -> PyResult<u64> {
    static NEXT_PROMOTION_ID: AtomicU64 = AtomicU64::new(1);
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let mut registry = registry().registry.lock().map_err(|_| {
        pyo3::exceptions::PyRuntimeError::new_err("native resource registry poisoned")
    })?;
    if registry
        .promotions
        .values()
        .any(|existing| paths_overlap(&roots, existing))
    {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(
            "overlapping native promotion already active",
        ));
    }
    let id = NEXT_PROMOTION_ID.fetch_add(1, Ordering::Relaxed);
    registry.promotions.insert(id, roots);
    Ok(id)
}

#[pyfunction]
pub(crate) fn native_end_promotion(token: u64) -> PyResult<()> {
    let mut registry = registry().registry.lock().map_err(|_| {
        pyo3::exceptions::PyRuntimeError::new_err("native resource registry poisoned")
    })?;
    if registry.promotions.remove(&token).is_none() {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(
            "unknown native promotion token",
        ));
    }
    if registry.promotions.capacity() > 256 {
        crate::collections::trim_map(&mut registry.promotions);
    }
    Ok(())
}

#[pyfunction]
pub(crate) fn native_resource_snapshot(py: Python<'_>, roots: Vec<String>) -> PyResult<Py<PyList>> {
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let records = {
        let registry = registry().registry.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("native resource registry poisoned")
        })?;
        matching_resources(&registry, &roots, false)
    };
    resource_snapshot_to_python(py, records)
}

#[pyfunction]
pub(crate) fn native_wait_for_resources(
    py: Python<'_>,
    roots: Vec<String>,
    timeout_seconds: f64,
) -> PyResult<Py<PyList>> {
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let records = py
        .detach(move || {
            let state = registry();
            let registry = state
                .registry
                .lock()
                .map_err(|_| io::Error::other("native resource registry poisoned"))?;
            // Zero is an explicit non-blocking probe, not an elapsed-time failure.
            // Positive values are accepted for API compatibility, but wait for release.
            if timeout_seconds <= 0.0 {
                return Ok::<_, io::Error>(matching_resources(&registry, &roots, true));
            }
            let registry = state
                .changed
                .wait_while(registry, |registry| {
                    registry.resources.values().any(|record| {
                        record.promotion_blocking && (roots.is_empty() || overlaps(record, &roots))
                    })
                })
                .map_err(|_| io::Error::other("native resource registry poisoned"))?;
            Ok::<_, io::Error>(matching_resources(&registry, &roots, true))
        })
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    resource_snapshot_to_python(py, records)
}

fn matching_resources(
    registry: &NativeRegistry,
    roots: &[PathBuf],
    promotion_only: bool,
) -> Vec<(u64, NativeResourceRecord)> {
    registry
        .resources
        .iter()
        .filter(|(_, record)| {
            (!promotion_only || record.promotion_blocking)
                && (roots.is_empty() || overlaps(record, roots))
        })
        .map(|(id, record)| (*id, record.clone()))
        .collect()
}

fn resource_snapshot_to_python(
    py: Python<'_>,
    records: Vec<(u64, NativeResourceRecord)>,
) -> PyResult<Py<PyList>> {
    let output = PyList::empty(py);
    for (id, record) in records {
        let item = PyDict::new(py);
        item.set_item("resource_id", id)?;
        item.set_item("kind", record.kind)?;
        item.set_item("promotion_blocking", record.promotion_blocking)?;
        item.set_item(
            "paths",
            record
                .paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        )?;
        item.set_item("thread", format!("{:?}", record.thread))?;
        item.set_item(
            "created_from",
            format!(
                "{}:{}",
                record.created_from.file(),
                record.created_from.line()
            ),
        )?;
        output.append(item)?;
    }
    Ok(output.unbind())
}
