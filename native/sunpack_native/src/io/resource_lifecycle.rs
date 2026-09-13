use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone)]
struct NativeResourceRecord {
    kind: &'static str,
    paths: Vec<PathBuf>,
    thread: String,
    created_from: String,
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
    file: Option<File>,
    resource: NativeResourceGuard,
}

impl TrackedFile {
    #[track_caller]
    pub(crate) fn open(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        let file = File::open(path)?;
        Ok(Self {
            file: Some(file),
            resource,
        })
    }

    #[track_caller]
    pub(crate) fn create(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        let file = File::create(path)?;
        Ok(Self {
            file: Some(file),
            resource,
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
            file: Some(file),
            resource,
        })
    }

    fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("tracked file methods cannot run after close")
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("tracked file methods cannot run after close")
    }

    pub(crate) fn close(&mut self) -> bool {
        let closed = self.file.take().is_some();
        if closed {
            self.resource.release();
        }
        closed
    }
}

impl Deref for TrackedFile {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        self.file()
    }
}

impl DerefMut for TrackedFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.file_mut()
    }
}

impl Read for TrackedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file_mut().read(buffer)
    }
}

impl Write for TrackedFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file_mut().write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_mut().flush()
    }
}

impl Seek for TrackedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file_mut().seek(position)
    }
}

impl Drop for TrackedFile {
    fn drop(&mut self) {
        self.close();
    }
}

impl NativeResourceGuard {
    #[track_caller]
    pub(crate) fn register(
        kind: &'static str,
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let paths = paths.into_iter().map(normalized_path).collect::<Vec<_>>();
        let mut registry = registry()
            .registry
            .lock()
            .map_err(|_| io::Error::other("native resource registry poisoned"))?;
        if registry
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
                thread: format!("{:?}", std::thread::current().id()),
                created_from: format!("{}:{}", caller.file(), caller.line()),
            },
        );
        Ok(Self { id })
    }

    pub(crate) fn release(&self) {
        let state = registry();
        if let Ok(mut registry) = state.registry.lock() {
            if registry.resources.remove(&self.id).is_some() {
                state.changed.notify_all();
            }
        }
    }
}

impl Drop for NativeResourceGuard {
    fn drop(&mut self) {
        self.release();
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
        PathBuf::from(resolved.to_string_lossy().to_lowercase())
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
    Ok(())
}

#[pyfunction]
pub(crate) fn native_resource_snapshot(py: Python<'_>, roots: Vec<String>) -> PyResult<Py<PyList>> {
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let registry = registry().registry.lock().map_err(|_| {
        pyo3::exceptions::PyRuntimeError::new_err("native resource registry poisoned")
    })?;
    resource_snapshot_to_python(py, matching_resources(&registry, &roots))
}

#[pyfunction]
pub(crate) fn native_wait_for_resources(
    py: Python<'_>,
    roots: Vec<String>,
    timeout_seconds: f64,
) -> PyResult<Py<PyList>> {
    if !timeout_seconds.is_finite() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "native resource wait timeout must be finite",
        ));
    }
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let timeout = Duration::from_secs_f64(timeout_seconds.clamp(0.0, u32::MAX as f64));
    let records = py
        .detach(move || {
            let state = registry();
            let registry = state
                .registry
                .lock()
                .map_err(|_| io::Error::other("native resource registry poisoned"))?;
            let (registry, _) = state
                .changed
                .wait_timeout_while(registry, timeout, |registry| {
                    registry
                        .resources
                        .values()
                        .any(|record| roots.is_empty() || overlaps(record, &roots))
                })
                .map_err(|_| io::Error::other("native resource registry poisoned"))?;
            Ok::<_, io::Error>(matching_resources(&registry, &roots))
        })
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    resource_snapshot_to_python(py, records)
}

fn matching_resources(
    registry: &NativeRegistry,
    roots: &[PathBuf],
) -> Vec<(u64, NativeResourceRecord)> {
    registry
        .resources
        .iter()
        .filter(|(_, record)| roots.is_empty() || overlaps(record, roots))
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
        item.set_item(
            "paths",
            record
                .paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        )?;
        item.set_item("thread", &record.thread)?;
        item.set_item("created_from", &record.created_from)?;
        output.append(item)?;
    }
    Ok(output.unbind())
}

#[allow(dead_code)]
pub(crate) fn snapshot_under(root: &Path) -> Vec<(u64, &'static str, Vec<PathBuf>)> {
    let root = normalized_path(root.to_path_buf());
    registry()
        .registry
        .lock()
        .map(|registry| {
            registry
                .resources
                .iter()
                .filter(|(_, record)| overlaps(record, std::slice::from_ref(&root)))
                .map(|(id, record)| (*id, record.kind, record.paths.clone()))
                .collect()
        })
        .unwrap_or_default()
}
