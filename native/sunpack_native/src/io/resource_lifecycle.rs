use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

#[derive(Clone)]
pub(crate) struct NativeResourceRecord {
    pub(crate) kind: &'static str,
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) promotion_blocking: bool,
    // Keep diagnostics cheap while the registry lock is held. Formatting is
    // only needed when a resource snapshot is requested.
    pub(crate) thread: std::thread::ThreadId,
    pub(crate) created_from: &'static std::panic::Location<'static>,
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
    _resource: FileResource,
}

// A batch shares only its promotion guard; file handles still close per probe.
enum FileResource {
    Owned { _guard: NativeResourceGuard },
    Shared { _guard: Arc<NativeResourceGuard> },
}

pub(crate) struct NativeReadScope {
    #[cfg(windows)]
    root: Vec<u16>,
    #[cfg(not(windows))]
    root: PathBuf,
    guard: Arc<NativeResourceGuard>,
}

impl NativeReadScope {
    pub(crate) fn new(root: &Path) -> io::Result<Self> {
        let root = normalized_path(root.to_path_buf());
        let guard = NativeResourceGuard::register_normalized(
            "directory_probe_batch",
            vec![root.clone()],
            true,
        )?;
        #[cfg(windows)]
        let root = {
            use std::os::windows::ffi::OsStrExt;
            let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
            while wide.last() == Some(&(b'\\' as u16)) {
                wide.pop();
            }
            wide
        };
        Ok(Self {
            root,
            guard: Arc::new(guard),
        })
    }

    pub(crate) fn open_reader(&self, path: &str) -> io::Result<TrackedFile> {
        let file = open_shared_reader(Path::new(path))?;
        // Verify the opened object, including reparse/rename races, without
        // opening a second handle just to canonicalize every file's name.
        if handle_path_is_under(&file, &self.root).unwrap_or(false) {
            return Ok(TrackedFile {
                file,
                _resource: FileResource::Shared {
                    _guard: Arc::clone(&self.guard),
                },
            });
        }
        drop(file);
        TrackedFile::open_reader(path, "volume_anchor_cheap")
    }
}

#[cfg(windows)]
fn handle_path_is_under(file: &File, root: &[u16]) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            handle: *mut std::ffi::c_void,
            path: *mut u16,
            len: u32,
            flags: u32,
        ) -> u32;
    }
    let mut stack = [0u16; 1024];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            stack.as_mut_ptr(),
            stack.len() as u32,
            0,
        )
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    } else if (len as usize) < stack.len() {
        Ok(handle_path_has_root(&stack[..len as usize], root))
    } else {
        let mut data = vec![0u16; len as usize + 1];
        let actual = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                data.as_mut_ptr(),
                data.len() as u32,
                0,
            )
        };
        if actual == 0 || actual as usize >= data.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(handle_path_has_root(&data[..actual as usize], root))
    }
}

#[cfg(windows)]
fn handle_path_has_root(actual: &[u16], root: &[u16]) -> bool {
    // Compare only the root component prefix, directly in the OS buffer. A
    // sibling named root-extra must never inherit this root's promotion guard.
    !root.is_empty()
        && actual.len() >= root.len()
        && (actual.len() == root.len() || actual[root.len()] == b'\\' as u16)
        && actual
            .iter()
            .zip(root)
            .all(|(&unit, &expected)| crate::path_keys::case_key_unit(unit) == expected)
}

#[cfg(not(windows))]
fn handle_path_is_under(_file: &File, _root: &Path) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "scoped probes require Windows",
    ))
}

fn open_shared_reader(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0x1 | 0x2 | 0x4);
    }
    options.open(path)
}

impl TrackedFile {
    #[track_caller]
    pub(crate) fn open(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        let file = File::open(path)?;
        Ok(Self {
            file,
            _resource: FileResource::Owned { _guard: resource },
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
            _resource: FileResource::Owned { _guard: resource },
        })
    }

    #[track_caller]
    pub(crate) fn open_reader(path: impl AsRef<Path>, kind: &'static str) -> io::Result<Self> {
        let path = path.as_ref();
        let resource = NativeResourceGuard::register(kind, [path.to_path_buf()])?;
        let file = open_shared_reader(path)?;
        Ok(Self {
            file,
            _resource: FileResource::Owned { _guard: resource },
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
pub(crate) fn read_shared_utf8_text(path: PathBuf) -> std::io::Result<String> {
    Ok((shared_utf8_text(path))?)
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
        let paths = paths.into_iter().map(normalized_path).collect::<Vec<_>>();
        Self::register_normalized(kind, paths, promotion_blocking)
    }

    #[track_caller]
    fn register_normalized(
        kind: &'static str,
        paths: Vec<PathBuf>,
        promotion_blocking: bool,
    ) -> io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
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

pub(crate) fn native_begin_promotion(roots: Vec<String>) -> std::io::Result<u64> {
    static NEXT_PROMOTION_ID: AtomicU64 = AtomicU64::new(1);
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let mut registry = registry()
        .registry
        .lock()
        .map_err(|_| std::io::Error::other("native resource registry poisoned"))?;
    if registry
        .promotions
        .values()
        .any(|existing| paths_overlap(&roots, existing))
    {
        return Err(std::io::Error::other(
            "overlapping native promotion already active",
        ));
    }
    let id = NEXT_PROMOTION_ID.fetch_add(1, Ordering::Relaxed);
    registry.promotions.insert(id, roots);
    Ok(id)
}

pub(crate) fn native_end_promotion(token: u64) -> std::io::Result<()> {
    let mut registry = registry()
        .registry
        .lock()
        .map_err(|_| std::io::Error::other("native resource registry poisoned"))?;
    if registry.promotions.remove(&token).is_none() {
        return Err(std::io::Error::other("unknown native promotion token"));
    }
    if registry.promotions.capacity() > 256 {
        crate::collections::trim_map(&mut registry.promotions);
    }
    Ok(())
}

pub(crate) fn native_resource_snapshot(
    roots: Vec<String>,
) -> io::Result<Vec<(u64, NativeResourceRecord)>> {
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let records = {
        let registry = registry()
            .registry
            .lock()
            .map_err(|_| std::io::Error::other("native resource registry poisoned"))?;
        matching_resources(&registry, &roots, false)
    };
    Ok(records)
}

pub(crate) fn native_wait_for_resources(
    roots: Vec<String>,
    nonblocking: bool,
) -> io::Result<Vec<(u64, NativeResourceRecord)>> {
    let roots = roots
        .into_iter()
        .map(PathBuf::from)
        .map(normalized_path)
        .collect::<Vec<_>>();
    let records = (move || {
        let state = registry();
        let registry = state
            .registry
            .lock()
            .map_err(|_| io::Error::other("native resource registry poisoned"))?;
        if nonblocking {
            return Ok::<_, io::Error>(matching_resources(&registry, &roots, true));
        }
        let _registry = state
            .changed
            .wait_while(registry, |registry| {
                registry.resources.values().any(|record| {
                    record.promotion_blocking && (roots.is_empty() || overlaps(record, &roots))
                })
            })
            .map_err(|_| io::Error::other("native resource registry poisoned"))?;
        Ok::<_, io::Error>(Vec::new())
    })()
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(records)
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

#[cfg(test)]
mod tests {
    use super::*;

    // File-only guards do not cover shared batch lifetime or redirected opens.
    // One scope checks close ordering and the existing per-file fallback.
    #[test]
    fn scoped_readers_keep_promotion_protection_until_handles_close() {
        let root = crate::test_support::temp_file("read_scope_İ_Σ_测试", b"");
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        let path = root.join("inside.fake");
        std::fs::write(&path, b"inside").unwrap();
        // A same-prefix sibling exercises the component boundary as well as
        // the non-ASCII root's shared filesystem case mapping.
        let outside = root.with_extension("sibling");
        std::fs::write(&outside, b"outside").unwrap();
        let scope = NativeReadScope::new(&root).unwrap();
        let id = scope.guard.id;
        let mut inside = scope.open_reader(path.to_str().unwrap()).unwrap();
        let mut fallback = scope.open_reader(outside.to_str().unwrap()).unwrap();
        assert!(matches!(inside._resource, FileResource::Shared { .. }));
        assert!(matches!(fallback._resource, FileResource::Owned { .. }));
        drop(scope);
        assert!(registry()
            .registry
            .lock()
            .unwrap()
            .resources
            .contains_key(&id));
        let mut data = String::new();
        inside.read_to_string(&mut data).unwrap();
        fallback.read_to_string(&mut data).unwrap();
        assert_eq!(data, "insideoutside");
        drop((inside, fallback));
        assert!(!registry()
            .registry
            .lock()
            .unwrap()
            .resources
            .contains_key(&id));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
        std::fs::remove_file(outside).unwrap();
    }
}
