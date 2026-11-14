use std::{
    env, io,
    path::{Path, PathBuf},
};

pub fn program_data_dir() -> io::Result<PathBuf> {
    env::var_os("PROGRAMDATA")
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(path).join("SunPack"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PROGRAMDATA is not defined"))
}

pub(crate) fn package_root() -> Option<&'static Path> {
    static ROOT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let exe = env::current_exe().ok()?;
        let dir = exe.parent()?;
        ((dir.join("sunpack.exe").is_file() || dir.join("bin/sunpack.exe").is_file())
            && dir.join("sunpack-runtime.exe").is_file())
        .then(|| dir.to_path_buf())
    })
    .as_deref()
}

fn development_root(cwd: &Path) -> Option<PathBuf> {
    static ROOT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| env::current_exe().ok().as_deref().and_then(checkout_root))
        .clone()
        .or_else(|| checkout_root(cwd))
}

fn checkout_root(path: &Path) -> Option<PathBuf> {
    // Match main's module-root-first policy: the invoking directory may itself
    // be a different checkout, but must not replace the running application's root.
    path.ancestors()
        .find(|root| root.join("native/Cargo.toml").is_file())
        .map(Path::to_path_buf)
}

/// Resolve the native CLI entry point without mistaking a source build for a package.
pub(crate) fn launcher_path(cwd: &Path) -> io::Result<PathBuf> {
    let exe = env::current_exe()?;
    let path = if let Some(root) = package_root() {
        let installed = root.join("bin/sunpack.exe");
        if installed.is_file() { installed } else { root.join("sunpack.exe") }
    } else {
        let root = development_root(cwd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SunPack application root was not found"))?;
        development_launcher(&root, &exe)?
    };
    if !path.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound,
            format!("SunPack native launcher was not built: {}", path.display())));
    }
    Ok(path)
}

fn development_launcher(root: &Path, exe: &Path) -> io::Result<PathBuf> {
    let profile = exe.parent().and_then(Path::file_name).and_then(|name| name.to_str());
    let suffix = match profile {
        Some("ci") => "-ci",
        Some("release") => "",
        _ => return Err(io::Error::new(io::ErrorKind::NotFound,
            "Build the native launcher and runtime with setup_windows_dev.ps1 (ci or release)")),
    };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    Ok(root.join(format!("native/sevenzip_bridge/build-{arch}{suffix}/Release/sunpack_launcher.exe")))
}

pub(crate) fn resource_roots(cwd: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(2);
    if let Some(root) = package_root().map(Path::to_path_buf).or_else(|| development_root(cwd)) {
        roots.push(root);
    }
    if roots.first().is_none_or(|root| root != cwd) {
        roots.push(cwd.to_path_buf());
    }
    roots
}

pub fn writable_data_dir(cwd: &Path) -> io::Result<PathBuf> {
    match package_root() {
        Some(_) => program_data_dir(),
        None => Ok(development_root(cwd).unwrap_or_else(|| cwd.to_path_buf())),
    }
}

fn tool_dirs() -> [&'static str; 2] {
    if cfg!(target_arch = "aarch64") {
        ["tools-arm64", "tools"]
    } else {
        ["tools", "tools-x64"]
    }
}

fn tool_path(cwd: &Path, name: &str) -> io::Result<PathBuf> {
    for root in resource_roots(cwd) {
        for dir in tool_dirs() {
            let path = root.join(dir).join(name);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Required {name} was not staged under tools."),
    ))
}

pub fn worker_path(cwd: &Path) -> io::Result<PathBuf> {
    tool_path(cwd, "sunpack_sevenzip_worker.exe")
}

pub fn toast_library_path(cwd: &Path) -> io::Result<PathBuf> {
    find_toast_library(resource_roots(cwd)).ok_or_else(|| io::Error::new(
        io::ErrorKind::NotFound,
        r"Optional sunpack_toast.dll was not found under tools\ or native\toast_host\build.",
    ))
}

fn find_toast_library(roots: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    const DLL: &str = "sunpack_toast.dll";
    let build = if cfg!(target_arch = "aarch64") {
        "native/toast_host/build-arm64/Release"
    } else {
        "native/toast_host/build-x64/Release"
    };
    let dirs = [build, "native/toast_host/build/Release", "native/toast_host/build/Debug"];
    for root in roots {
        if let Some(path) = dirs.into_iter().chain(tool_dirs()).chain([""])
            .map(|dir| root.join(dir).join(DLL)).find(|path| path.is_file()) {
            return Some(path);
        }
    }
    None
}

pub(crate) struct FileMutex(*mut std::ffi::c_void);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(
        attributes: *const std::ffi::c_void,
        owner: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

impl FileMutex {
    pub(crate) fn lock(path: &Path, prefix: &str) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let key = crate::path_keys::path_key(&path.to_string_lossy());
        let hash = crate::fast_hash_core::xxh64(key.as_bytes(), 0);
        let name: Vec<u16> = format!("Local\\{prefix}-{hash:016x}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // The guard is thread-bound and releases exactly one successful wait.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        match unsafe { WaitForSingleObject(handle, u32::MAX) } {
            0 | 0x80 => Ok(Self(handle)),
            _ => {
                let error = io::Error::last_os_error();
                unsafe {
                    CloseHandle(handle);
                }
                Err(error)
            }
        }
    }
}

impl Drop for FileMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod entrypoint_tests {
    use super::*;

    #[test]
    fn source_layout_finds_its_own_checkout_from_the_runtime_executable() {
        let temp = env::temp_dir().join(format!("sunpack-resource-roots-{}", std::process::id()));
        let application = temp.join("application");
        std::fs::create_dir_all(application.join("native")).unwrap();
        std::fs::write(application.join("native/Cargo.toml"), "[workspace]").unwrap();
        let exe = application.join(".cache/rust-target/x64/target/ci/sunpack-runtime.exe");
        assert_eq!(checkout_root(&exe), Some(application));
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn source_launcher_uses_the_runtime_build_profile_without_package_staging() {
        let root = Path::new("checkout");
        let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
        for (profile, suffix) in [("ci", "-ci"), ("release", "")] {
            let exe = root.join(".cache/rust-target").join(arch).join("target").join(profile).join("sunpack-runtime.exe");
            assert_eq!(development_launcher(root, &exe).unwrap(), root.join(format!("native/sevenzip_bridge/build-{arch}{suffix}/Release/sunpack_launcher.exe")));
        }
        assert!(development_launcher(root, &root.join("debug/sunpack-runtime.exe")).is_err());
    }

    #[test]
    fn toast_lookup_prefers_the_current_architecture_in_the_running_checkout() {
        let marker = crate::test_support::temp_file("toast_lookup", b"");
        let root = marker.with_extension("checkout");
        let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
        let current = root.join(format!("native/toast_host/build-{arch}/Release/sunpack_toast.dll"));
        let staged = root.join("tools/sunpack_toast.dll");
        for file in [&current, &staged] {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, b"").unwrap();
        }
        assert_eq!(find_toast_library([root.clone()]), Some(current.clone()));
        std::fs::remove_file(current).unwrap();
        assert_eq!(find_toast_library([root.clone()]), Some(staged));
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(marker).unwrap();
    }
}
