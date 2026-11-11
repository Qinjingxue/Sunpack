use std::path::Path;

#[cfg(windows)]
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

#[derive(Default)]
pub(super) struct ShellNotifier {
    #[cfg(windows)]
    shared: OnceLock<Arc<Shared>>,
}

/// Collect each branch's touched directories, including rollback. The shell
/// callback can merge concurrent branches without keeping a host stage busy.
pub(super) struct ShellUpdates<'a> {
    notifier: &'a ShellNotifier,
    #[cfg(windows)]
    directories: HashMap<String, PathBuf>,
}

impl ShellNotifier {
    pub(super) fn branch(&self) -> ShellUpdates<'_> {
        ShellUpdates {
            notifier: self,
            #[cfg(windows)]
            directories: HashMap::new(),
        }
    }

    #[cfg(windows)]
    fn enqueue(&self, directories: HashMap<String, PathBuf>) {
        use windows_sys::Win32::System::Threading::TrySubmitThreadpoolCallback;

        let shared = self.shared.get_or_init(Arc::default);
        let mut state = shared.state.lock().unwrap();
        if state.directories.is_empty() {
            state.directories = directories;
        } else {
            state.directories.extend(directories);
        }
        if state.scheduled {
            return;
        }
        state.scheduled = true;
        drop(state);

        let context = Arc::into_raw(Arc::clone(shared));
        // On success the Windows pool owns this strong reference. If it could
        // not schedule the callback, publish the notifications here instead.
        if unsafe {
            TrySubmitThreadpoolCallback(
                Some(notify_shell),
                context.cast_mut().cast(),
                std::ptr::null(),
            )
        } == 0
        {
            let shared = unsafe { Arc::from_raw(context) };
            shared.drain();
        }
    }
}

impl ShellUpdates<'_> {
    pub(super) fn output(&mut self, path: &Path) {
        #[cfg(windows)]
        self.insert(path);
        self.parent(path);
    }

    pub(super) fn parent(&mut self, path: &Path) {
        #[cfg(windows)]
        if let Some(parent) = path.parent() {
            self.insert(parent);
        }
    }

    #[cfg(windows)]
    fn insert(&mut self, path: &Path) {
        use crate::path_keys::{normalize_windows_extended_prefix, path_key};
        let path = normalize_windows_extended_prefix(path.to_string_lossy().into_owned());
        self.directories
            .entry(path_key(&path))
            .or_insert_with(|| path.into());
    }
}

#[cfg(windows)]
impl Drop for ShellUpdates<'_> {
    fn drop(&mut self) {
        if !self.directories.is_empty() {
            self.notifier.enqueue(std::mem::take(&mut self.directories));
        }
    }
}

#[cfg(windows)]
#[derive(Default)]
struct State {
    directories: HashMap<String, PathBuf>,
    scheduled: bool,
}

#[cfg(windows)]
#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    idle: Condvar,
}

#[cfg(windows)]
unsafe extern "system" fn notify_shell(
    _: windows_sys::Win32::System::Threading::PTP_CALLBACK_INSTANCE,
    context: *mut std::ffi::c_void,
) {
    let shared = unsafe { Arc::from_raw(context.cast::<Shared>()) };
    shared.drain();
}

#[cfg(windows)]
impl Shared {
    fn drain(&self) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::{
            SHChangeNotify, SHCNE_UPDATEDIR, SHCNF_FLUSHNOWAIT, SHCNF_PATHW,
        };
        let mut wide = Vec::new();
        loop {
            let directories = {
                let mut state = self.state.lock().unwrap();
                if state.directories.is_empty() {
                    state.scheduled = false;
                    self.idle.notify_all();
                    return;
                }
                std::mem::take(&mut state.directories)
            };
            let mut paths = directories
                .into_values()
                .filter(|path| path.is_dir())
                .peekable();
            while let Some(directory) = paths.next() {
                wide.clear();
                wide.extend(directory.as_os_str().encode_wide().chain(Some(0)));
                // Send a batch to the shell without forcing delivery per path.
                let flags = SHCNF_PATHW
                    | if paths.peek().is_none() {
                        SHCNF_FLUSHNOWAIT
                    } else {
                        0
                    };
                unsafe {
                    SHChangeNotify(
                        SHCNE_UPDATEDIR as i32,
                        flags,
                        wide.as_ptr().cast(),
                        std::ptr::null(),
                    );
                }
            }
        }
    }
}

#[cfg(windows)]
impl Drop for ShellNotifier {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.get() {
            drop(
                shared
                    .idle
                    .wait_while(shared.state.lock().unwrap(), |state| state.scheduled)
                    .unwrap(),
            );
        }
    }
}
