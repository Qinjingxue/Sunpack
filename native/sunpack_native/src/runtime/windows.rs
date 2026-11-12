use super::pipe;
use crate::core::resources;
use crate::core::{config::ProcessMode, process};
use crate::pipeline::{Cancellation, Engine};
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{FreeLibrary, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, SetConsoleCtrlHandler, CONSOLE_SCREEN_BUFFER_INFO,
    CTRL_BREAK_EVENT, CTRL_C_EVENT, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, ResetEvent, SetEvent,
};

pub(super) fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

pub(super) struct Event(OwnedHandle);

impl Event {
    pub(super) fn new(manual: bool) -> io::Result<Self> {
        let raw = unsafe { CreateEventW(null(), i32::from(manual), 0, null()) };
        if raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw) }))
        }
    }

    pub(super) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    pub(super) fn signal(&self) {
        unsafe { SetEvent(self.raw()) };
    }

    pub(super) fn reset(&self) -> io::Result<()> {
        bool_result(unsafe { ResetEvent(self.raw()) })
    }
}

pub(super) fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut output = [0; N];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            output.as_mut_ptr(),
            N as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        Err(io::Error::other(format!(
            "Windows random generation failed ({status:#010x})"
        )))
    } else {
        Ok(output)
    }
}

fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut raw = null_mut();
    bool_result(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut size = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    bool_result(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    })?;
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    bool_result(unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) })?;
    let _owned = LocalAllocation(text.cast());
    let size = (0..)
        .take_while(|index| unsafe { *text.add(*index) != 0 })
        .count();
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, size)
    }))
}

pub(super) struct PipeSecurity(LocalAllocation);

impl PipeSecurity {
    pub(super) fn current_user() -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl = wide(OsStr::new(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")));
        let mut raw = null_mut();
        bool_result(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                null_mut(),
            )
        })?;
        Ok(Self(LocalAllocation(raw)))
    }

    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: 0,
        }
    }
}

static CONSOLE_CANCEL: Mutex<Option<Cancellation>> = Mutex::new(None);
static PRIORITY_TRANSITION: Mutex<()> = Mutex::new(());

pub(super) fn foreground_active() -> bool {
    process::foreground_active()
}

pub(super) fn maintain_when_foreground_idle(engine: &Engine, maintain: impl FnOnce()) {
    let _transition = PRIORITY_TRANSITION.lock().unwrap();
    if !foreground_active() {
        let _ = process::expire_foreground_override();
        let _ = engine.set_process_mode(process::effective_mode());
        maintain();
    }
}

pub(super) fn monotonic_seconds() -> f64 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryPerformanceCounter(counter: *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
    }
    static FREQUENCY: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    let frequency = *FREQUENCY.get_or_init(|| {
        let mut frequency = 0;
        unsafe { QueryPerformanceFrequency(&mut frequency) };
        frequency.max(1)
    });
    let mut counter = 0;
    unsafe { QueryPerformanceCounter(&mut counter) };
    counter as f64 / frequency as f64
}

pub(super) fn configure_priority(engine: &Engine, mode: ProcessMode) {
    let _transition = PRIORITY_TRANSITION.lock().unwrap();
    let _ = process::configure_mode(mode);
    let _ = engine.set_process_mode(process::effective_mode());
}

pub(super) struct Foreground<'a> {
    engine: &'a Engine,
    watch: &'a super::watch::Watch,
    host: Option<process::ForegroundPriority>,
}

impl<'a> Foreground<'a> {
    pub(super) fn enter(engine: &'a Engine, watch: &'a super::watch::Watch) -> Self {
        let _transition = PRIORITY_TRANSITION.lock().unwrap();
        let host = process::ForegroundPriority::enter();
        let _ = engine.set_process_mode(process::effective_mode());
        Self {
            engine,
            watch,
            host: Some(host),
        }
    }
}

impl Drop for Foreground<'_> {
    fn drop(&mut self) {
        let last = {
            let _transition = PRIORITY_TRANSITION.lock().unwrap();
            drop(self.host.take());
            !foreground_active()
        };
        if last {
            // Watch startup also takes its running lock before this priority
            // gate. Release the gate before selecting who owns idle expiry.
            self.watch.foreground_finished(|| {
                maintain_when_foreground_idle(self.engine, || {});
            });
        }
    }
}

unsafe extern "system" fn on_console_control(kind: u32) -> i32 {
    if matches!(kind, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        if let Some(cancel) = CONSOLE_CANCEL.lock().unwrap().as_ref() {
            cancel.cancel();
            return 1;
        }
    }
    0
}

pub(super) struct ConsoleControl;

impl ConsoleControl {
    pub(super) fn install(cancel: Cancellation) -> Self {
        *CONSOLE_CANCEL.lock().unwrap() = Some(cancel);
        unsafe { SetConsoleCtrlHandler(Some(on_console_control), 1) };
        Self
    }
}

impl Drop for ConsoleControl {
    fn drop(&mut self) {
        unsafe { SetConsoleCtrlHandler(Some(on_console_control), 0) };
        CONSOLE_CANCEL.lock().unwrap().take();
    }
}

pub(super) fn enable_console_updates() -> bool {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };
    let mut mode = 0;
    unsafe {
        let output = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleMode(output, &mut mode) != 0
            && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
                || SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0)
    }
}

pub(super) fn console_size() -> (usize, usize) {
    let mut screen = CONSOLE_SCREEN_BUFFER_INFO::default();
    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut screen) } == 0 {
        (80, 24)
    } else {
        (
            (i32::from(screen.srWindow.Right) - i32::from(screen.srWindow.Left) + 1).max(1)
                as usize,
            (i32::from(screen.srWindow.Bottom) - i32::from(screen.srWindow.Top) + 1).max(1)
                as usize,
        )
    }
}

type LibraryHandle = windows_sys::Win32::Foundation::HMODULE;

pub(super) struct ToastLibrary(LibraryHandle);

impl ToastLibrary {
    pub(super) fn load(cwd: &Path) -> io::Result<Self> {
        let path = wide(resources::toast_library_path(cwd)?.as_os_str());
        let raw = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        };
        if raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }

    fn procedure(&self, name: &[u8]) -> io::Result<unsafe extern "system" fn() -> isize> {
        unsafe { GetProcAddress(self.0, name.as_ptr()) }.ok_or_else(io::Error::last_os_error)
    }

    pub(super) fn self_test(&self) -> io::Result<()> {
        let self_test: unsafe extern "C" fn() -> i32 =
            unsafe { std::mem::transmute(self.procedure(b"sunpack_toast_self_test\0")?) };
        hresult(unsafe { self_test() })
    }

    pub(super) fn presenter(&self, log: &Path) -> io::Result<ToastPresenter<'_>> {
        type Create = unsafe extern "C" fn(*const u16, *const u16, *mut *mut c_void) -> i32;
        let create: Create =
            unsafe { std::mem::transmute(self.procedure(b"sunpack_toast_create_presenter\0")?) };
        let exe = wide(std::env::current_exe()?.as_os_str());
        let log = wide(log.as_os_str());
        let mut context = null_mut();
        hresult(unsafe { create(exe.as_ptr(), log.as_ptr(), &mut context) })?;
        Ok(ToastPresenter {
            library: self,
            context,
        })
    }
}

impl Drop for ToastLibrary {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}

pub(super) struct ToastPresenter<'a> {
    library: &'a ToastLibrary,
    context: *mut c_void,
}

impl ToastPresenter<'_> {
    pub(super) fn show(&self, payload: &[u8], sequence: u64) -> io::Result<()> {
        let show: unsafe extern "C" fn(*mut c_void, *const u8, u32, u64) -> i32 =
            unsafe { std::mem::transmute(self.library.procedure(b"sunpack_toast_show\0")?) };
        hresult(unsafe {
            show(
                self.context,
                payload.as_ptr(),
                payload.len() as u32,
                sequence,
            )
        })
    }

    pub(super) fn clear(&self) -> io::Result<()> {
        let clear: unsafe extern "C" fn(*mut c_void) -> i32 =
            unsafe { std::mem::transmute(self.library.procedure(b"sunpack_toast_clear\0")?) };
        hresult(unsafe { clear(self.context) })
    }
}

impl Drop for ToastPresenter<'_> {
    fn drop(&mut self) {
        if let Ok(address) = self.library.procedure(b"sunpack_toast_destroy\0") {
            let destroy: unsafe extern "C" fn(*mut c_void) -> i32 =
                unsafe { std::mem::transmute(address) };
            unsafe { destroy(self.context) };
        }
    }
}

fn hresult(value: i32) -> io::Result<()> {
    if value < 0 {
        Err(io::Error::other(format!(
            "Windows toast call failed (HRESULT {value:#010X})"
        )))
    } else {
        Ok(())
    }
}

pub(super) fn activate_toast(cwd: &Path, identity: &str) -> io::Result<i32> {
    let library = ToastLibrary::load(cwd)?;
    let activate: unsafe extern "C" fn() -> i32 =
        unsafe { std::mem::transmute(library.procedure(b"sunpack_toast_activate\0")?) };
    let cancel_batch: unsafe extern "C" fn(*mut u16, u32) -> i32 =
        unsafe { std::mem::transmute(library.procedure(b"sunpack_toast_cancel_batch\0")?) };
    hresult(unsafe { activate() })?;
    let mut batch = [0; 33];
    hresult(unsafe { cancel_batch(batch.as_mut_ptr(), batch.len() as u32) })?;
    let len = batch
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(batch.len());
    if len == 0 {
        return Ok(0);
    }
    let id = String::from_utf16_lossy(&batch[..len]);
    let result = pipe::submit_existing(cwd, identity, &["--cancel-watch-batch".into(), id], false)?;
    Ok(result.unwrap_or(1))
}

const STARTUP_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const STARTUP_VALUE: &str = "SunPackWatchService";

struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn registry_result(result: u32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub(super) fn registry_key_exists(hive: HKEY, path: &str) -> io::Result<bool> {
    let key = wide(OsStr::new(path));
    let mut result = null_mut();
    let status = unsafe { RegOpenKeyExW(hive, key.as_ptr(), 0, KEY_READ, &mut result) };
    if status == 2 {
        return Ok(false);
    }
    registry_result(status)?;
    let _key = RegistryKey(result);
    Ok(true)
}

pub(super) fn startup_status() -> io::Result<Option<String>> {
    registry_text(HKEY_CURRENT_USER, STARTUP_KEY, STARTUP_VALUE)
}

pub(super) fn registry_text(hive: HKEY, path: &str, value: &str) -> io::Result<Option<String>> {
    let key = wide(OsStr::new(path));
    let name = wide(OsStr::new(value));
    let mut size = 0;
    let status = unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            name.as_ptr(),
            0x00000006,
            null_mut(),
            null_mut(),
            &mut size,
        )
    };
    if status == 2 {
        return Ok(None);
    }
    registry_result(status)?;
    let mut value = vec![0u16; (size as usize).div_ceil(2)];
    registry_result(unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            name.as_ptr(),
            0x00000006,
            null_mut(),
            value.as_mut_ptr().cast(),
            &mut size,
        )
    })?;
    let len = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    Ok(Some(String::from_utf16_lossy(&value[..len])))
}

pub(super) fn registry_dword(hive: HKEY, path: &str, value: &str) -> io::Result<Option<u32>> {
    let key = wide(OsStr::new(path));
    let value = wide(OsStr::new(value));
    let mut result = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            value.as_ptr(),
            0x10,
            null_mut(),
            (&mut result as *mut u32).cast(),
            &mut size,
        )
    };
    if status == 2 {
        return Ok(None);
    }
    registry_result(status)?;
    Ok(Some(result))
}

pub(super) fn startup_command() -> io::Result<String> {
    let exe = std::env::current_exe()?;
    let identity = super::RUNTIME_ID
        .get()
        .map(String::as_str)
        .unwrap_or("v2-0000000000000000");
    Ok(format!(
        "\"{}\" --_sunpack-runtime-id={identity} watch start",
        exe.display()
    ))
}

pub(super) fn launch_watch_request(cwd: &Path, args: &[String]) -> io::Result<i32> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe()?;
    let installed = exe.with_file_name("bin").join("sunpack.exe");
    let launcher = if installed.is_file() {
        installed
    } else {
        exe.with_file_name("sunpack.exe")
    };
    let status = std::process::Command::new(launcher)
        .current_dir(cwd)
        .args(args)
        .creation_flags(0x0800_0000)
        .status()?;
    Ok(status.code().unwrap_or(3))
}

pub(super) fn startup_enable() -> io::Result<String> {
    let command = startup_command()?;
    let data = wide(OsStr::new(&command));
    let key = startup_key()?;
    let name = wide(OsStr::new(STARTUP_VALUE));
    registry_result(unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    })?;
    Ok(command)
}

pub(super) fn startup_disable() -> io::Result<bool> {
    let key = startup_key()?;
    let name = wide(OsStr::new(STARTUP_VALUE));
    let status = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
    if status == 2 {
        return Ok(false);
    }
    registry_result(status)?;
    Ok(true)
}

fn startup_key() -> io::Result<RegistryKey> {
    let key = wide(OsStr::new(STARTUP_KEY));
    let mut result = null_mut();
    registry_result(unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut result,
            null_mut(),
        )
    })?;
    Ok(RegistryKey(result))
}
