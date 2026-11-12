use super::windows;
use crate::core::{
    i18n::Language, process::launch_unelevated, resources, windows_message::pump_until_stop,
};
use std::{
    cell::Cell,
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi},
        Shell::{
            Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
            NOTIFYICONDATAW,
        },
        WindowsAndMessaging::{
            AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, CreateWindowExW,
            DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, FindWindowW, GetCursorPos,
            GetWindowLongPtrW, LoadIconW, LoadImageW, PostMessageW, RegisterClassW,
            RegisterWindowMessageW, SetForegroundWindow, SetWindowLongPtrW, TrackPopupMenu,
            UnregisterClassW, CREATESTRUCTW, GWLP_USERDATA, HICON, IDI_APPLICATION, IMAGE_ICON,
            MF_STRING, MSGFLT_ALLOW, SM_CXSMICON, SM_CYSMICON, TPM_NONOTIFY, TPM_RETURNCMD,
            TPM_RIGHTBUTTON, WM_CANCELMODE, WM_DISPLAYCHANGE, WM_DPICHANGED, WM_LBUTTONDBLCLK,
            WM_LBUTTONUP, WM_NCCREATE, WM_NULL, WM_RBUTTONUP, WM_USER, WNDCLASSW, WS_EX_TOOLWINDOW,
        },
    },
};

const TRAY_EVENT: u32 = WM_USER + 20;
const OPEN: i32 = 1001;
const RELOAD: i32 = 1003;
const STOP: i32 = 1004;
const STARTUP: i32 = 1005;

pub(super) enum Action {
    Reload,
    Stop,
}

pub(super) struct Tray {
    stop: Arc<windows::Event>,
    chinese: Arc<AtomicBool>,
    window: usize,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Tray {
    pub(super) fn start(
        cwd: &Path,
        language: Language,
        notify: impl Fn(Action) + Send + 'static,
        report_error: impl Fn(u32, &io::Error) + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(windows::Event::new(true)?);
        let event = stop.clone();
        let chinese = Arc::new(AtomicBool::new(language == Language::Zh));
        let language = chinese.clone();
        let cwd = cwd.to_owned();
        let (ready, receive) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("sunpack-tray".into())
            .spawn(move || {
                let mut ready = Some(ready);
                let result = run_tray(cwd, language, Box::new(notify), Box::new(report_error), &event, &mut ready);
                if let Some(ready) = ready {
                    let error = result.as_ref().err().map_or_else(
                        || io::Error::other("Tray exited before startup"),
                        |error| io::Error::new(error.kind(), error.to_string()),
                    );
                    let _ = ready.send(Err(error));
                }
                result
            })?;
        match receive.recv() {
            Ok(Ok(window)) => Ok(Self {
                stop,
                chinese,
                window,
                thread: Some(thread),
            }),
            failure => {
                let _ = thread.join();
                match failure {
                    Ok(Err(error)) => Err(error),
                    _ => Err(io::Error::other("Tray did not start")),
                }
            }
        }
    }

    pub(super) fn set_language(&self, language: Language) {
        self.chinese
            .store(language == Language::Zh, Ordering::Relaxed);
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.stop.signal();
        // TrackPopupMenu runs a nested modal loop. Dismiss it before joining.
        unsafe {
            PostMessageW(self.window as HWND, WM_CANCELMODE, 0, 0);
        }
        if let Some(thread) = self.thread.take() {
            if let Ok(Err(error)) = thread.join() {
                eprintln!("SunPack tray: {error}");
            }
        }
    }
}

struct Context {
    cwd: PathBuf,
    chinese: Arc<AtomicBool>,
    notify: Box<dyn Fn(Action) + Send>,
    report_error: Box<dyn Fn(u32, &io::Error) + Send>,
    taskbar_created: u32,
    icon_registered: Cell<bool>,
}

fn run_tray(
    cwd: PathBuf,
    chinese: Arc<AtomicBool>,
    notify: Box<dyn Fn(Action) + Send>,
    report_error: Box<dyn Fn(u32, &io::Error) + Send>,
    stop: &windows::Event,
    ready: &mut Option<mpsc::SyncSender<io::Result<usize>>>,
) -> io::Result<()> {
    static NEXT_WINDOW: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_WINDOW.fetch_add(1, Ordering::Relaxed);
    let class_name = windows::wide(OsStr::new(&format!("SunPackWatchTray_{id:016x}")));
    let taskbar = windows::wide(OsStr::new("TaskbarCreated"));
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar.as_ptr()) };
    if taskbar_created == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut context = Context {
        cwd,
        chinese,
        notify,
        report_error,
        taskbar_created,
        icon_registered: Cell::new(false),
    };
    unsafe {
        let module = GetModuleHandleW(null());
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module,
            lpszClassName: class_name.as_ptr(),
            ..WNDCLASSW::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(io::Error::last_os_error());
        }
        let window = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class_name.as_ptr(),
            null(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            module,
            (&mut context as *mut Context).cast(),
        );
        if window.is_null() {
            let error = io::Error::last_os_error();
            UnregisterClassW(class_name.as_ptr(), module);
            return Err(error);
        }
        ChangeWindowMessageFilterEx(window, taskbar_created, MSGFLT_ALLOW, null_mut());
        // Explorer might not be ready. TaskbarCreated will retry registration.
        context.install_icon(window);
        let _ = ready
            .take()
            .expect("one tray startup notification")
            .send(Ok(window as usize));
        let result = pump_until_stop(stop.raw());
        Shell_NotifyIconW(NIM_DELETE, &icon_data(window));
        DestroyWindow(window);
        UnregisterClassW(class_name.as_ptr(), module);
        result
    }
}

fn icon_data(window: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        ..NOTIFYICONDATAW::default()
    }
}

fn load_icon() -> (HICON, bool) {
    unsafe {
        let tray = windows::wide(OsStr::new("Shell_TrayWnd"));
        let taskbar = FindWindowW(tray.as_ptr(), null());
        let dpi = if taskbar.is_null() {
            96
        } else {
            GetDpiForWindow(taskbar).max(96)
        };
        let width = GetSystemMetricsForDpi(SM_CXSMICON, dpi).max(16);
        let height = GetSystemMetricsForDpi(SM_CYSMICON, dpi).max(16);
        let icon = LoadImageW(
            GetModuleHandleW(null()),
            1usize as *const u16,
            IMAGE_ICON,
            width,
            height,
            0,
        );
        if icon.is_null() {
            (LoadIconW(null_mut(), IDI_APPLICATION), false)
        } else {
            (icon, true)
        }
    }
}

impl Context {
    fn language(&self) -> Language {
        if self.chinese.load(Ordering::Relaxed) {
            Language::Zh
        } else {
            Language::En
        }
    }

    fn update_icon(&self, window: HWND, add: bool) -> bool {
        let (icon, owned) = load_icon();
        let mut data = icon_data(window);
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = TRAY_EVENT;
        data.hIcon = icon;
        for (dst, src) in data
            .szTip
            .iter_mut()
            .take(127)
            .zip(self.language().text("tray.tip").encode_utf16())
        {
            *dst = src;
        }
        unsafe {
            let updated = Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &data) != 0;
            if owned {
                DestroyIcon(icon);
            }
            updated
        }
    }

    fn install_icon(&self, window: HWND) {
        self.icon_registered
            .set(self.update_icon(window, true) || self.update_icon(window, false));
    }

    fn command(&self, id: i32) -> io::Result<()> {
        match id {
            OPEN => open_manager(&self.cwd),
            STARTUP => {
                if windows::startup_status()?.is_some() {
                    windows::startup_disable()?;
                } else {
                    windows::startup_enable()?;
                }
                Ok(())
            }
            RELOAD => {
                (self.notify)(Action::Reload);
                Ok(())
            }
            STOP => {
                (self.notify)(Action::Stop);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn menu(&self, window: HWND) -> io::Result<()> {
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return Err(io::Error::last_os_error());
            }
            let startup_label = if windows::startup_status().ok().flatten().is_some() {
                "tray.disable_startup"
            } else {
                "tray.enable_startup"
            };
            for (id, key) in [
                (OPEN, "tray.open_manager"),
                (STARTUP, startup_label),
                (RELOAD, "tray.reload"),
                (STOP, "tray.exit"),
            ] {
                let label = windows::wide(OsStr::new(self.language().text(key)));
                AppendMenuW(menu, MF_STRING, id as usize, label.as_ptr());
            }
            let mut point = POINT::default();
            GetCursorPos(&mut point);
            SetForegroundWindow(window);
            let command = TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                point.x,
                point.y,
                0,
                window,
                null(),
            );
            PostMessageW(window, WM_NULL, 0, 0);
            DestroyMenu(menu);
            self.command(command)
        }
    }
}

fn open_manager(cwd: &Path) -> io::Result<()> {
    let data = resources::writable_data_dir(cwd)?;
    let (manager, args) = if let Some(root) = resources::package_root() {
        (root.join("SunPackGUI.exe"), Vec::new())
    } else {
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };
        let root = resources::resource_roots(cwd)
            .into_iter()
            .next()
            .unwrap_or_else(|| cwd.to_owned());
        let manager = root.join(format!(".cache/gui-{arch}/Release/SunPackGUI.exe"));
        let args = vec![
            OsString::from("--data-dir"),
            data.clone().into_os_string(),
            OsString::from("--cli"),
            std::env::current_exe()?.into_os_string(),
        ];
        (manager, args)
    };
    if !manager.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("SunPack GUI manager was not found: {}", manager.display()),
        ));
    }
    launch_unelevated(&manager, &args, &data)
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
        unsafe {
            SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize);
        }
    }
    let context = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *const Context).as_ref() };
    if let Some(context) = context {
        let result = match message {
            message if message == context.taskbar_created => {
                context.install_icon(window);
                Ok(())
            }
            WM_DISPLAYCHANGE | WM_DPICHANGED => {
                if context.icon_registered.get() {
                    context.update_icon(window, false);
                }
                Ok(())
            }
            TRAY_EVENT if lparam as u32 == WM_RBUTTONUP => context.menu(window),
            TRAY_EVENT if matches!(lparam as u32, WM_LBUTTONUP | WM_LBUTTONDBLCLK) => {
                context.command(OPEN)
            }
            _ => return unsafe { DefWindowProcW(window, message, wparam, lparam) },
        };
        if let Err(error) = result {
            (context.report_error)(message, &error);
        }
        return 0;
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
