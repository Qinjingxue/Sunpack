//! An event-driven clipboard and volume observer owned by one Watch instance.
use super::{passwords, windows_message::pump_until_stop};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::{
        DataExchange::{AddClipboardFormatListener, RemoveClipboardFormatListener},
        LibraryLoader::GetModuleHandleW,
        Threading::{CreateEventW, SetEvent},
    },
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, GetWindowLongPtrW, PostQuitMessage,
        RegisterClassW, SetWindowLongPtrW, UnregisterClassW, CREATESTRUCTW, DBT_DEVICEARRIVAL,
        DBT_DEVICEREMOVECOMPLETE, DBT_DEVTYP_VOLUME, DEV_BROADCAST_HDR, DEV_BROADCAST_VOLUME,
        GWLP_USERDATA, HWND_MESSAGE, WM_CLIPBOARDUPDATE, WM_CLOSE, WM_DEVICECHANGE, WM_NCCREATE,
        WNDCLASSW,
    },
};

pub(crate) enum Notification {
    Clipboard(Vec<String>),
    VolumeChanged { unit_mask: u32, arrived: bool },
}

struct Context {
    clipboard_enabled: bool,
    observe_volumes: bool,
    notify: Box<dyn Fn(Notification) + Send>,
}

impl Context {
    fn clipboard_updated(&self) {
        let values = passwords::clipboard_passwords();
        if !values.is_empty() {
            (self.notify)(Notification::Clipboard(values));
        }
    }
}

pub(crate) struct Monitor {
    stop: Arc<OwnedHandle>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Monitor {
    pub(crate) fn start(
        clipboard_enabled: bool,
        observe_volumes: bool,
        notify: impl Fn(Notification) + Send + 'static,
    ) -> io::Result<Self> {
        let (ready, receive) = mpsc::sync_channel(1);
        let context = Context {
            clipboard_enabled,
            observe_volumes,
            notify: Box::new(notify),
        };
        let stop = unsafe { CreateEventW(null(), 1, 0, null()) };
        if stop.is_null() {
            return Err(io::Error::last_os_error());
        }
        let stop = Arc::new(unsafe { OwnedHandle::from_raw_handle(stop) });
        let stop_signal = stop.clone();
        let thread = thread::Builder::new()
            .name("sunpack-clipboard".into())
            .spawn(move || {
                let mut ready = Some(ready);
                let result = run_window(context, &stop_signal, &mut ready);
                if let Some(ready) = ready {
                    let startup = result.as_ref().err().map_or_else(
                        || io::Error::other("clipboard observer exited before startup"),
                        |error| io::Error::new(error.kind(), error.to_string()),
                    );
                    let _ = ready.send(Err(startup));
                }
                result
            })?;
        match receive.recv() {
            Ok(Ok(())) => Ok(Self {
                stop,
                thread: Some(thread),
            }),
            failure => {
                let _ = thread.join();
                match failure {
                    Ok(Err(error)) => Err(error),
                    _ => Err(io::Error::other("clipboard observer startup failed")),
                }
            }
        }
    }

    fn stop(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        // The stop event works even when the message queue is full.
        unsafe {
            SetEvent(self.stop.as_raw_handle());
        }
        thread
            .join()
            .map_err(|_| io::Error::other("clipboard observer panicked"))?
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn run_window(
    mut context: Context,
    stop: &OwnedHandle,
    ready: &mut Option<mpsc::SyncSender<io::Result<()>>>,
) -> io::Result<()> {
    static NEXT_CLASS: AtomicU64 = AtomicU64::new(0);
    let serial = NEXT_CLASS.fetch_add(1, Ordering::Relaxed);
    let name: Vec<u16> = format!("SunPackClipboardMonitor_{serial:016x}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let module = GetModuleHandleW(null());
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module,
            lpszClassName: name.as_ptr(),
            ..WNDCLASSW::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(io::Error::last_os_error());
        }
        // Message-only windows never receive the volume-change broadcasts.
        let parent = if context.observe_volumes {
            null_mut()
        } else {
            HWND_MESSAGE
        };
        let window = CreateWindowExW(
            0,
            name.as_ptr(),
            null(),
            0,
            0,
            0,
            0,
            0,
            parent,
            null_mut(),
            module,
            (&mut context as *mut Context).cast(),
        );
        if window.is_null() {
            let error = io::Error::last_os_error();
            UnregisterClassW(name.as_ptr(), module);
            return Err(error);
        }
        let clipboard = context.clipboard_enabled && AddClipboardFormatListener(window) != 0;
        let result = (|| {
            if context.clipboard_enabled && !clipboard && !context.observe_volumes {
                return Err(io::Error::last_os_error());
            }
            let _ = ready
                .take()
                .expect("one clipboard startup notification")
                .send(Ok(()));
            // Read once after registration. A copy before registration leaves
            // no queued WM_CLIPBOARDUPDATE for the new window.
            if clipboard {
                context.clipboard_updated();
            }
            if context.observe_volumes {
                (context.notify)(Notification::VolumeChanged {
                    unit_mask: 0,
                    arrived: true,
                });
            }
            pump_until_stop(stop.as_raw_handle())
        })();
        if clipboard {
            RemoveClipboardFormatListener(window);
        }
        DestroyWindow(window);
        UnregisterClassW(name.as_ptr(), module);
        result
    }
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
        match message {
            WM_CLIPBOARDUPDATE if context.clipboard_enabled => {
                context.clipboard_updated();
                return 0;
            }
            WM_DEVICECHANGE if context.observe_volumes && lparam != 0 => {
                let event = wparam as u32;
                if matches!(event, DBT_DEVICEARRIVAL | DBT_DEVICEREMOVECOMPLETE) {
                    let header = unsafe { &*(lparam as *const DEV_BROADCAST_HDR) };
                    if header.dbch_devicetype == DBT_DEVTYP_VOLUME
                        && header.dbch_size as usize >= std::mem::size_of::<DEV_BROADCAST_VOLUME>()
                    {
                        let volume = unsafe { &*(lparam as *const DEV_BROADCAST_VOLUME) };
                        if volume.dbcv_unitmask != 0 {
                            (context.notify)(Notification::VolumeChanged {
                                unit_mask: volume.dbcv_unitmask,
                                arrived: event == DBT_DEVICEARRIVAL,
                            });
                        }
                    }
                    return 1;
                }
            }
            WM_CLOSE => {
                unsafe {
                    PostQuitMessage(0);
                }
                return 0;
            }
            _ => {}
        }
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
