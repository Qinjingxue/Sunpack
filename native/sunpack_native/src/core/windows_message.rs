use std::{io, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
    System::Threading::INFINITE,
    UI::WindowsAndMessaging::{
        DispatchMessageW, MsgWaitForMultipleObjectsEx, PeekMessageW, MSG, MWMO_INPUTAVAILABLE,
        PM_REMOVE, QS_ALLINPUT, WM_QUIT,
    },
};

pub(crate) fn pump_until_stop(stop: HANDLE) -> io::Result<()> {
    let mut message = MSG::default();
    loop {
        unsafe {
            match MsgWaitForMultipleObjectsEx(1, &stop, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE)
            {
                WAIT_OBJECT_0 => return Ok(()),
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                _ if PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) != 0 => {
                    if message.message == WM_QUIT {
                        return Ok(());
                    }
                    DispatchMessageW(&message);
                }
                _ => {}
            }
        }
    }
}
