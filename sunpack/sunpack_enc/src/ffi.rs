//! Synchronous COM stream adaptation. No paths, Python values, or worker policy.
use crate::{Decoder, Error};
use std::{
    ffi::c_void,
    io::{Read, Seek, SeekFrom, Write},
    panic::{catch_unwind, AssertUnwindSafe},
};
type ReadFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize;
type SeekFn = unsafe extern "C" fn(*mut c_void, u64) -> i32;
type WriteFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
type ProgressFn = unsafe extern "C" fn(*mut c_void, u64) -> i32;
type AcquireFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
type ReleaseFn = unsafe extern "C" fn(*mut c_void, u32);
type AllocateFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
type CancelFn = unsafe extern "C" fn(*mut c_void) -> i32;

#[derive(Clone, Copy)]
pub(crate) struct NativeCpu {
    pub(crate) ctx: *mut c_void,
    pub(crate) acquire: AcquireFn,
    pub(crate) release: ReleaseFn,
}

pub(crate) struct HelperCredits {
    cpu: NativeCpu,
    remaining: usize,
}

pub(crate) struct HelperCredit(NativeCpu);

// SAFETY: only release crosses threads. The native callback reads the immutable
// CPU context pointer and releases from its atomic budget. The enclosing scope
// joins every helper before the synchronous FFI call can release its context.
unsafe impl Send for HelperCredit {}

impl Drop for HelperCredit {
    fn drop(&mut self) {
        unsafe { (self.0.release)(self.0.ctx, 1) }
    }
}

impl NativeCpu {
    pub(crate) fn reserve(self, wanted: usize) -> HelperCredits {
        let granted = if wanted == 0 {
            0
        } else {
            unsafe { (self.acquire)(self.ctx, wanted as u32) as usize }
        };
        let remaining = if granted == 0 {
            0
        } else {
            granted.min(wanted).min(rayon::current_num_threads())
        };
        if granted > remaining {
            unsafe { (self.release)(self.ctx, (granted - remaining) as u32) };
        }
        HelperCredits {
            cpu: self,
            remaining,
        }
    }
}

impl HelperCredits {
    pub(crate) fn len(&self) -> usize {
        self.remaining
    }
    pub(crate) fn take(&mut self) -> HelperCredit {
        assert!(self.remaining != 0);
        self.remaining -= 1;
        HelperCredit(self.cpu)
    }
}

impl Drop for HelperCredits {
    fn drop(&mut self) {
        if self.remaining != 0 {
            unsafe { (self.cpu.release)(self.cpu.ctx, self.remaining as u32) }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MemoryCallbacks {
    ctx: *mut c_void,
    allocate: AllocateFn,
    free: FreeFn,
    cancel: CancelFn,
}
impl MemoryCallbacks {
    pub(crate) fn cancelled(self) -> bool {
        unsafe { (self.cancel)(self.ctx) != 0 }
    }
}
pub(crate) struct ExternalArena {
    pub(crate) callbacks: MemoryCallbacks,
    data: *mut argon2_rust::__internal::Block,
    len: usize,
}
impl ExternalArena {
    pub(crate) fn blocks(
        &mut self,
        len: usize,
    ) -> crate::Result<&mut [argon2_rust::__internal::Block]> {
        if self.len != len {
            self.clear();
            let size = len
                .checked_mul(std::mem::size_of::<argon2_rust::__internal::Block>())
                .ok_or(Error::Memory)?;
            // Worker callback supplies zeroed, 64-byte-aligned memory. Its
            // allocator performs admission before committing the arena.
            self.data = unsafe { (self.callbacks.allocate)(self.callbacks.ctx, size) }.cast();
            if self.data.is_null() {
                return Err(Error::Memory);
            }
            self.len = len;
        }
        Ok(unsafe { std::slice::from_raw_parts_mut(self.data, self.len) })
    }
    fn clear(&mut self) {
        if !self.data.is_null() {
            unsafe {
                argon2_rust::__internal::secure_wipe_blocks(std::slice::from_raw_parts_mut(
                    self.data, self.len,
                ));
                (self.callbacks.free)(self.callbacks.ctx, self.data.cast());
            }
            self.data = std::ptr::null_mut();
            self.len = 0;
        }
    }
}
impl Drop for ExternalArena {
    fn drop(&mut self) {
        self.clear();
    }
}
struct Input {
    ctx: *mut c_void,
    read: ReadFn,
    seek: SeekFn,
}
impl Read for Input {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { (self.read)(self.ctx, bytes.as_mut_ptr(), bytes.len()) };
        if n < 0 || n as usize > bytes.len() {
            Err(std::io::ErrorKind::Other.into())
        } else {
            Ok(n as usize)
        }
    }
}
impl Seek for Input {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let SeekFrom::Start(pos) = pos else {
            return Err(std::io::ErrorKind::InvalidInput.into());
        };
        if unsafe { (self.seek)(self.ctx, pos) } != 0 {
            Err(std::io::ErrorKind::Other.into())
        } else {
            Ok(pos)
        }
    }
}
struct Output {
    ctx: *mut c_void,
    write: WriteFn,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if unsafe { (self.write)(self.ctx, bytes.as_ptr(), bytes.len()) } != 0 {
            Err(std::io::ErrorKind::Other.into())
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn status(result: crate::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(Error::Password) => 1,
        Err(Error::Authentication) => 2,
        Err(Error::Truncated) => 3,
        Err(Error::Format) => 4,
        Err(Error::Memory) => 5,
        Err(Error::Io) => 6,
        Err(Error::Cancelled) => 7,
        Err(Error::Framing) => 8,
    }
}
#[no_mangle]
pub unsafe extern "C" fn sup_enc_open(
    ctx: *mut c_void,
    read: ReadFn,
    seek: SeekFn,
    length: u64,
    password: *const u16,
    password_len: usize,
    decoder: *mut *mut Decoder,
    output_size: *mut u64,
    acquire: AcquireFn,
    release: ReleaseFn,
    allocate: AllocateFn,
    free: FreeFn,
    cancel: CancelFn,
) -> i32 {
    if decoder.is_null() || output_size.is_null() || (password.is_null() && password_len != 0) {
        return 4;
    }
    *decoder = std::ptr::null_mut();
    catch_unwind(AssertUnwindSafe(|| {
        let pw = if password_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(password, password_len)
        };
        let mut input = Input { ctx, read, seek };
        // Only the selected password reaches extraction. KDF memory is released
        // at the end of Open; the decoder retains just its small derived keys.
        let mut workspace = crate::Workspace::default();
        workspace.native_cpu = Some(NativeCpu {
            ctx,
            acquire,
            release,
        });
        workspace.external = Some(ExternalArena {
            callbacks: MemoryCallbacks {
                ctx,
                allocate,
                free,
                cancel,
            },
            data: std::ptr::null_mut(),
            len: 0,
        });
        let opened = Decoder::open_with_budget(&mut input, length, pw, workspace);
        match opened {
            Ok(value) => {
                *output_size = value.output_size();
                *decoder = Box::into_raw(Box::new(value));
                0
            }
            Err(e) => status(Err(e)),
        }
    }))
    .unwrap_or(6)
}
#[no_mangle]
pub unsafe extern "C" fn sup_enc_decrypt(
    decoder: *const Decoder,
    ctx: *mut c_void,
    read: ReadFn,
    seek: SeekFn,
    write: WriteFn,
    progress: ProgressFn,
    acquire: AcquireFn,
    release: ReleaseFn,
) -> i32 {
    if decoder.is_null() {
        return 4;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let cpu = NativeCpu {
            ctx,
            acquire,
            release,
        };
        status((*decoder).decrypt(
            &mut Input { ctx, read, seek },
            &mut Output { ctx, write },
            |cipher, offset, bytes, wanted| {
                let mut credits = cpu.reserve(wanted);
                cipher.apply_with_threads(offset, bytes, 1 + credits.len(), Some(&mut credits));
            },
            |n| {
                if progress(ctx, n) == 0 {
                    Ok(())
                } else {
                    Err(Error::Cancelled)
                }
            },
        ))
    }))
    .unwrap_or(6)
}
#[no_mangle]
pub unsafe extern "C" fn sup_enc_close(decoder: *mut Decoder) {
    if !decoder.is_null() {
        drop(Box::from_raw(decoder));
    }
}
