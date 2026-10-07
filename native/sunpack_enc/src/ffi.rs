//! Synchronous COM stream adaptation. No paths, Python values, or worker policy.
use crate::{Decoder, Error, Workspace};
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
        let opened = Decoder::open(&mut input, length, pw, &mut Workspace::default());
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
        status((*decoder).decrypt_with_budget(
            &mut Input { ctx, read, seek },
            &mut Output { ctx, write },
            |wanted| acquire(ctx, wanted as u32) as usize,
            |count| release(ctx, count as u32),
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
