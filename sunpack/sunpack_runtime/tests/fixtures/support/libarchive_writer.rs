//! Independent test writer using the OS libarchive, with no ANSI pathname API.
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::{c_char, c_void, CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::ptr::NonNull;
use std::time::UNIX_EPOCH;

type Handle = *mut c_void;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
}

struct Library(NonNull<c_void>);
impl Library {
    fn load(name: &str) -> io::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        Ok(Self(
            NonNull::new(unsafe {
                LoadLibraryExW(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            })
            .ok_or_else(io::Error::last_os_error)?,
        ))
    }
    fn symbol(&self, name: &CStr) -> io::Result<*mut c_void> {
        let address = unsafe { GetProcAddress(self.0.as_ptr(), name.as_ptr()) };
        if address.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(address)
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0.as_ptr());
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pax,
    Zip,
}

// Resolve the C ABI from archive.h/archive_entry.h. Load only the OS DLL, never
// one from the working directory. All handles are freed before its last borrow.
macro_rules! api {
    ($($name:ident: $signature:ty),* $(,)?) => {
        struct Api { $($name: $signature,)* _library: Library }
        impl Api {
            fn load() -> io::Result<Self> {
                let library = Library::load("archiveint.dll")?;
                Ok(Self {
                    $($name: {
                        let address = library.symbol(CStr::from_bytes_with_nul(concat!(stringify!($name), "\0").as_bytes()).unwrap())?;
                        unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
                    },)*
                    _library: library,
                })
            }
        }
    };
}
api! {
    archive_version_details: unsafe extern "C" fn() -> *const c_char,
    archive_error_string: unsafe extern "C" fn(Handle) -> *const c_char,
    archive_write_new: unsafe extern "C" fn() -> Handle,
    archive_write_free: unsafe extern "C" fn(Handle) -> i32,
    archive_write_set_format_pax: unsafe extern "C" fn(Handle) -> i32,
    archive_write_set_format_zip: unsafe extern "C" fn(Handle) -> i32,
    archive_write_set_options: unsafe extern "C" fn(Handle, *const c_char) -> i32,
    archive_write_open_filename_w: unsafe extern "C" fn(Handle, *const u16) -> i32,
    archive_write_header: unsafe extern "C" fn(Handle, Handle) -> i32,
    archive_write_data: unsafe extern "C" fn(Handle, *const u8, usize) -> isize,
    archive_write_close: unsafe extern "C" fn(Handle) -> i32,
    archive_entry_new: unsafe extern "C" fn() -> Handle,
    archive_entry_free: unsafe extern "C" fn(Handle),
    archive_entry_set_pathname_utf8: unsafe extern "C" fn(Handle, *const c_char),
    archive_entry_set_mode: unsafe extern "C" fn(Handle, u16),
    archive_entry_set_size: unsafe extern "C" fn(Handle, i64),
    archive_entry_set_mtime: unsafe extern "C" fn(Handle, i64, i32),
}

struct Writer<'a> {
    handle: Handle,
    api: &'a Api,
}
impl Drop for Writer<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.archive_write_free)(self.handle);
        }
    }
}
struct Entry<'a> {
    handle: Handle,
    api: &'a Api,
}
impl Drop for Entry<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.archive_entry_free)(self.handle);
        }
    }
}
impl Writer<'_> {
    fn checked(&self, result: i32) -> io::Result<()> {
        if result == 0 {
            return Ok(());
        }
        let error = unsafe { (self.api.archive_error_string)(self.handle) };
        Err(io::Error::other(if error.is_null() {
            format!("libarchive writer failed ({result})")
        } else {
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        }))
    }
}

// Test-only locale override: archiveint uses the OS CRT state (_o_setlocale),
// separate from an application's ordinary setlocale. The fixture process serves
// one request; restore its locale after freeing all entries and the writer.
type SetLocale = unsafe extern "C" fn(i32, *const c_char) -> *const c_char;
struct Locale {
    setter: SetLocale,
    previous: CString,
    _library: Library,
}
impl Locale {
    fn set(value: &str) -> io::Result<Self> {
        let library = Library::load("ucrtbase.dll")?;
        let setter: SetLocale = unsafe { std::mem::transmute(library.symbol(c"_o_setlocale")?) };
        let previous = unsafe { setter(0, std::ptr::null()) };
        if previous.is_null() {
            return Err(io::Error::other("cannot query fixture locale"));
        }
        let previous = unsafe { CStr::from_ptr(previous) }.to_owned();
        let requested = CString::new(value).map_err(io::Error::other)?;
        if unsafe { setter(0, requested.as_ptr()) }.is_null() {
            return Err(io::Error::other(format!(
                "unsupported fixture locale: {value}"
            )));
        }
        Ok(Self {
            setter,
            previous,
            _library: library,
        })
    }
}
impl Drop for Locale {
    fn drop(&mut self) {
        unsafe {
            (self.setter)(0, self.previous.as_ptr());
        }
    }
}

pub fn write(
    root: &Path,
    output: &Path,
    paths: &[PathBuf],
    format: Format,
    locale: Option<&str>,
) -> io::Result<Value> {
    let _locale = locale.map(Locale::set).transpose()?;
    let api = Api::load()?;
    let handle = unsafe { (api.archive_write_new)() };
    if handle.is_null() {
        return Err(io::Error::other("cannot allocate libarchive writer"));
    }
    let writer = Writer { handle, api: &api };
    let version = unsafe { CStr::from_ptr((api.archive_version_details)()) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        writer.checked(match format {
            Format::Pax => (api.archive_write_set_format_pax)(handle),
            Format::Zip => (api.archive_write_set_format_zip)(handle),
        })?;
        if matches!(format, Format::Zip) {
            writer.checked((api.archive_write_set_options)(
                handle,
                c"zip:hdrcharset=UTF-8".as_ptr(),
            ))?;
        }
        let filename: Vec<u16> = output.as_os_str().encode_wide().chain(Some(0)).collect();
        writer.checked((api.archive_write_open_filename_w)(
            handle,
            filename.as_ptr(),
        ))?;
    }
    let mut buffer = [0u8; 64 * 1024];
    for relative in paths {
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(io::Error::other(
                "fixture member must be a relative file path",
            ));
        }
        let path = relative
            .to_str()
            .ok_or_else(|| io::Error::other("fixture member is not Unicode"))?;
        let path = CString::new(path.replace('\\', "/")).map_err(io::Error::other)?;
        let mut file = File::open(root.join(relative))?;
        let metadata = file.metadata()?;
        let size = i64::try_from(metadata.len()).map_err(io::Error::other)?;
        let modified = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let entry = Entry {
            handle: unsafe { (api.archive_entry_new)() },
            api: &api,
        };
        if entry.handle.is_null() {
            return Err(io::Error::other("cannot allocate libarchive entry"));
        }
        unsafe {
            // Preserve the Unicode spelling, instead of asking for an ANSI
            // string which can be NULL under CP1252 in libarchive 3.8.8.
            (api.archive_entry_set_pathname_utf8)(entry.handle, path.as_ptr());
            (api.archive_entry_set_mode)(entry.handle, 0o100644);
            (api.archive_entry_set_size)(entry.handle, size);
            (api.archive_entry_set_mtime)(
                entry.handle,
                modified.as_secs() as i64,
                modified.subsec_nanos() as i32,
            );
            writer.checked((api.archive_write_header)(handle, entry.handle))?;
        }
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let mut offset = 0;
            while offset < count {
                let written = unsafe {
                    (api.archive_write_data)(handle, buffer[offset..count].as_ptr(), count - offset)
                };
                if written < 0 {
                    writer.checked(written as i32)?;
                }
                if written == 0 {
                    return Err(io::Error::other("libarchive writer made no progress"));
                }
                offset += written as usize;
            }
        }
    }
    writer.checked(unsafe { (api.archive_write_close)(handle) })?;
    Ok(json!({"creator": format!("{version} (Unicode API)")}))
}
