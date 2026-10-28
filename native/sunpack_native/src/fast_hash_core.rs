//! Streaming identities backed by the same bundled XXH64 as the one-shot API.
use std::ffi::c_void;
use std::io::{self, Read};

// Layout of XXH64_state_t in the bundled native/third_party/lz4/xxhash.h.
// Inline states own no pointers or buffers outside this object.
#[repr(C)]
#[derive(Default)]
pub(crate) struct Xxh64 {
    total_len: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    mem64: [u64; 4],
    memsize: u32,
    reserved: [u32; 2],
}

unsafe extern "C" {
    fn SUNPACK_LZ4_XXH64(input: *const c_void, size: usize, seed: u64) -> u64;
    fn SUNPACK_LZ4_XXH64_reset(state: *mut Xxh64, seed: u64) -> u32;
    fn SUNPACK_LZ4_XXH64_update(state: *mut Xxh64, input: *const c_void, size: usize) -> u32;
    fn SUNPACK_LZ4_XXH64_digest(state: *const Xxh64) -> u64;
}

pub(crate) fn xxh64(data: &[u8], seed: u64) -> u64 {
    // The C implementation reads synchronously and retains no slice pointers.
    unsafe { SUNPACK_LZ4_XXH64(data.as_ptr().cast(), data.len(), seed) }
}

impl Xxh64 {
    pub(crate) fn new(seed: u64) -> Self {
        let mut state = Self::default();
        unsafe { SUNPACK_LZ4_XXH64_reset(&mut state, seed) };
        state
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // Exclusive state access; input is borrowed only for this call.
        unsafe { SUNPACK_LZ4_XXH64_update(self, data.as_ptr().cast(), data.len()) };
    }

    pub(crate) fn digest(&self) -> u64 {
        unsafe { SUNPACK_LZ4_XXH64_digest(self) }
    }
}

pub(crate) struct Hash128([Xxh64; 2]);

impl Hash128 {
    pub(crate) fn new() -> Self {
        Self([Xxh64::new(0), Xxh64::new(1)])
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for state in &mut self.0 {
            state.update(data);
        }
    }

    pub(crate) fn hexdigest(&self) -> String {
        format!("{:016x}{:016x}", self.0[0].digest(), self.0[1].digest())
    }
}

pub(crate) fn hash_reader(mut reader: impl Read, mut update: impl FnMut(&[u8])) -> io::Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(());
        }
        update(&buffer[..count]);
    }
}
