//! Stable non-cryptographic identities using the already bundled XXH64.
use pyo3::prelude::*;
use std::ffi::c_void;

unsafe extern "C" {
    fn SUNPACK_LZ4_XXH64(input: *const c_void, size: usize, seed: u64) -> u64;
}

fn xxh64(data: &[u8], seed: u64) -> u64 {
    // XXH64 reads this live slice synchronously and retains no pointers.
    unsafe { SUNPACK_LZ4_XXH64(data.as_ptr().cast(), data.len(), seed) }
}

#[pyfunction]
pub(crate) fn fast_hash64(py: Python<'_>, data: &[u8]) -> String {
    py.detach(|| format!("{:016x}", xxh64(data, 0)))
}

#[pyfunction]
pub(crate) fn fast_hash128(py: Python<'_>, data: &[u8]) -> String {
    py.detach(|| format!("{:016x}{:016x}", xxh64(data, 0), xxh64(data, 1)))
}

#[cfg(test)]
mod tests {
    use super::xxh64;

    #[test]
    fn bundled_xxh64_vectors() {
        assert_eq!(xxh64(b"", 0), 0xef46db3751d8e999);
        assert_eq!(xxh64(b"a", 0), 0xd24ec4f1a98c6e5b);
        assert_ne!(xxh64(b"", 0), xxh64(b"", 1));
    }
}
