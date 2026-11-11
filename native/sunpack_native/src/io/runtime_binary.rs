use crate::fast_hash_core::{hash_reader, Xxh64};
use crate::io::resource_lifecycle::TrackedFile;
use std::io;
use std::path::Path;

pub(crate) fn runtime_binary_build_id(path: &Path) -> io::Result<String> {
    hash_runtime_binary(path).map(|hash| format!("{hash:016x}"))
}

fn hash_runtime_binary(path: &Path) -> io::Result<u64> {
    let file = TrackedFile::open_reader(path, "runtime_binary_build_id")?;
    let mut hash = Xxh64::new(0);
    hash_reader(file, |data| hash.update(data))?;
    Ok(hash.digest())
}
