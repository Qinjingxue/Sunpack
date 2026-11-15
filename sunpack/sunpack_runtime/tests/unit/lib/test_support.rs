use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough for tests")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sunpack_runtime_{name}_{nonce}.bin"));
    fs::write(&path, contents).expect("write test file");
    path
}

pub(crate) fn built_worker() -> std::io::Result<PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile = std::env::var("SUNPACK_TEST_BUILD_PROFILE").unwrap_or_else(|_| "ci".into());
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    let path = root.join(format!(
        ".cache/native/{arch}/{profile}/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe"
    ));
    fs::metadata(&path)?;
    Ok(path)
}
