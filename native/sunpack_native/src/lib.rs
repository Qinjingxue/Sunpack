mod analysis_native;
mod collections;
mod event_log;
mod failure_report;
mod fast_hash_core;
mod filesystem;
mod formats;
mod io;
mod output_names;
mod password;
mod path_keys;
mod postprocess;
mod relations;
mod scan;
mod wal;
mod watch_journal;
mod watch_store;

pub mod core;
pub mod pipeline;
pub mod runtime;

#[cfg(test)]
mod test_support {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sunpack_native_{name}_{nonce}.bin"));
        fs::write(&path, contents).expect("write test file");
        path
    }
}
