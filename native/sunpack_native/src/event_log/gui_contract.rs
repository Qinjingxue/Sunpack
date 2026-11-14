//! Actual Rust writer -> shipped C++ query boundary; no fixture decoder.
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn project(binary: &Path, path: &Path, query: &str, cursor: &str, root: &str, status: &str) -> Value {
    let output = Command::new(binary).arg("--project").arg(path)
        .args([query, cursor, root, status]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["tasks"].take()
}
fn rows(binary: &Path, path: &Path, query: &str, root: &str, status: &str) -> BTreeMap<String, Value> {
    let mut cursor = String::new();
    let mut result = BTreeMap::new();
    loop {
        let page = project(binary, path, query, &cursor, root, status);
        let values = page["rows"].as_array().unwrap();
        assert!(values.len() <= 100);
        for row in values {
            assert!(result.insert(row["id"].as_str().unwrap().to_owned(), row.clone()).is_none(),
                "duplicate task across GUI pages");
        }
        if page["hasMore"] == false { break; }
        assert!(!values.is_empty());
        let next = page["next"].as_str().unwrap();
        assert_ne!(next, cursor);
        cursor = next.to_owned();
    }
    result
}
fn manifest(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
#[ignore = "requires the real sunpack_gui_tests.exe; run by GUI/runtime CI"]
fn rust_writer_cpp_query_lifecycle() {
    let binary = PathBuf::from(std::env::var_os("SUNPACK_GUI_TEST_BINARY")
        .expect("set SUNPACK_GUI_TEST_BINARY to the real C++ GUI test executable"));
    assert!(binary.is_file());
    let marker = crate::test_support::temp_file("gui_writer", b"");
    let root = Directory(marker.with_extension("store"));
    std::fs::remove_file(marker).unwrap();
    std::fs::create_dir(&root.0).unwrap();
    let path = root.0.join("events.json");
    let log = NativeEventLog::new(path.clone(), 7, true).unwrap();
    let base = utc_us() as f64 / 1_000_000.0 - 2.0 * 86400.0;
    for index in 0..250 {
        let source = root.0.join(if index < 100 { "one" } else { "two" })
            .join(format!("载体-{index}.fake"));
        let member = root.0.join(format!("密钥_{index}%.002"));
        let ts = base + f64::from(index / 100) * 86400.0 + f64::from(index) / 1000.0;
        log.write(json!({"event":"pipeline_sources_claimed", "owner":index.to_string(),
            "processing":true,"ts":ts,"groups":[{"path":source,"name":"payload.rar","members":[source,member]}]})).unwrap();
        log.write(json!({"event":"done","owner":index.to_string(),"path":member,"ts":ts})).unwrap();
    }
    log.flush().unwrap();
    let history = rows(&binary, &path, "", "", "");
    assert_eq!(history.len(), 250);
    for query in ["密", "密钥", "100%", "PAYLOAD.RAR"] {
        let selected = rows(&binary, &path, query, "", "");
        assert_eq!(selected.len(), if query == "100%" { 1 } else { 250 });
    }
    assert!(rows(&binary, &path, "密匙", "", "").is_empty());
    let stamp = history.values().next().unwrap()["time"].as_str().unwrap();
    for query in [stamp, &stamp[..10], &stamp[11..16]] {
        let expected: BTreeMap<_, _> = history.iter().filter(|(_, row)|
            row["time"].as_str().unwrap().contains(query)).map(|(id, row)| (id.clone(), row.clone())).collect();
        assert_eq!(rows(&binary, &path, query, "", ""), expected);
    }
    assert_eq!(rows(&binary, &path, "", &root.0.join("one").to_string_lossy(), "taskSucceeded").len(), 100);
    assert!(rows(&binary, &path, "", "", "taskFailed").is_empty());

    let a = root.0.join("carrier.001");
    let b = root.0.join("other.bin");
    let c = root.0.join("retired.part");
    log.write(json!({"event":"pipeline_sources_claimed","owner":"active","processing":true,
        "groups":[{"path":a,"name":"payload.rar","members":[a,b,c]}]})).unwrap();
    log.write(json!({"event":"failed_password","owner":"active","path":a})).unwrap();
    log.flush().unwrap();
    assert_eq!(rows(&binary, &path, "retired.part", "", "taskWaiting").len(), 1);

    // Force the real live-store compaction threshold via retired slots, not
    // by rewriting its manifest or constructing a parallel index implementation.
    for index in 0..260 {
        log.write(json!({"event":"processing_started","owner":format!("transient-{index}"),
            "path":root.0.join(format!("transient-{index}.zip"))})).unwrap();
    }
    log.flush().unwrap();
    let before = manifest(&path)["live"]["name"].clone();
    assert!(before.is_string());
    log.write(json!({"event":"task_retired","path":c})).unwrap();
    for index in 0..260 {
        log.write(json!({"event":"task_retired","scope":"task",
            "path":root.0.join(format!("transient-{index}.zip"))})).unwrap();
    }
    log.flush().unwrap();
    assert_ne!(manifest(&path)["live"]["name"], before, "live records were not compacted");
    let waiting = rows(&binary, &path, "", "", "taskWaiting");
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting.values().next().unwrap()["parts"], json!(["carrier.001", "other.bin"]));
    assert!(rows(&binary, &path, "retired.part", "", "").is_empty());
    assert_eq!(rows(&binary, &path, "", "", "taskSucceeded"), history);

    log.write(json!({"event":"processing_started","owner":"active","path":a})).unwrap();
    log.write(json!({"event":"done","owner":"active","path":b,"output_dirs":["new-output"]})).unwrap();
    log.flush().unwrap();
    let completed = rows(&binary, &path, "", "", "");
    assert_eq!(completed.len(), 251);
    assert!(completed.values().all(|row| row["status"] == "taskSucceeded"));
    drop(log);
    // Reopen the real producer, then close it before offline C++ reads.
    let log = NativeEventLog::new(path.clone(), 7, true).unwrap();
    log.flush().unwrap();
    drop(log);
    let bytes = std::fs::read(&path).unwrap();
    let folder = path.with_file_name("events.json.store");
    let files: BTreeMap<_, _> = std::fs::read_dir(folder).unwrap().map(|entry| {
        let entry = entry.unwrap();
        (entry.path(), entry.metadata().unwrap().modified().unwrap())
    }).collect();
    assert_eq!(rows(&binary, &path, "", "", ""), completed);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    for (file, modified) in files { assert_eq!(std::fs::metadata(file).unwrap().modified().unwrap(), modified); }
}
