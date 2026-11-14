//! Actual Rust writer -> shipped C++ query boundary; no fixture decoder.
use super::*;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use windows_sys::Win32::Foundation::{ERROR_SHARING_VIOLATION, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

pub(crate) struct Directory(pub(crate) PathBuf);

impl Directory {
    pub(crate) fn new(test: &str) -> Self {
        let marker = crate::test_support::temp_file(test, b"");
        let root = Self(marker.with_extension("store"));
        fs::remove_file(marker).unwrap();
        fs::create_dir(&root.0).unwrap();
        root
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn query_output(binary: &Path, path: &Path, filters: [&str; 4]) -> Output {
    Command::new(binary).arg("--project").arg(path).args(filters).output().unwrap()
}
pub(crate) fn project(binary: &Path, path: &Path, query: &str, cursor: &str, root: &str, status: &str) -> Value {
    let output = query_output(binary, path, [query, cursor, root, status]);
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

pub(crate) fn gui_binary() -> PathBuf {
    let binary = PathBuf::from(std::env::var_os("SUNPACK_GUI_TEST_BINARY")
        .expect("set SUNPACK_GUI_TEST_BINARY to the real C++ GUI test executable"));
    assert!(binary.is_file());
    binary
}

pub(crate) struct DirectoryNotification(HANDLE);

impl DirectoryNotification {
    pub(crate) fn new(path: &Path) -> Self {
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        let handle = unsafe { FindFirstChangeNotificationW(wide.as_ptr(), 0, FILE_NOTIFY_CHANGE_FILE_NAME) };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "{}", std::io::Error::last_os_error());
        Self(handle)
    }

    pub(crate) fn wait_for_temp(&self, path: &Path) {
        while !path.is_file() {
            let result = unsafe { WaitForSingleObject(self.0, 10_000) };
            assert_eq!(result, WAIT_OBJECT_0, "writer did not stage the manifest: {path:?}");
            assert_ne!(unsafe { FindNextChangeNotification(self.0) }, 0);
        }
    }
}

impl Drop for DirectoryNotification {
    fn drop(&mut self) {
        unsafe { FindCloseChangeNotification(self.0) };
    }
}

#[test]
#[ignore = "requires the real sunpack_gui_tests.exe; run by GUI/runtime CI"]
fn rust_writer_cpp_query_publication_conflict() {
    let binary = gui_binary();
    let root = Directory::new("gui_publication");
    let path = root.0.join("events.json");
    let source = root.0.join("carrier.001");
    let log = NativeEventLog::new(path.clone(), 7, true).unwrap();
    log.write(json!({"event":"processing_started","owner":"test","path":source})).unwrap();
    log.flush().unwrap();

    // A live GUI reader shares DELETE. Replacement must let its old handle
    // keep reading the previous manifest while new readers see the new one.
    let before = fs::read(&path).unwrap();
    let mut shared = OpenOptions::new().read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path).unwrap();
    log.write(json!({"event":"failed_password","path":source})).unwrap();
    log.flush().unwrap();
    let mut old_manifest = Vec::new();
    shared.read_to_end(&mut old_manifest).unwrap();
    assert_eq!(old_manifest, before);
    drop(shared);
    let waiting = project(&binary, &path, "", "", "", "");
    assert_eq!(waiting["rows"][0]["statusText"], "等待密码");

    {
        let _held = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let changed = DirectoryNotification::new(&root.0);
        log.write(json!({"event":"suspended_missing_volume","path":source})).unwrap();
        // The real writer updates the mutable index before staging publication.
        // Wait for that boundary so the reader cannot accidentally see old slots.
        changed.wait_for_temp(&root.0.join("events.json.tmp"));
        assert_eq!(fs::read(&path).unwrap(), before);
        let pending = query_output(&binary, &path, [""; 4]);
        assert_eq!(pending.status.code(), Some(ERROR_SHARING_VIOLATION as i32),
            "{}", String::from_utf8_lossy(&pending.stdout));
    }
    log.flush().unwrap();
    assert!(log.error().unwrap().is_none());
    let healed = project(&binary, &path, "", "", "", "");
    assert_eq!(healed["rows"][0]["statusText"], "等待分卷");
    assert_eq!(healed["rows"][0]["id"], waiting["rows"][0]["id"]);
    log.write(json!({"event":"done","owner":"test","path":source,
        "output_dirs":["retained-output"]})).unwrap();
    log.flush().unwrap();
    drop(log);
    let offline = project(&binary, &path, "", "", "", "");
    assert_eq!(offline["rows"][0]["status"], "taskSucceeded");
    assert_eq!(offline["rows"][0]["outputs"], json!(["retained-output"]));
    assert!(!root.0.join("events.json.tmp").exists());
}

#[test]
#[ignore = "requires the real sunpack_gui_tests.exe; run by GUI/runtime CI"]
fn rust_writer_cpp_query_lifecycle() {
    let binary = gui_binary();
    let root = Directory::new("gui_writer");
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
