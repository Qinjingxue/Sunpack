use super::resources::{self, FileMutex};
use crate::{
    fast_hash_core::{xxh64, Hash128},
    io::{
        atomic_file,
        reader::{physical_file_generation, PhysicalFileGeneration},
        resource_lifecycle::TrackedFile,
    },
    path_keys::path_key,
};
use serde::{
    de::{self, value::MapAccessDeserializer, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::value::RawValue;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
};

pub(crate) const FILENAME: &str = "builtin_passwords.json";
const DEFAULT_DOCUMENT: &str = "{\n  \"passwords\": [],\n  \"clipboard_history\": []\n}\n";

#[derive(Clone)]
struct Bucket {
    values: Arc<[Arc<str>]>,
    digest: [u8; 32],
}

pub struct PasswordSnapshot {
    global: Bucket,
    scoped: HashMap<Box<str>, Bucket>,
    signature: Box<str>,
}

impl Bucket {
    fn new(values: Vec<Arc<str>>) -> Self {
        let mut hash = Hash128::new();
        hash.update(&(values.len() as u64).to_le_bytes());
        for value in &values {
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        let digest = hash
            .hexdigest()
            .into_bytes()
            .try_into()
            .expect("XXH128 is 32 hex digits");
        Self {
            values: Arc::from(values),
            digest,
        }
    }
}

impl Default for PasswordSnapshot {
    fn default() -> Self {
        Self::new(Bucket::new(Vec::new()), HashMap::new())
    }
}

impl PasswordSnapshot {
    fn new(global: Bucket, scoped: HashMap<Box<str>, Bucket>) -> Self {
        let mut hash = Hash128::new();
        hash.update(&0_u64.to_le_bytes());
        hash.update(&global.digest);
        let mut entries: Vec<_> = scoped.iter().collect();
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        for (scope, bucket) in entries {
            hash.update(&(scope.len() as u64).to_le_bytes());
            hash.update(scope.as_bytes());
            hash.update(&bucket.digest);
        }
        Self {
            global,
            scoped,
            signature: hash.hexdigest().into_boxed_str(),
        }
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn scope_signature(&self, path: &Path) -> String {
        let mut hash = Hash128::new();
        hash.update(&self.global.digest);
        for bucket in self.scoped_buckets(path) {
            hash.update(&bucket.digest);
        }
        hash.hexdigest()
    }

    pub fn global(&self) -> &[Arc<str>] {
        &self.global.values
    }

    pub fn scoped(&self, path: &Path) -> impl Iterator<Item = &[Arc<str>]> + '_ {
        self.scoped_buckets(path)
            .map(|bucket| bucket.values.as_ref())
    }

    fn scoped_buckets(&self, path: &Path) -> impl Iterator<Item = &Bucket> + '_ {
        // Take one normalized path key per candidate scope. Ancestors are
        // borrowed from that key and share it through the rest of this lookup.
        let key = (!self.scoped.is_empty()).then(|| scope_key(path));
        let mut ancestors = key.as_deref().map(str::len);
        std::iter::from_fn(move || {
            let key = key.as_deref()?;
            while let Some(end) = ancestors {
                let current = key[..end].trim_end_matches(['\\', '/']);
                ancestors = Path::new(&key[..end])
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .and_then(Path::to_str)
                    .map(str::len);
                if let Some(bucket) = self.scoped.get(current) {
                    return Some(bucket);
                }
            }
            None
        })
    }
}

fn scope_key(path: &Path) -> String {
    let absolute = std::path::absolute(path);
    path_key(&absolute.as_deref().unwrap_or(path).to_string_lossy())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    #[serde(borrow)]
    passwords: &'a RawValue,
    #[serde(borrow, default, deserialize_with = "present_raw")]
    clipboard_history: Option<&'a RawValue>,
}

fn present_raw<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: Deserializer<'de>,
{
    <&RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<'a> {
    #[serde(borrow)]
    value: Cow<'a, str>,
    #[serde(borrow, default, deserialize_with = "present_raw")]
    scopes: Option<&'a RawValue>,
}

// The password file schema uses objects. Serde's derived struct parser also
// accepts arrays of positional fields unless we request a map explicitly.
struct JsonObject<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = JsonObject<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(JsonObject)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

fn valid_text(value: &str) -> Result<(), &'static str> {
    if value.contains('\0') {
        Err("password fields must be strings without NUL")
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct IndexBuilder {
    values: HashSet<Arc<str>>,
    global: Vec<Arc<str>>,
    scoped: HashMap<Box<str>, Vec<Arc<str>>>,
}

impl IndexBuilder {
    fn intern(&mut self, value: &str) -> Arc<str> {
        if let Some(value) = self.values.get(value) {
            return value.clone();
        }
        let value: Arc<str> = Arc::from(value);
        self.values.insert(value.clone());
        value
    }

    fn finish(self, previous: &PasswordSnapshot) -> PasswordSnapshot {
        let bucket = |mut values: Vec<Arc<str>>, previous: Option<&Bucket>| {
            let mut seen = HashSet::with_capacity(values.len());
            values.retain(|value| seen.insert(value.clone()));
            if let Some(previous) = previous.filter(|old| old.values.as_ref() == values) {
                previous.clone()
            } else {
                Bucket::new(values)
            }
        };
        PasswordSnapshot::new(
            bucket(self.global, Some(&previous.global)),
            self.scoped
                .into_iter()
                .map(|(scope, values)| {
                    let values = bucket(values, previous.scoped.get(scope.as_ref()));
                    (scope, values)
                })
                .collect(),
        )
    }
}

struct Passwords<'a>(Option<&'a mut IndexBuilder>);

impl<'de> DeserializeSeed<'de> for Passwords<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Passwords<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of password records")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut entries: A) -> Result<(), A::Error> {
        while let Some(JsonObject(record)) = entries.next_element::<JsonObject<Record<'_>>>()? {
            valid_text(&record.value).map_err(de::Error::custom)?;
            let password = self
                .0
                .as_deref_mut()
                .map(|index| index.intern(&record.value));
            if let Some(raw) = record.scopes {
                let scopes: Vec<String> =
                    serde_json::from_str(raw.get()).map_err(de::Error::custom)?;
                if scopes.is_empty() {
                    return Err(de::Error::custom(
                        "scopes must be a non-empty array of absolute directories",
                    ));
                }
                for scope in scopes {
                    let path = Path::new(&scope);
                    if !path.is_absolute() || scope.contains('\0') {
                        return Err(de::Error::custom(
                            "scope must be an absolute Windows directory",
                        ));
                    }
                    if let (Some(index), Some(password)) = (self.0.as_deref_mut(), &password) {
                        let mut key = scope_key(path);
                        key.truncate(key.trim_end_matches(['\\', '/']).len());
                        index
                            .scoped
                            .entry(key.into_boxed_str())
                            .or_default()
                            .push(password.clone());
                    }
                }
            } else if let (Some(index), Some(password)) = (self.0.as_deref_mut(), password) {
                index.global.push(password);
            }
        }
        Ok(())
    }
}

fn invalid_json(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl<'a> Document<'a> {
    fn parse(text: &'a str) -> io::Result<Self> {
        serde_json::from_str(text).map(|JsonObject(document)| document).map_err(invalid_json)
    }

    fn read_passwords(&self, index: Option<&mut IndexBuilder>) -> io::Result<()> {
        Passwords(index)
            .deserialize(&mut serde_json::Deserializer::from_str(
                self.passwords.get(),
            ))
            .map_err(invalid_json)
    }

    fn history(&self) -> io::Result<Vec<String>> {
        let Some(raw) = self.clipboard_history else {
            return Ok(Vec::new());
        };
        let values: Vec<String> = serde_json::from_str(raw.get()).map_err(invalid_json)?;
        for value in &values {
            valid_text(value)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
        }
        Ok(values)
    }
}

#[derive(Default)]
struct StoreState {
    generation: Option<PhysicalFileGeneration>,
    observed: Option<[u64; 2]>,
    snapshot: Arc<PasswordSnapshot>,
}

pub struct BuiltinStore {
    path: PathBuf,
    state: Mutex<StoreState>,
    dirty: std::sync::atomic::AtomicBool,
}

impl BuiltinStore {
    pub fn shared(cwd: &Path) -> io::Result<Arc<Self>> {
        static SOURCE: Mutex<Option<Weak<BuiltinStore>>> = Mutex::new(None);
        let path = resources::writable_data_dir(cwd)?.join(FILENAME);
        let mut source = SOURCE.lock().unwrap_or_else(|error| error.into_inner());
        let existing = source
            .as_ref()
            .and_then(Weak::upgrade)
            .filter(|store| store.path == path);
        if let Some(store) = existing {
            return Ok(store);
        }
        let store = Arc::new(Self::open(cwd)?);
        *source = Some(Arc::downgrade(&store));
        Ok(store)
    }

    pub fn open(cwd: &Path) -> io::Result<Self> {
        let path = resources::writable_data_dir(cwd)?.join(FILENAME);
        let absent = || {
            fs::symlink_metadata(&path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        };
        if absent() {
            let _lock = FileMutex::lock(&path, "SunPack.EditableFile")?;
            if absent() {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let result = publish(&path, atomic_file::rename_no_replace, |file| {
                    file.write_all(DEFAULT_DOCUMENT.as_bytes())
                });
                if let Err(error) = result {
                    // An editor that does not use the SunPack mutex can still
                    // publish between the absence check and the atomic rename.
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
            }
        }
        let store = Self {
            path,
            state: Mutex::default(),
            dirty: std::sync::atomic::AtomicBool::new(false),
        };
        if let Err(error) = store.reload() {
            eprintln!("Cannot load password JSON: {error}");
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> Arc<PasswordSnapshot> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .snapshot
            .clone()
    }

    pub fn reload(&self) -> io::Result<Arc<PasswordSnapshot>> {
        // File change notifications can observe writes with identical metadata.
        self.read_snapshot(true)
    }

    pub(crate) fn invalidate(&self) {
        self.dirty.store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn observed_snapshot(&self) -> Arc<PasswordSnapshot> {
        if self.dirty.swap(false, std::sync::atomic::Ordering::AcqRel) {
            if let Err(error) = self.reload() {
                eprintln!("Cannot load password JSON; keeping the last valid snapshot: {error}");
            }
        }
        self.snapshot()
    }

    pub(crate) fn snapshot_for_request(&self) -> Arc<PasswordSnapshot> {
        self.read_snapshot(false).unwrap_or_else(|error| {
            eprintln!("Cannot load password JSON; keeping the last valid snapshot: {error}");
            self.snapshot()
        })
    }

    fn read_snapshot(&self, force: bool) -> io::Result<Arc<PasswordSnapshot>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut file = match TrackedFile::open_reader(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if state.observed.is_some() {
                    *state = StoreState::default();
                }
                return Ok(state.snapshot.clone());
            }
            Err(error) => return Err(error),
        };
        let generation = physical_file_generation(&file).ok();
        if !force && generation.is_some() && generation == state.generation {
            return Ok(state.snapshot.clone());
        }
        let mut text = Vec::new();
        file.read_to_end(&mut text)?;
        drop(file);
        state.generation = generation;
        let observed = [xxh64(&text, 0), xxh64(&text, 1)];
        if state.observed == Some(observed) {
            return Ok(state.snapshot.clone());
        }
        // Cache invalid documents too so that only another edit needs parsing.
        state.observed = Some(observed);
        let text = std::str::from_utf8(&text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let document = Document::parse(text)?;
        let mut index = IndexBuilder::default();
        document.read_passwords(Some(&mut index))?;
        for value in document.history()? {
            let value = index.intern(&value);
            index.global.push(value);
        }
        let updated = index.finish(&state.snapshot);
        let previous = &state.snapshot;
        let same = Arc::ptr_eq(&updated.global.values, &previous.global.values)
            && updated.scoped.len() == previous.scoped.len()
            && updated.scoped.iter().all(|(key, bucket)| {
                previous
                    .scoped
                    .get(key)
                    .is_some_and(|old| Arc::ptr_eq(&bucket.values, &old.values))
            });
        if !same {
            state.snapshot = Arc::new(updated);
        }
        Ok(state.snapshot.clone())
    }

    pub fn merge_clipboard(&self, values: &[String], max_entries: usize) -> io::Result<bool> {
        if values.is_empty() || max_entries == 0 {
            return Ok(false);
        }
        let _lock = FileMutex::lock(&self.path, "SunPack.EditableFile")?;
        let original = crate::io::resource_lifecycle::read_shared_utf8_text(&self.path)?;
        let document = Document::parse(original.strip_prefix('\u{feff}').unwrap_or(&original))?;
        document.read_passwords(None)?;
        let history = document.history()?;
        let mut seen = HashSet::with_capacity(history.len() + values.len());
        let mut updated: Vec<&str> = history
            .iter()
            .map(String::as_str)
            .filter(|value| seen.insert(*value))
            .collect();
        seen.clear();
        for value in values {
            valid_text(value)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
            if seen.insert(value.as_str()) {
                updated.retain(|previous| *previous != value.as_str());
                updated.push(value);
            }
        }
        let updated = &updated[updated.len().saturating_sub(max_entries)..];
        if updated
            .iter()
            .copied()
            .eq(history.iter().map(String::as_str))
        {
            return Ok(false);
        }
        let (start, end, prefix) = match document.clipboard_history {
            Some(history) => {
                let start = history.get().as_ptr() as usize - original.as_ptr() as usize;
                (start, start + history.get().len(), "")
            }
            None => {
                let end = original.rfind('}').expect("validated password document");
                (end, end, ", \"clipboard_history\": ")
            }
        };
        publish(&self.path, atomic_file::replace_once, |file| {
            file.write_all(original[..start].as_bytes())?;
            file.write_all(prefix.as_bytes())?;
            serde_json::to_writer(&mut *file, updated).map_err(invalid_json)?;
            file.write_all(original[end..].as_bytes())
        })?;
        Ok(true)
    }
}

fn publish(
    path: &Path,
    commit: impl FnOnce(&Path, &Path) -> io::Result<()>,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let (temp, mut file) = loop {
        let serial = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp = path.with_file_name(format!(".{FILENAME}.{}.{serial}.tmp", std::process::id()));
        match OpenOptions::new().create_new(true).write(true).open(&temp) {
            Ok(file) => break (temp, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = write(&mut file);
    drop(file);
    let result = result.and_then(|()| commit(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn clipboard_passwords() -> Vec<String> {
    let Some(text) = clipboard_text() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    text.split([
        '\n', '\r', '\u{000b}', '\u{000c}', '\u{001c}', '\u{001d}', '\u{001e}', '\u{0085}',
        '\u{2028}', '\u{2029}',
    ])
    .filter(|part| {
        !part.is_empty()
            && part.chars().count() <= 512
            && !part.chars().any(|ch| ch < ' ' && ch != '\t')
    })
    .filter(|part| seen.insert(*part))
    .map(str::to_owned)
    .collect()
}

fn clipboard_text() -> Option<String> {
    use std::ffi::c_void;
    #[link(name = "user32")]
    unsafe extern "system" {
        fn OpenClipboard(window: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(format: u32) -> *mut c_void;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalSize(handle: *mut c_void) -> usize;
        fn GlobalLock(handle: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(handle: *mut c_void) -> i32;
    }
    const LIMIT: usize = 64 * 1024;
    struct Clipboard;
    impl Drop for Clipboard {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let _clipboard = Clipboard;
        let handle = GetClipboardData(13);
        if handle.is_null() {
            return None;
        }
        let units = GlobalSize(handle) / std::mem::size_of::<u16>();
        if units == 0 || units > LIMIT + 1 {
            return None;
        }
        let data = GlobalLock(handle).cast::<u16>();
        if data.is_null() {
            return None;
        }
        let text = std::slice::from_raw_parts(data, units);
        let end = text
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(units)
            .min(LIMIT);
        let result = String::from_utf16(&text[..end]).ok();
        GlobalUnlock(handle);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{atomic_file, fs, io, publish, Document, IndexBuilder, PasswordSnapshot, Write};
    use std::path::Path;

    #[test]
    fn builtin_password_documents_require_objects() {
        assert!(Document::parse(r#"[[{"value":"secret"}]]"#).is_err());
        assert!(Document::parse(r#"{"passwords":[["secret"]]}"#)
            .unwrap().read_passwords(None).is_err());
        assert!(Document::parse(r#"{"passwords":[{"value":"secret"}]}"#)
            .unwrap().read_passwords(None).is_ok());
    }

    #[test]
    fn clipboard_save_reports_share_conflict_without_waiting_for_reader() {
        use std::{os::windows::fs::OpenOptionsExt, sync::{mpsc, Mutex}, time::Duration};
        let path = crate::test_support::temp_file("clipboard_share_conflict", br#"{"passwords":[],"clipboard_history":[]}"#);
        let reader = fs::OpenOptions::new().read(true).share_mode(3).open(&path).unwrap();
        let store = super::BuiltinStore { path: path.clone(), state: Mutex::default(), dirty: Default::default() };
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(store.merge_clipboard(&["new-password".into()], 30)).unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(5));
        // Release before asserting so the former retry loop cannot leak a
        // worker or keep the test process alive on a regression.
        drop(reader);
        worker.join().unwrap();
        let error = result.expect("clipboard save waited for an external reader").unwrap_err();
        assert!(matches!(error.raw_os_error(), Some(32 | 33)));
        assert_eq!(fs::read(&path).unwrap(), br#"{"passwords":[],"clipboard_history":[]}"#);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_password_publication_preserves_concurrent_edit() {
        let path = crate::test_support::temp_file("builtin_password_creation", b"");
        fs::remove_file(&path).unwrap();
        let result = publish(&path, atomic_file::rename_no_replace, |file| {
            file.write_all(b"default")?;
            fs::write(&path, b"user edit")
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"user edit");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn persisted_password_signatures_survive_runtime_migration() {
        let text = r##"{
            "passwords": [
                {"value":"世界"},
                {"value":"#literal"},
                {"value":" secret ","scopes":["C:\\Downloads"]},
                {"value":"child","scopes":["C:\\Downloads\\child"]}
            ]
        }"##;
        let mut index = IndexBuilder::default();
        Document::parse(text)
            .unwrap()
            .read_passwords(Some(&mut index))
            .unwrap();
        let snapshot = index.finish(&PasswordSnapshot::default());
        // Existing Watch records contain these fingerprints. A schema or
        // ordering change here would retry unchanged failed archives on upgrade.
        assert_eq!(snapshot.signature(), "0871aed6a34a4efb389027260eaaf30f");
        assert_eq!(
            snapshot.scope_signature(Path::new(r"C:\Downloads\child\deep")),
            "7fa575ff785f4d5a6e3e7afaa5e05bcb",
        );
        assert_eq!(
            snapshot.scope_signature(Path::new(r"C:\different")),
            "a55be77812b08557859dab8291a7ac45",
        );
        // A scoped edit changes only receipts that inherit that bucket, not
        // every password failure under an unrelated Watch root.
        let mut changed = IndexBuilder::default();
        Document::parse(&text.replace("\"value\":\"child\"", "\"value\":\"new child\""))
            .unwrap().read_passwords(Some(&mut changed)).unwrap();
        let changed = changed.finish(&snapshot);
        assert_ne!(snapshot.scope_signature(Path::new(r"C:\Downloads\child\deep")),
            changed.scope_signature(Path::new(r"C:\Downloads\child\deep")));
        assert_eq!(snapshot.scope_signature(Path::new(r"C:\different")),
            changed.scope_signature(Path::new(r"C:\different")));

    }
}
