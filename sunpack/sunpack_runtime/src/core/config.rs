use super::{i18n::Language, resources};
use crate::io::reader::{capture_file_generation, PhysicalFileGeneration};
use crate::scan::path_filter::{NativePathRule, RuleEntry};
use serde_json::{Map, Value};
use std::{
    borrow::Cow,
    collections::VecDeque,
    env, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const SIMPLE: &str = "sunpack_config.json";
const ADVANCED: &str = "sunpack_advanced_config.json";
const OVERRIDES: &str = "SUNPACK_CONFIG_OVERRIDES";
const DEFAULTS: &str = include_str!("../../../../sunpack_advanced_config.json");
pub(crate) const CONFIG_CACHE_LIMIT: usize = 64;

#[derive(Clone, PartialEq)]
pub struct Config {
    pub cli: CliConfig,
    pub runtime: RuntimeConfig,
    pub output: OutputConfig,
    pub watch: WatchConfig,
    pub passwords: PasswordConfig,
    pub user_passwords: Arc<[Arc<str>]>,
    pub recursive_extract: Recursion,
    pub recursive_authorization: AuthorizationConfig,
    pub embedded_scan: EmbeddedConfig,
    pub extraction: ExtractionConfig,
    pub post_extract: PostExtractConfig,
    pub filesystem: FilesystemConfig,
    pub performance: PerformanceConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Clone, PartialEq)]
pub struct OutputConfig {
    pub root: Option<std::path::PathBuf>,
    pub fixed_root: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub struct CliConfig {
    pub language: Language,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMode {
    Background,
    Normal,
    High,
}

#[derive(Clone, Copy, PartialEq)]
pub struct RuntimeConfig {
    pub process_mode: ProcessMode,
}

#[derive(Clone, Copy, PartialEq)]
pub struct WatchConfig {
    pub boundary_confirmation_seconds: f64,
    pub runtime_cache_cleanup_idle_seconds: f64,
    pub clipboard_monitor_enabled: bool,
    pub clipboard_builtin_max_entries: usize,
    pub tray_enabled: bool,
    pub toast_enabled: bool,
    pub toast_report_retention_days: u64,
    pub event_log_retention_days: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub struct PasswordConfig {
    pub clipboard_passwords_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recursion {
    Infinite,
    Prompt,
    Fixed(usize),
}

#[derive(Clone, Copy, PartialEq)]
pub struct AuthorizationConfig {
    pub enabled: bool,
    pub byte_ratio_exponent: f64,
    pub project_ratio_exponent: f64,
    pub minimum_authorization_score: f64,
}

#[derive(Clone, Copy, PartialEq)]
pub struct EmbeddedConfig {
    pub enabled: bool,
    pub recursive_candidate_ratio: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentRequirement {
    Complete,
    AllowPartial,
}

#[derive(Clone, Copy, PartialEq)]
pub struct ExtractionConfig {
    pub content_requirement: ContentRequirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupMode {
    Delete,
    Recycle,
    Keep,
}

#[derive(Clone, Copy, PartialEq)]
pub struct PostExtractConfig {
    pub archive_cleanup_mode: CleanupMode,
    pub flatten_single_directory: bool,
}

#[derive(Clone, PartialEq)]
pub struct FilesystemConfig {
    pub scan_filters_enabled: bool,
    pub scan_filters: Arc<[ScanFilter]>,
}

pub type NumericBounds = [Option<u64>; 5];

#[derive(Clone, PartialEq)]
pub struct ScanFilter {
    pub enabled: bool,
    pub kind: ScanFilterKind,
}

#[derive(Clone, PartialEq)]
pub enum ScanFilterKind {
    Blacklist(PathRule),
    Whitelist(PathRule),
    SizeRange(NumericBounds),
    MtimeRange(NumericBounds),
    Unknown(Box<str>),
}

#[derive(Clone)]
pub struct PathRule {
    inner: Arc<PathRuleInner>,
}

struct PathRuleInner {
    entries: [Vec<RuleEntry>; 4],
    compiled: OnceLock<io::Result<NativePathRule>>,
}

impl PartialEq for PathRule {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.inner.entries == other.inner.entries
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct PerformanceConfig {
    pub persistent_server_idle_seconds: Option<f64>,
    pub worker: WorkerConfig,
}

#[derive(Clone, Copy, PartialEq)]
pub struct WorkerConfig {
    pub space_poll_interval_ms: Option<u64>,
    pub space_status_report_interval_ms: Option<u64>,
}

#[derive(Clone, PartialEq)]
pub struct AnalysisConfig {
    pub modules: Arc<[AnalysisModule]>,
}

#[derive(Clone, PartialEq)]
pub struct AnalysisModule {
    pub name: Box<str>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigSources {
    pub simple: Option<PathBuf>,
    pub advanced: Option<PathBuf>,
    pub override_file: Option<PathBuf>,
    inline_override: Option<Box<str>>,
}

impl ConfigSources {
    fn stamp(&self) -> io::Result<[Option<PhysicalFileGeneration>; 3]> {
        let stamp = |path: Option<&Path>| path.map(capture_file_generation).transpose();
        Ok([
            stamp(self.advanced.as_deref())?,
            stamp(self.simple.as_deref())?,
            stamp(self.override_file.as_deref())?,
        ])
    }

    pub(crate) fn primary(&self) -> &Path {
        self.simple
            .as_deref()
            .or(self.advanced.as_deref())
            .expect("valid configuration has a source")
    }
}

pub struct Snapshot {
    pub config: Config,
    pub sources: ConfigSources,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn defaults() -> &'static Value {
    static DEFAULT: OnceLock<Value> = OnceLock::new();
    DEFAULT.get_or_init(|| serde_json::from_str(DEFAULTS).expect("valid built-in configuration"))
}

pub(crate) fn default_idle_seconds() -> f64 {
    defaults()["performance"]["persistent_server_idle_seconds"]
        .as_f64()
        .expect("valid built-in idle timeout")
}

// Include absent candidates: a deletion must not unsubscribe its recreation,
// and a new higher-priority config must supersede the current source.
fn source_candidates(roots: &[PathBuf], name: &str, selected: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in roots {
        let path = root.join(name);
        let selected = selected == Some(path.as_path());
        paths.push(path);
        if selected { break; }
    }
    paths
}

pub(crate) fn watch_paths(cwd: &Path, sources: &ConfigSources) -> Vec<PathBuf> {
    let roots = resources::resource_roots(cwd);
    // Lower-priority request directories cannot change the selected source.
    // Keep the selected file and absent higher-priority candidates so deletion,
    // recreation and a newly overriding configuration still wake readers.
    let mut paths = source_candidates(&roots, ADVANCED, sources.advanced.as_deref());
    if resources::package_root().is_some() {
        if let Ok(root) = resources::program_data_dir() {
            paths.push(root.join(SIMPLE));
        }
    } else {
        paths.extend(source_candidates(&roots, SIMPLE, sources.simple.as_deref()));
    }
    paths.extend(sources.simple.iter().cloned());
    paths.extend(sources.advanced.iter().cloned());
    paths.extend(sources.override_file.iter().cloned());
    paths.sort_unstable();
    paths.dedup();
    paths
}

pub(crate) fn resolve_sources(cwd: &Path) -> ConfigSources {
    let roots = resources::resource_roots(cwd);
    let search = |name| {
        roots
            .iter()
            .map(|root| root.join(name))
            .find(|path| path.exists())
    };
    let simple = if resources::package_root().is_some() {
        resources::program_data_dir()
            .ok()
            .map(|root| root.join(SIMPLE))
            .filter(|path| path.exists())
    } else {
        search(SIMPLE)
    };
    let mut sources = ConfigSources {
        simple,
        advanced: search(ADVANCED),
        override_file: None,
        inline_override: None,
    };
    let mut inline = env::var(OVERRIDES)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if let Some(path) = inline
        .as_deref()
        .and_then(|value| std::path::absolute(value).ok())
        .filter(|path| path.is_file())
    {
        sources.override_file = Some(path);
        inline = None;
    }
    sources.inline_override = inline.map(String::into_boxed_str);
    sources
}

fn parse_file_json(path: &Path) -> io::Result<Value> {
    let text = crate::io::resource_lifecycle::read_shared_utf8_text(path)?;
    if text.starts_with('\u{feff}') {
        return Err(invalid("Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)"));
    }
    serde_json::from_str(&text).map_err(|error| invalid(format!("{}: {error}", path.display())))
}

fn parse_config_file(path: &Path) -> io::Result<Value> {
    let value = parse_file_json(path)?;
    if !value.is_object() {
        return Err(invalid(format!(
            "Config file must contain a JSON object: {}",
            path.display()
        )));
    }
    Ok(value)
}

fn merge_named(base: &mut Vec<Value>, changes: Vec<Value>) {
    // Preserve the external layer's order for configured filters. A definition
    // omitted from the new layer retains its relative position.
    use std::collections::HashMap;

    let mut indices: HashMap<_, _> = base.iter().enumerate().filter_map(|(index, item)| {
        Some((item.get("name")?.as_str()?.to_owned(), index))
    }).collect();
    let mut order = Vec::with_capacity(changes.len());
    let mut occurrences = vec![0usize; base.len()];
    for entry in changes {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            base.push(entry);
            occurrences.push(0);
            continue;
        };
        let index = if let Some(&index) = indices.get(name) {
            merge(&mut base[index], entry, MergeScope::Other);
            index
        } else {
            let index = base.len();
            indices.insert(name.to_owned(), index);
            base.push(entry);
            occurrences.push(0);
            index
        };
        order.push(index);
        occurrences[index] += 1;
    }
    let mut ordered = Vec::with_capacity(base.len());
    for index in order {
        // Duplicate names repeat their final merged definition. Move each
        // unique value directly from the layer and clone only those duplicates.
        let entry = if occurrences[index] == 1 {
            base[index].take()
        } else {
            occurrences[index] -= 1;
            base[index].clone()
        };
        ordered.push(entry);
    }
    ordered.extend(base.drain(..).enumerate().filter_map(|(index, entry)| {
        let overridden = entry.get("name").and_then(Value::as_str)
            .is_some_and(|name| indices.get(name).is_some_and(|&last| occurrences[last] != 0));
        (occurrences[index] == 0 && !overridden).then_some(entry)
    }));
    *base = ordered;
}

#[derive(Clone, Copy)]
enum MergeScope {
    Root,
    Filesystem,
    Other,
}

fn merge(base: &mut Value, layer: Value, scope: MergeScope) {
    match (base, layer) {
        (Value::Object(base), Value::Object(layer)) => {
            for (key, new) in layer {
                if let Some(old) = base.get_mut(&key) {
                    match (old, new) {
                        (Value::Array(old), Value::Array(new))
                            if matches!(scope, MergeScope::Filesystem) && key == "scan_filters" =>
                        {
                            merge_named(old, new);
                        }
                        (old, new) => {
                            let scope = if matches!(scope, MergeScope::Root) && key == "filesystem" {
                                MergeScope::Filesystem
                            } else {
                                MergeScope::Other
                            };
                            merge(old, new, scope);
                        }
                    }
                } else {
                    base.insert(key, new);
                }
            }
        }
        (old, new) => *old = new,
    }
}

impl ConfigSources {
    fn load(&self, cwd: &Path) -> io::Result<Value> {
        if self.simple.is_none() && self.advanced.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing required {SIMPLE} or {ADVANCED}. Searched: {}",
                    watch_paths(cwd, self).iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")),
            ));
        }
        let mut value = self
            .advanced
            .as_deref()
            .map(parse_config_file)
            .transpose()?
            .unwrap_or_else(|| Value::Object(Map::new()));
        if let Some(path) = self.simple.as_deref() {
            merge(&mut value, parse_config_file(path)?, MergeScope::Root);
        }
        let overrides = match (self.override_file.as_deref(), self.inline_override.as_deref()) {
            (Some(path), _) => Some(parse_file_json(path)?),
            (None, Some(text)) => {
                let layer = serde_json::from_str::<Value>(text).map_err(|error| invalid(if text.starts_with(['{', '[']) {
                    format!("{OVERRIDES} contains invalid JSON: {error}")
                } else {
                    format!("{OVERRIDES} must be an inline JSON object or an existing JSON file: {text}")
                }))?;
                Some(layer)
            }
            (None, None) => None,
        };
        if let Some(layer) = overrides {
            let object = layer.as_object()
                .ok_or_else(|| invalid(format!("{OVERRIDES} must contain a JSON object")))?;
            let unknown: Vec<_> = object.keys()
                .filter(|key| defaults().get(*key).is_none()).map(String::as_str).collect();
            if !unknown.is_empty() {
                return Err(invalid(format!("{OVERRIDES} contains unknown config sections: {}", unknown.join(", "))));
            }
            merge(&mut value, layer, MergeScope::Root);
        }
        Ok(value)
    }
}

pub fn load_raw(cwd: &Path) -> io::Result<(PathBuf, Value)> {
    let sources = resolve_sources(cwd);
    let value = sources.load(cwd)?;
    Ok((sources.primary().to_path_buf(), value))
}


struct Generation {
    stamp: Option<[Option<PhysicalFileGeneration>; 3]>,
    snapshot: Snapshot,
    revision: u64,
    language: Language,
    reload_error: Option<Arc<io::Error>>,
}

impl Generation {
    fn check_reload(&self) -> io::Result<()> {
        match &self.reload_error {
            Some(error) => Err(io::Error::new(error.kind(), Arc::clone(error))),
            None => Ok(()),
        }
    }
}

static SOURCE_REVISION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn invalidate_sources() {
    SOURCE_REVISION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

pub(crate) struct ConfigRead {
    observed: io::Result<Arc<Generation>>,
    language: Language,
    raw: Option<Value>,
}

fn inspection_path(sources: &ConfigSources) -> PathBuf {
    let path = sources.primary();
    std::fs::canonicalize(path)
        .map(|path| crate::path_keys::normalize_windows_extended_prefix(path.to_string_lossy().into_owned()).into())
        .unwrap_or_else(|_| path.to_path_buf())
}

impl ConfigRead {
    pub(crate) fn language(&self) -> Language {
        self.language
    }

    pub(crate) fn normalized(self, keep_previous: bool) -> io::Result<Config> {
        let current = self.observed?;
        if !keep_previous {
            current.check_reload()?;
        }
        Ok(current.snapshot.config.clone())
    }

    pub(crate) fn into_inspection(self) -> io::Result<(PathBuf, Value, Config)> {
        let current = self.observed?;
        current.check_reload()?;
        Ok((
            inspection_path(&current.snapshot.sources),
            self.raw.expect("inspection reads the raw configuration"),
            current.snapshot.config.clone(),
        ))
    }
}

pub(crate) fn generation(cwd: &Path) -> ConfigRead {
    read_generation(cwd, resolve_sources(cwd), ReadMode::CheckStamp)
}

#[derive(Clone, Copy)]
pub(crate) enum ReadMode {
    CheckStamp,
    Observe,
    Refresh,
    Inspect,
}

pub(crate) fn read_generation(cwd: &Path, sources: ConfigSources, mode: ReadMode) -> ConfigRead {
    static CACHE: Mutex<VecDeque<Arc<Generation>>> = Mutex::new(VecDeque::new());
    let revision = SOURCE_REVISION.load(std::sync::atomic::Ordering::Acquire);
    let previous = {
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        cache
            .iter()
            .position(|entry| entry.snapshot.sources == sources)
            .and_then(|index| cache.remove(index))
            .inspect(|entry| cache.push_front(Arc::clone(entry)))
    };
    let refresh = matches!(mode, ReadMode::Refresh | ReadMode::Inspect)
        || previous.as_ref().is_some_and(|hit| hit.revision != revision);
    if let Some(hit) = previous.as_ref().filter(|_| matches!(mode, ReadMode::Observe) && !refresh) {
        return ConfigRead {
            observed: Ok(Arc::clone(hit)),
            language: hit.language,
            raw: None,
        };
    }
    let stamp = if matches!(mode, ReadMode::Observe) { None } else { sources.stamp().ok() };
    if let Some(hit) = previous
        .as_ref()
        .filter(|hit| !refresh && stamp.is_some() && hit.stamp == stamp)
    {
        return ConfigRead {
            observed: Ok(Arc::clone(hit)),
            language: hit.language,
            raw: None,
        };
    }
    let mut language = default_language();
    let mut inspection = None;
    let read = (|| {
        let raw = sources.load(cwd)?;
        language = raw_language(&raw);
        let config = Config::parse(&raw)?;
        if matches!(mode, ReadMode::Inspect) {
            inspection = Some(raw);
        }
        Ok::<_, io::Error>(config)
    })();
    let observed = (|| {
        let (snapshot, stamp, reload_error) = match read {
            Ok(config) => (Snapshot { config, sources }, stamp, None),
            Err(error) if matches!(mode, ReadMode::Observe | ReadMode::CheckStamp) => {
                let Some(previous) = previous.as_ref() else { return Err(error); };
                (Snapshot { config: previous.snapshot.config.clone(), sources }, None, Some(Arc::new(error)))
            }
            Err(error) => return Err(error),
        };
        let current = Arc::new(Generation { stamp, snapshot, revision, language, reload_error });
        // A stamp-based reader can recheck an unavailable source on its next
        // request. Event-observed requests consume this revision even on error.
        if current.reload_error.is_some() && !matches!(mode, ReadMode::Observe) {
            return Ok(current);
        }
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        let index = cache
            .iter()
            .position(|entry| entry.snapshot.sources == current.snapshot.sources);
        if let Some(hit) = index.map(|index| &cache[index]) {
            if !refresh && current.stamp.is_some() && hit.stamp == current.stamp
                && hit.revision == revision {
                return Ok(Arc::clone(hit));
            }
            if !previous
                .as_ref()
                .is_some_and(|previous| Arc::ptr_eq(previous, hit))
            {
                // A later request already published a different generation.
                return Ok(current);
            }
            cache.remove(index.unwrap());
        } else if previous.is_some() {
            // This source was evicted while it was being read.
            return Ok(current);
        }
        cache.push_front(Arc::clone(&current));
        cache.truncate(CONFIG_CACHE_LIMIT);
        Ok(current)
    })();
    ConfigRead { observed, language, raw: inspection }
}

pub fn load_language(cwd: &Path) -> Language {
    load_raw(cwd).map_or_else(|_| default_language(), |(_, raw)| raw_language(&raw))
}

fn raw_language(raw: &Value) -> Language {
    let Some(cli) = raw.get("cli").and_then(Value::as_object) else {
        return default_language();
    };
    Language::parse(cli.get("language").and_then(Value::as_str).unwrap_or_default())
}

fn default_language() -> Language {
    Language::parse(defaults()["cli"]["language"].as_str().expect("valid built-in language"))
}

pub fn load_snapshot(cwd: &Path) -> io::Result<Snapshot> {
    snapshot(generation(cwd))
}

pub(crate) fn reload_snapshot(cwd: &Path) -> io::Result<Snapshot> {
    // File notifications are authoritative even on filesystems whose metadata
    // cannot distinguish two same-size writes within one timestamp tick.
    snapshot(read_generation(cwd, resolve_sources(cwd), ReadMode::Refresh))
}

fn snapshot(read: ConfigRead) -> io::Result<Snapshot> {
    let generation = read.observed?;
    generation.check_reload()?;
    Ok(Snapshot {
        config: generation.snapshot.config.clone(),
        sources: generation.snapshot.sources.clone(),
    })
}

pub fn load(cwd: &Path) -> io::Result<Config> {
    generation(cwd).normalized(false)
}

fn field<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let strict_nested = matches!(
        path,
        [
            "watch" | "passwords" | "recursive_authorization" | "embedded_scan",
            _,
            ..
        ]
    );
    at(value, path)
        .filter(|value| strict_nested || !value.is_null())
        .or_else(|| at(defaults(), path))
        .unwrap_or(&Value::Null)
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, &key| value.get(key))
}

fn bool_field(value: &Value, path: &[&str]) -> io::Result<bool> {
    field(value, path)
        .as_bool()
        .ok_or_else(|| invalid(format!("{} must be boolean", path.join("."))))
}

fn string_field<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    field(value, path)
        .as_str()
        .unwrap_or_default()
        .trim()
}

fn selection_field<'a>(value: &'a Value, path: &[&str], default: &'a str) -> &'a str {
    let value = field(value, path);
    if !json_truthy(value) {
        return default;
    }
    // Python stringifies truthy non-strings before checking the enum. None
    // can match these string choices; let the enum emit its normal diagnostic.
    value.as_str().unwrap_or_default().trim()
}

fn number_field(value: &Value, path: &[&str]) -> io::Result<f64> {
    number_value(field(value, path))
        .ok_or_else(|| invalid(format!("{} must be a number", path.join("."))))
}

// Normalize only Python's decimal digits and digit separators; leave the
// numeric grammar to Rust. Ordinary ASCII settings need no allocation.
fn numeric_string(value: &str) -> Option<Cow<'_, str>> {
    let value = value.trim();
    if value.is_ascii() && !value.contains('_') {
        return Some(Cow::Borrowed(value));
    }
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut digit_before = false;
    while let Some(character) = characters.next() {
        if character == '_' {
            if !digit_before || characters.peek().and_then(|&next| decimal_digit(next)).is_none() {
                return None;
            }
            digit_before = false;
        } else if let Some(digit) = decimal_digit(character) {
            normalized.push((b'0' + digit as u8) as char);
            digit_before = true;
        } else {
            normalized.push(character);
            digit_before = false;
        }
    }
    Some(Cow::Owned(normalized))
}

fn number_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| numeric_string(value.as_str()?)?.parse().ok())
        .or_else(|| value.as_bool().map(|value| f64::from(u8::from(value))))
}

fn integer_field(value: &Value, path: &[&str], min: u64) -> io::Result<u64> {
    integer_value(field(value, path))
        .map(|n| n.max(min))
        .ok_or_else(|| invalid(format!("{} must be an integer", path.join("."))))
}

fn integer_value(value: &Value) -> Option<u64> {
    value
        .as_i64()
        .map(|n| n.max(0) as u64)
        .or_else(|| value.as_u64())
        .or_else(|| value.as_bool().map(u64::from))
        .or_else(|| {
            let number = numeric_string(value.as_str()?)?;
            if let Some(negative) = number.strip_prefix('-') {
                // The field clamps negatives to zero, including Python ints
                // whose magnitude is larger than the native unsigned field.
                return (!negative.is_empty() && negative.bytes().all(|byte| byte.is_ascii_digit()))
                    .then_some(0);
            }
            number.parse::<u64>().ok()
        })
        .or_else(|| value.as_f64().map(|n| n.max(0.0) as u64))
}

fn check_section(value: &Value, section: &str, strict: bool) -> io::Result<()> {
    if value[section].is_null() {
        return Ok(());
    }
    let entries = value[section]
        .as_object()
        .ok_or_else(|| invalid(format!("{section} must be an object")))?;
    if strict {
        let unknown: Vec<_> = entries
            .keys()
            .filter(|key| defaults()[section].get(*key).is_none())
            .map(String::as_str)
            .collect();
        if !unknown.is_empty() {
            return Err(invalid(format!(
                "{section} has unknown fields: {}",
                unknown.join(", ")
            )));
        }
    }
    Ok(())
}

impl Config {
    /// Validate every saved path rule once, including disabled rules.
    pub fn validate_scan_filters(&self) -> Vec<String> {
        self.filesystem.scan_filters.iter().enumerate().filter_map(|(index, filter)| {
            let rule = match &filter.kind {
                ScanFilterKind::Blacklist(rule) | ScanFilterKind::Whitelist(rule) => rule,
                _ => return None,
            };
            rule.compile().err().map(|error| format!("filesystem.scan_filters[{index}]: {error}"))
        }).collect()
    }

    pub fn parse(value: &Value) -> io::Result<Self> {
        for section in ["runtime", "watch", "passwords", "extraction"] {
            check_section(value, section, false)?;
        }
        for section in ["recursive_authorization", "embedded_scan"] {
            check_section(value, section, true)?;
        }
        let watch = WatchConfig {
            boundary_confirmation_seconds: number_field(
                value,
                &["watch", "boundary_confirmation_seconds"],
            )?
            .max(0.0),
            runtime_cache_cleanup_idle_seconds: number_field(
                value,
                &["watch", "runtime_cache_cleanup_idle_seconds"],
            )?
            .max(0.0),
            clipboard_monitor_enabled: bool_field(value, &["watch", "clipboard_monitor_enabled"])?,
            clipboard_builtin_max_entries: integer_field(
                value,
                &["watch", "clipboard_builtin_max_entries"],
                1,
            )? as usize,
            tray_enabled: bool_field(value, &["watch", "tray_enabled"])?,
            toast_enabled: bool_field(value, &["watch", "toast_enabled"])?,
            toast_report_retention_days: integer_field(
                value,
                &["watch", "toast_report_retention_days"],
                1,
            )?,
            event_log_retention_days: integer_field(
                value,
                &["watch", "event_log_retention_days"],
                1,
            )?,
        };
        let process_mode = ProcessMode::parse(selection_field(
            value,
            &["runtime", "process_mode"],
            "normal",
        ))?;
        let recursive_extract = match field(value, &["recursive_extract"]) {
            Value::String(value) => Recursion::parse(value)?,
            Value::Number(value) => value.as_u64().filter(|&count| count > 0)
                .map(|count| Recursion::Fixed(count as usize))
                .ok_or_else(invalid_recursion)?,
            _ => return Err(invalid_recursion()),
        };
        let authorization_number = |name| {
            number_field(value, &["recursive_authorization", name])
                .map_err(|_| invalid("recursive_authorization thresholds must be numeric"))
        };
        let recursive_authorization = AuthorizationConfig {
            enabled: bool_field(value, &["recursive_authorization", "enabled"])?,
            byte_ratio_exponent: authorization_number("byte_ratio_exponent")?,
            project_ratio_exponent: authorization_number("project_ratio_exponent")?,
            minimum_authorization_score: authorization_number("minimum_authorization_score")?,
        };
        if !recursive_authorization.byte_ratio_exponent.is_finite() || recursive_authorization.byte_ratio_exponent <= 0.0 {
            return Err(invalid(
                "recursive_authorization.byte_ratio_exponent must be positive",
            ));
        }
        if !recursive_authorization.project_ratio_exponent.is_finite() || recursive_authorization.project_ratio_exponent <= 0.0 {
            return Err(invalid(
                "recursive_authorization.project_ratio_exponent must be positive",
            ));
        }
        if !(0.0..=1.0).contains(&recursive_authorization.minimum_authorization_score) {
            return Err(invalid(
                "recursive_authorization.minimum_authorization_score must be between 0 and 1",
            ));
        }
        let recursive_candidate_ratio =
            field(value, &["embedded_scan", "recursive_candidate_ratio"])
                .as_f64()
                .filter(|ratio| (0.0..=1.0).contains(ratio))
                .ok_or_else(|| {
                    invalid("embedded_scan.recursive_candidate_ratio must be between 0 and 1")
                })?;
        let filters = field(value, &["filesystem", "scan_filters"])
            .as_array()
            .ok_or_else(|| invalid("filesystem.scan_filters must be a list"))?;
        let scan_filters_enabled = bool_field(value, &["filesystem", "scan_filters_enabled"])?;
        let scan_filters = filters
            .iter()
            .enumerate()
            .map(|(index, filter)| ScanFilter::parse(index, filter))
            .collect::<io::Result<Arc<[_]>>>()?;
        // A supplied module list replaces the defaults, including a null
        // value that the analysis engine treats as no configured modules.
        let modules = at(value, &["analysis", "modules"])
            .unwrap_or(&defaults()["analysis"]["modules"])
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let name = entry["name"].as_str()?.trim();
                (!name.is_empty()).then(|| AnalysisModule {
                    name: name.into(),
                    enabled: json_truthy(&entry["enabled"]),
                })
            })
            .collect();
        let mut user_passwords: Vec<Arc<str>> = match value.get("user_passwords") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => serde::Deserialize::deserialize(value)
                .map_err(|_| invalid("user_passwords must be an array of strings"))?,
        };
        let mut seen = std::collections::HashSet::new();
        user_passwords.retain(|password| seen.insert(password.clone()));
        Ok(Self {
            user_passwords: user_passwords.into(),
            cli: CliConfig {
                language: Language::parse(field(value, &["cli", "language"]).as_str().unwrap_or_default()),
            },
            runtime: RuntimeConfig { process_mode },
            output: OutputConfig {
                root: field(value, &["output", "root"]).as_str()
                    .filter(|root| !root.is_empty()).map(std::path::PathBuf::from),
                fixed_root: json_truthy(field(value, &["output", "fixed_root"])),
            },
            watch,
            passwords: PasswordConfig {
                clipboard_passwords_enabled: bool_field(
                    value,
                    &["passwords", "clipboard_passwords_enabled"],
                )?,
            },
            recursive_extract,
            recursive_authorization,
            embedded_scan: EmbeddedConfig {
                enabled: bool_field(value, &["embedded_scan", "enabled"])?,
                recursive_candidate_ratio,
            },
            extraction: ExtractionConfig {
                content_requirement: ContentRequirement::parse(selection_field(
                    value,
                    &["extraction", "content_requirement"],
                    "complete",
                ))?,
            },
            post_extract: PostExtractConfig {
                archive_cleanup_mode: CleanupMode::parse(string_field(
                    value,
                    &["post_extract", "archive_cleanup_mode"],
                ))?,
                flatten_single_directory: bool_field(
                    value,
                    &["post_extract", "flatten_single_directory"],
                )?,
            },
            filesystem: FilesystemConfig {
                scan_filters_enabled,
                scan_filters,
            },
            performance: PerformanceConfig {
                persistent_server_idle_seconds: at(
                    value,
                    &["performance", "persistent_server_idle_seconds"],
                )
                .and_then(number_value)
                .map(|seconds| seconds.max(0.0)),
                worker: WorkerConfig {
                    space_poll_interval_ms: at(
                        value,
                        &["performance", "worker", "space_poll_interval_ms"],
                    )
                    .and_then(integer_value)
                    .filter(|&interval| interval >= 50),
                    space_status_report_interval_ms: at(
                        value,
                        &["performance", "worker", "space_status_report_interval_ms"],
                    )
                    .and_then(integer_value)
                    .filter(|&interval| interval >= 1000),
                },
            },
            analysis: AnalysisConfig { modules },
        })
    }
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

impl Default for Config {
    fn default() -> Self {
        static CONFIG: OnceLock<Config> = OnceLock::new();
        CONFIG
            .get_or_init(|| Self::parse(defaults()).expect("valid built-in configuration"))
            .clone()
    }
}

impl Recursion {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.trim() {
            "*" => Ok(Self::Infinite),
            "?" => Ok(Self::Prompt),
            count => positive_decimal(count).map(Self::Fixed).ok_or_else(invalid_recursion),
        }
    }
}

fn invalid_recursion() -> io::Error {
    invalid("recursive_extract must be \"*\", \"?\", or a positive integer")
}

// Python int accepts Unicode decimal digits and single underscores between
// digits. Use the existing Unicode property database, not a second hand-kept
// digit table. Saturation preserves the effective "deeper than any task" limit.
fn positive_decimal(value: &str) -> Option<usize> {
    let value = value.strip_prefix('+').unwrap_or(value);
    let mut result = 0usize;
    let mut digit_before = false;
    for character in value.chars() {
        if character == '_' {
            if !digit_before { return None; }
            digit_before = false;
            continue;
        }
        let digit = decimal_digit(character)?;
        result = result.saturating_mul(10).saturating_add(digit as usize);
        digit_before = true;
    }
    (digit_before && result > 0).then_some(result)
}

// Reuse the existing Unicode property database for Python decimal syntax.
pub(crate) fn decimal_digit(character: char) -> Option<u32> {
    use regex_syntax::hir::{Class, HirKind};
    static DECIMAL_RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    if character.is_ascii_digit() { return Some(character as u32 - '0' as u32); }
    let ranges = DECIMAL_RANGES.get_or_init(|| {
        let hir = regex_syntax::Parser::new().parse(r"\p{Nd}").expect("Unicode decimal class");
        let HirKind::Class(Class::Unicode(class)) = hir.kind() else { unreachable!() };
        class.iter().map(|range| (range.start() as u32, range.end() as u32)).collect()
    });
    let code = character as u32;
    let &(start, _) = ranges.iter().find(|&&(start, end)| start <= code && code <= end)?;
    Some((code - start) % 10)
}

impl ProcessMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            value if value.eq_ignore_ascii_case("background") => Ok(Self::Background),
            value if value.eq_ignore_ascii_case("normal") => Ok(Self::Normal),
            value if value.eq_ignore_ascii_case("high") => Ok(Self::High),
            _ => Err(invalid(
                "runtime.process_mode must be background, normal, or high",
            )),
        }
    }
}

impl CleanupMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "d" | "D" => Ok(Self::Delete),
            "r" | "R" => Ok(Self::Recycle),
            "k" | "K" => Ok(Self::Keep),
            _ => Err(invalid("archive_cleanup_mode must be one of: d, r, k")),
        }
    }

    pub(crate) fn option(self) -> &'static str {
        match self {
            Self::Delete => "d",
            Self::Recycle => "r",
            Self::Keep => "k",
        }
    }
}

impl ContentRequirement {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            value if value.eq_ignore_ascii_case("complete") => Ok(Self::Complete),
            value if value.eq_ignore_ascii_case("allow_partial") => Ok(Self::AllowPartial),
            _ => Err(invalid(
                "extraction.content_requirement must be 'complete' or 'allow_partial'",
            )),
        }
    }
}

fn check_keys(value: &Map<String, Value>, allowed: &[&str], label: &str) -> io::Result<()> {
    let unknown: Vec<_> = value
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(invalid(format!("{label} fields: {}", unknown.join(", "))))
    }
}

impl PathRule {
    pub fn parse(value: &Value) -> io::Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("path rule must be an object"))?;
        check_keys(
            object,
            &[
                "name",
                "enabled",
                "paths",
                "files",
                "extensions",
                "full_names",
            ],
                &format!("Unsupported {}", object.get("name").and_then(Value::as_str).map(str::trim).unwrap_or("None")),
        )?;
        let parse = |key: &str| -> io::Result<Vec<RuleEntry>> {
            let Some(value) = object.get(key) else {
                return Ok(Vec::new());
            };
            let values = value.as_array()
                .ok_or_else(|| invalid(format!("{key} must be a list of rule objects")))?;
            let entries = values.iter().enumerate().map(|(index, value)| {
                value.as_object().filter(|entry| entry.len() == 2)
                    .and_then(|entry| {
                        let value = entry.get("value")?.as_str().filter(|value| !value.is_empty())?;
                        let regex = entry.get("regex")?.as_bool()?;
                        Some(RuleEntry { value: value.into(), regex })
                    })
                    .ok_or_else(|| invalid(format!(
                        "{key}[{index}] requires a nonempty value string and a regex boolean"
                    )))
            }).collect::<io::Result<Vec<_>>>()?;
            Ok(entries)
        };
        Ok(Self {
            inner: Arc::new(PathRuleInner {
                entries: [parse("paths")?, parse("files")?, parse("extensions")?, parse("full_names")?],
                compiled: OnceLock::new(),
            }),
        })
    }

    pub(crate) fn compile(&self) -> io::Result<NativePathRule> {
        self.inner.compiled.get_or_init(|| {
            let [paths, files, extensions, full_names] = self.inner.entries.clone();
            NativePathRule::compile(paths, files, extensions, full_names)
        }).as_ref().cloned().map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }
}

impl ScanFilter {
    fn parse(index: usize, value: &Value) -> io::Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            invalid(format!(
                "filesystem.scan_filters[{index}] must be an object"
            ))
        })?;
        let name = value["name"]
            .as_str()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                invalid(format!(
                    "filesystem.scan_filters[{index}].name must not be empty"
                ))
            })?;
        let enabled = match value.get("enabled") {
            Some(value) => value.as_bool().ok_or_else(|| {
                invalid(format!(
                    "filesystem.scan_filters[{index}].enabled must be boolean"
                ))
            })?,
            None => false,
        };
        let kind = match name {
            "blacklist" => {
                ScanFilterKind::Blacklist(PathRule::parse(value)?)
            }
            "whitelist" => {
                ScanFilterKind::Whitelist(PathRule::parse(value)?)
            }
            "size_range" => {
                check_keys(
                    object,
                    &["name", "enabled", "min_bytes", "max_bytes"],
                    "Unknown range filter",
                )?;
                let size = |key: &str| {
                    optional(
                        &value[key],
                        Value::as_u64,
                        "Size bounds must be null or uint64 integer bytes",
                    )
                };
                let (min, max) = (size("min_bytes")?, size("max_bytes")?);
                if min.zip(max).is_some_and(|(min, max)| min > max) {
                    return Err(invalid("min_bytes must not exceed max_bytes"));
                }
                ScanFilterKind::SizeRange([None, min, None, max, None])
            }
            "mtime_range" => {
                check_keys(
                    object,
                    &["name", "enabled", "start_utc", "end_utc"],
                    "Unknown range filter",
                )?;
                let parse_time = |key: &str| {
                    if value[key].is_null() { return Ok(None); }
                    let text = value[key].as_str().filter(|text| {
                        let b = text.as_bytes();
                        b.len() == 17 && b.iter().enumerate().all(|(index, byte)| match index {
                            4 | 7 => *byte == b'-', 10 => *byte == b'T',
                            13 => *byte == b':', 16 => *byte == b'Z', _ => byte.is_ascii_digit(),
                        })
                    }).ok_or_else(|| invalid("Time bounds must be null or UTC minutes: YYYY-MM-DDTHH:mmZ"))?;
                    utc_minute(text).map(Some).ok_or_else(|| invalid("Invalid UTC minute"))
                };
                let (start, end) = (parse_time("start_utc")?, parse_time("end_utc")?);
                if start.zip(end).is_some_and(|(start, end)| start >= end) {
                    return Err(invalid("start_utc must precede end_utc"));
                }
                let bounds =
                    if start.is_some_and(|t| t > u64::MAX as i128) || end.is_some_and(|t| t <= 0) {
                        [Some(0), None, Some(0), None, None]
                    } else {
                        let upper = end.and_then(|t| u64::try_from(t).ok());
                        let lower = start
                            .map(|t| t.max(0) as u64)
                            .or_else(|| end.filter(|_| upper.is_none()).map(|_| 0));
                        [None, lower, upper, None, None]
                    };
                ScanFilterKind::MtimeRange(bounds)
            }
            _ => ScanFilterKind::Unknown(name.into()),
        };
        Ok(Self { enabled, kind })
    }
}

fn optional<T>(
    value: &Value,
    parse: impl FnOnce(&Value) -> Option<T>,
    error: &str,
) -> io::Result<Option<T>> {
    if value.is_null() {
        Ok(None)
    } else {
        parse(value).map(Some).ok_or_else(|| invalid(error))
    }
}

fn utc_minute(value: &str) -> Option<i128> {
    let b = value.as_bytes();
    if b.len() != 17
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b'Z'
    {
        return None;
    }
    let digits = |start: usize, end: usize| {
        b[start..end].iter().try_fold(0_i64, |n, &digit| {
            digit
                .is_ascii_digit()
                .then(|| n * 10 + i64::from(digit - b'0'))
        })
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (hour, minute) = (digits(11, 13)?, digits(14, 16)?);
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_lengths = [
        31,
        if leap_year { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year < 1
        || !(1..=12).contains(&month)
        || !(1..=month_lengths[month as usize - 1]).contains(&day)
        || hour > 23
        || minute > 59
    {
        return None;
    }
    let previous = year - 1;
    let days = previous * 365 + previous / 4 - previous / 100
        + previous / 400
        + month_lengths[..month as usize - 1].iter().sum::<i64>()
        + day
        - 1
        - 719_162;
    Some(i128::from(days * 86_400 + hour * 3600 + minute * 60) * 1_000_000_000)
}

#[cfg(test)]
mod layer_merge_tests {
    use super::*;

    #[test]
    fn explicit_null_analysis_modules_does_not_enable_builtins() {
        let default = Config::parse(&serde_json::json!({"analysis": null})).unwrap();
        let disabled = Config::parse(&serde_json::json!({"analysis": {"modules": null}})).unwrap();
        assert!(!default.analysis.modules.is_empty());
        assert!(disabled.analysis.modules.is_empty());
    }

    #[test]
    fn observed_invalid_edit_is_consumed_while_inspection_stays_strict() {
        let path = crate::test_support::temp_file("observed_config", br#"{"cli":{"language":"en"}}"#);
        let sources = ConfigSources { simple: Some(path.clone()), ..Default::default() };
        let read = |mode| read_generation(Path::new("."), sources.clone(), mode);
        let first = read(ReadMode::Observe).observed.unwrap();
        std::fs::write(&path, br#"{"cli":{"language":"zh"},"recursive_extract":0}"#).unwrap();
        invalidate_sources();
        let failed = read(ReadMode::Observe);
        assert!(failed.language() == Language::Zh);
        let fallback = failed.observed.unwrap();
        assert!(fallback.reload_error.is_some());
        assert!(fallback.snapshot.config == first.snapshot.config);
        let reused = read(ReadMode::Observe).observed.unwrap();
        assert!(Arc::ptr_eq(&fallback, &reused));
        assert!(read(ReadMode::Inspect).into_inspection().is_err());

        std::fs::write(&path, br#"{"cli":{"language":"zh"}}"#).unwrap();
        invalidate_sources();
        let current = read(ReadMode::Observe).normalized(true).unwrap();
        assert!(current.cli.language == Language::Zh);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn one_config_value_preserves_layer_precedence_and_named_filter_order() {
        let advanced = crate::test_support::temp_file("merge_advanced", br#"{"cli":{"language":"en","language":"zh"},"user_passwords":["old"],"filesystem":{"scan_filters":[{"name":"a","z":0,"a":1},{"name":"b","keep":true},{"name":"c","untouched":7}]},"analysis":{"filesystem":{"scan_filters":[{"name":"a","old":true}]}}}"#);
        let simple = crate::test_support::temp_file("merge_simple", br#"{"filesystem":{"scan_filters":[{"name":"b","extra":7},{"name":"a","a":2,"new":3}]},"user_passwords":["second","first"],"analysis":{"filesystem":{"scan_filters":[{"name":"a","new":true}]}}}"#);
        let sources = ConfigSources {
            advanced: Some(advanced.clone()),
            simple: Some(simple.clone()),
            inline_override: Some(r#"{"filesystem":{"scan_filters":[{"name":"a","last":1},{"free":true},{"name":"a","later":2}]},"cli":{"verbose":true}}"#.into()),
            ..ConfigSources::default()
        };
        let value = sources.load(Path::new(".")).unwrap();
        std::fs::remove_file(advanced).unwrap();
        std::fs::remove_file(simple).unwrap();
        let expected = serde_json::json!({
            "cli":{"language":"zh","verbose":true},
            "user_passwords":["second","first"],
            "analysis":{"filesystem":{"scan_filters":[{"name":"a","new":true}]}},
            "filesystem":{"scan_filters":[
                {"name":"a","z":0,"a":2,"new":3,"last":1,"later":2},
                {"name":"a","z":0,"a":2,"new":3,"last":1,"later":2},
                {"name":"b","keep":true,"extra":7},
                {"name":"c","untouched":7},
                {"free":true}
            ]}
        });
        assert_eq!(value, expected);
        // Both show encodings now serialize this same authoritative document,
        // without a parallel shape that can omit keys or truncate arrays.
        let encoded = serde_json::to_string_pretty(&value).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), expected);
    }
}

#[cfg(test)]
mod filter_runtime_tests {
    use super::*;

    #[test]
    fn observed_config_candidates_stop_at_selected_priority() {
        let roots = [PathBuf::from(r"C:\application"), PathBuf::from(r"C:\request")];
        let application = roots[0].join(ADVANCED);
        let request = roots[1].join(ADVANCED);
        assert_eq!(source_candidates(&roots, ADVANCED, Some(&application)), [application.clone()]);
        // Missing sources and a lower-priority selection retain the higher
        // candidate so its later creation can take precedence.
        assert_eq!(source_candidates(&roots, ADVANCED, None), [application.clone(), request.clone()]);
        assert_eq!(source_candidates(&roots, ADVANCED, Some(&request)), [application, request]);
    }

    #[test]
    fn filter_validation_errors_match_public_main_messages() {
        let cases = [
            (serde_json::json!({"name":"mtime_range","start_utc":"2026-02-30T00:00Z"}), "Invalid UTC minute"),
            (serde_json::json!({"name":"blacklist","unexpected":true}), "Unsupported blacklist fields: unexpected"),
            (serde_json::json!({"name":"blacklist","paths":[{"value":"a","regex":1}]}), "paths[0] requires a nonempty value string and a regex boolean"),
            (serde_json::json!({"name":"blacklist","paths":[["a",false]]}), "paths[0] requires a nonempty value string and a regex boolean"),
            (serde_json::json!({"name":"whitelist","paths":[{"value":"","regex":false}]}), "paths[0] requires a nonempty value string and a regex boolean"),
            (serde_json::json!({"name":"blacklist","paths":null}), "paths must be a list of rule objects"),
        ];
        for (value, expected) in cases {
            let error = match ScanFilter::parse(0, &value) {
                Ok(_) => panic!("invalid filter accepted"),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn saved_output_mapping_participates_in_runtime_configuration() {
        let mut raw = defaults().clone();
        let original = Config::parse(&raw).unwrap();
        assert!(original.output.root.is_none());
        assert!(!original.output.fixed_root);
        raw["output"] = serde_json::json!({"root": "Recovered", "fixed_root": true});
        let mapped = Config::parse(&raw).unwrap();
        assert_eq!(mapped.output.root.as_deref(), Some(std::path::Path::new("Recovered")));
        assert!(mapped.output.fixed_root);
        assert!(mapped != original);
        raw["output"]["root"] = Value::String(String::new());
        assert!(Config::parse(&raw).unwrap().output.root.is_none());
    }

    #[test]
    fn configured_user_passwords_are_literal_ordered_and_deduplicated() {
        let mut raw = defaults().clone();
        raw["user_passwords"] = serde_json::json!([" first ", "", " first ", "second\0"]);
        let config = Config::parse(&raw).unwrap();
        assert_eq!(config.user_passwords.iter().map(AsRef::as_ref).collect::<Vec<_>>(), [" first ", "", "second\0"]);
        let old = Arc::clone(&config.user_passwords);
        let second_batch = Arc::clone(&config.user_passwords);
        assert!(Arc::ptr_eq(&old, &second_batch));
        let copied_config = config.clone();
        assert!(Arc::ptr_eq(&old, &copied_config.user_passwords));
        raw["user_passwords"] = serde_json::json!(["new", " first "]);
        let updated = Config::parse(&raw).unwrap();
        assert!(!Arc::ptr_eq(&old, &updated.user_passwords));
        assert_eq!(old[0].as_ref(), " first ");
        assert_eq!(updated.user_passwords[0].as_ref(), "new");
    }

    #[test]
    fn normalized_configuration_equality_ignores_syntax_but_not_runtime_changes() {
        let mut raw = defaults().clone();
        let before = Config::parse(&raw).unwrap();
        raw["runtime"]["process_mode"] = Value::String("NORMAL".into());
        let same = Config::parse(&raw).unwrap();
        assert!(before == same);
        raw["runtime"]["process_mode"] = Value::String("background".into());
        let changed = Config::parse(&raw).unwrap();
        assert!(before != changed);
        let omitted_rules = PathRule::parse(&serde_json::json!({"name":"blacklist","enabled":true})).unwrap();
        let empty_rules = PathRule::parse(&serde_json::json!({"paths":[],"files":[],"extensions":[],"full_names":[]})).unwrap();
        // The compiled matcher is shared, and does not affect settings equality.
        omitted_rules.compile().unwrap();
        let copied = omitted_rules.clone();
        assert!(Arc::ptr_eq(&omitted_rules.inner, &copied.inner));
        assert!(copied.inner.compiled.get().is_some());
        assert!(omitted_rules == empty_rules);
    }

    #[test]
    fn disabled_rules_validate_shape_without_compiling_expressions() {
        let mut raw = defaults().clone();
        raw["filesystem"]["scan_filters"] = serde_json::json!([{
            "name": "blacklist", "enabled": false,
            "full_names": [{"value": "[", "regex": true}]
        }]);
        assert!(Config::parse(&raw).is_ok());
        assert!(!Config::parse(&raw).unwrap().validate_scan_filters().is_empty());
        raw["filesystem"]["scan_filters"][0]["name"] = Value::String(" blacklist ".into());
        assert!(Config::parse(&raw).is_ok());
        assert!(!Config::parse(&raw).unwrap().validate_scan_filters().is_empty());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String(String::new());
        assert!(Config::parse(&raw).is_err());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String("[".into());
        raw["filesystem"]["scan_filters"][0]["enabled"] = Value::Bool(true);
        let config = Config::parse(&raw).unwrap();
        assert!(crate::pipeline::scan_options(&config).is_err());
        let second = raw["filesystem"]["scan_filters"][0].clone();
        raw["filesystem"]["scan_filters"].as_array_mut().unwrap().push(second);
        assert_eq!(Config::parse(&raw).unwrap().validate_scan_filters().len(), 2);
        raw["filesystem"]["scan_filters_enabled"] = Value::Bool(false);
        assert!(crate::pipeline::scan_options(&Config::parse(&raw).unwrap()).is_ok());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["regex"] = Value::String("bad".into());
        assert!(Config::parse(&raw).is_err());
        let a = PathRule::parse(&serde_json::json!({"name":"blacklist"})).unwrap();
        let b = PathRule::parse(&serde_json::json!({"name":"whitelist", "paths":[]})).unwrap();
        assert!(a == b);
    }
}

#[cfg(test)]
mod numeric_lexical_tests {
    use super::*;

    #[test]
    fn python_numeric_config_strings_normalize_without_widening_grammar() {
        let mut strings = defaults().clone();
        strings["watch"]["clipboard_builtin_max_entries"] = Value::String("  +１_０００  ".into());
        strings["watch"]["boundary_confirmation_seconds"] = Value::String("0_5".into());
        strings["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::String("١.２e+१".into());
        strings["recursive_authorization"]["byte_ratio_exponent"] = Value::String("1_0".into());
        let mut numbers = defaults().clone();
        numbers["watch"]["clipboard_builtin_max_entries"] = Value::from(1000);
        numbers["watch"]["boundary_confirmation_seconds"] = Value::from(5.0);
        numbers["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::from(12.0);
        numbers["recursive_authorization"]["byte_ratio_exponent"] = Value::from(10.0);
        assert!(Config::parse(&strings).unwrap() == Config::parse(&numbers).unwrap());
        assert!(matches!(numeric_string(" 12.5 "), Some(Cow::Borrowed("12.5"))));
        for input in ["_1", "1_", "1__0", "+_1", "1_.0", "1._0", "1_e2", "1e_2", "1e+_2", "²", "0x10"] {
            assert!(number_value(&Value::String(input.into())).is_none(), "{input}");
            assert!(integer_value(&Value::String(input.into())).is_none(), "{input}");
        }
        for input in ["１.０", "1e２", "1_0.0"] {
            assert!(number_value(&Value::String(input.into())).is_some(), "{input}");
            assert!(integer_value(&Value::String(input.into())).is_none(), "{input}");
        }
        assert_eq!(integer_value(&Value::String("-１_２".into())), Some(0));
    }

    #[test]
    fn numeric_normalization_keeps_field_specific_bounds_and_diagnostics() {
        for (text, expected) in [("nan", 0.0), ("-inf", 0.0), ("inf", f64::INFINITY), ("1e9999", f64::INFINITY)] {
            let mut raw = defaults().clone();
            raw["watch"]["boundary_confirmation_seconds"] = Value::String(text.into());
            raw["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::String(text.into());
            let settings = Config::parse(&raw).unwrap();
            assert_eq!(settings.watch.boundary_confirmation_seconds, expected);
            assert_eq!(settings.watch.runtime_cache_cleanup_idle_seconds, expected);
        }
        for (text, expected) in [("9223372036854775808", 1u64 << 63), ("18446744073709551615", u64::MAX), ("-18446744073709551615", 1)] {
            let mut raw = defaults().clone();
            raw["watch"]["event_log_retention_days"] = Value::String(text.into());
            assert_eq!(Config::parse(&raw).unwrap().watch.event_log_retention_days, expected);
        }
        for name in ["byte_ratio_exponent", "project_ratio_exponent", "minimum_authorization_score"] {
            for text in ["nan", "inf", "-inf", "not numeric"] {
                let mut raw = defaults().clone();
                raw["recursive_authorization"][name] = Value::String(text.into());
                let error = Config::parse(&raw).err().unwrap().to_string();
                let expected = if text == "not numeric" {
                    "recursive_authorization thresholds must be numeric".to_owned()
                } else if name == "minimum_authorization_score" {
                    format!("recursive_authorization.{name} must be between 0 and 1")
                } else {
                    format!("recursive_authorization.{name} must be positive")
                };
                assert_eq!(error, expected);
            }
        }
    }

    #[test]
    fn python_positive_decimal_recursion_contract() {
        for (input, expected) in [("1_0", 10), ("١", 1), ("+１２", 12), (" १_२ ", 12), ("𝟙𝟘", 10)] {
            assert!(matches!(Recursion::parse(input), Ok(Recursion::Fixed(value)) if value == expected));
        }
        for input in ["", "_1", "1_", "1__0", "0", "-1", "²", "1.0", "+_1"] {
            assert!(Recursion::parse(input).is_err(), "{input}");
        }
        assert!(matches!(Recursion::parse(&"9".repeat(100)), Ok(Recursion::Fixed(usize::MAX))));
    }
}
