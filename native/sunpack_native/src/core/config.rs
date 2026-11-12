use super::{i18n::Language, resources};
use crate::io::reader::{capture_file_generation, PhysicalFileGeneration};
use crate::scan::path_filter::{NativePathRule, RuleEntry};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    env, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const SIMPLE: &str = "sunpack_config.json";
const ADVANCED: &str = "sunpack_advanced_config.json";
const OVERRIDES: &str = "SUNPACK_CONFIG_OVERRIDES";
const DEFAULTS: &str = include_str!("../../../../sunpack_advanced_config.json");
const CONFIG_CACHE_LIMIT: usize = 64;

#[derive(Clone, PartialEq)]
pub struct Config {
    pub cli: CliConfig,
    pub runtime: RuntimeConfig,
    pub watch: WatchConfig,
    pub passwords: PasswordConfig,
    pub recursive_extract: Recursion,
    pub recursive_authorization: AuthorizationConfig,
    pub embedded_scan: EmbeddedConfig,
    pub extraction: ExtractionConfig,
    pub post_extract: PostExtractConfig,
    pub filesystem: FilesystemConfig,
    pub performance: PerformanceConfig,
    pub analysis: AnalysisConfig,
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
    raw: Arc<Value>,
    compiled: Option<NativePathRule>,
}

impl PartialEq for PathRule {
    fn eq(&self, other: &Self) -> bool { self.raw == other.raw }
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
pub(crate) fn watch_paths(cwd: &Path, sources: &ConfigSources) -> Vec<PathBuf> {
    let roots = resources::resource_roots(cwd);
    let mut paths: Vec<_> = roots.iter().map(|root| root.join(ADVANCED)).collect();
    if resources::package_root().is_some() {
        if let Ok(root) = resources::program_data_dir() {
            paths.push(root.join(SIMPLE));
        }
    } else {
        paths.extend(roots.iter().map(|root| root.join(SIMPLE)));
    }
    paths.extend(sources.simple.iter().cloned());
    paths.extend(sources.advanced.iter().cloned());
    paths.extend(sources.override_file.iter().cloned());
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn resolve_sources(cwd: &Path) -> ConfigSources {
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
        .map(|value| cwd.join(value))
        .filter(|path| path.is_file())
    {
        sources.override_file = Some(path);
        inline = None;
    }
    sources.inline_override = inline.map(String::into_boxed_str);
    sources
}

fn parse_json(text: &str, path: &Path) -> io::Result<Value> {
    let value: Value = serde_json::from_str(text)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
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
    let mut names = Vec::new();
    let mut unnamed = Vec::new();
    for entry in changes {
        let Some(name) = entry.get("name").and_then(Value::as_str).map(str::to_owned) else {
            unnamed.push(entry);
            continue;
        };
        if let Some(existing) = base
            .iter_mut()
            .rev()
            .find(|item| item["name"] == name.as_str())
        {
            merge(existing, entry, false);
        } else {
            base.push(entry);
        }
        names.push(name);
    }
    let mut ordered = Vec::with_capacity(base.len() + unnamed.len());
    for name in &names {
        if let Some(entry) = base.iter().rev().find(|item| item["name"] == name.as_str()) {
            ordered.push(entry.clone());
        }
    }
    ordered.extend(base.drain(..).filter(|entry| {
        entry["name"]
            .as_str()
            .is_none_or(|name| !names.iter().any(|item| item == name))
    }));
    ordered.extend(unnamed);
    *base = ordered;
}

fn merge(base: &mut Value, layer: Value, filesystem: bool) {
    match (base, layer) {
        (Value::Object(base), Value::Object(layer)) => {
            for (key, new) in layer {
                if let Some(old) = base.get_mut(&key) {
                    match (old, new) {
                        (Value::Array(old), Value::Array(new))
                            if filesystem && key == "scan_filters" =>
                        {
                            merge_named(old, new);
                        }
                        (old, new) => merge(old, new, key == "filesystem"),
                    }
                } else {
                    base.insert(key, new);
                }
            }
        }
        (old, new) => *old = new,
    }
}

struct Layers {
    sources: ConfigSources,
    advanced: Option<String>,
    simple: Option<String>,
    overrides: Option<String>,
}

impl Layers {
    fn read(sources: ConfigSources) -> io::Result<Self> {
        use crate::io::resource_lifecycle::read_shared_utf8_text;
        if sources.simple.is_none() && sources.advanced.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing required {SIMPLE} or {ADVANCED}"),
            ));
        }
        let advanced = sources
            .advanced
            .clone()
            .map(read_shared_utf8_text)
            .transpose()?;
        let simple = sources
            .simple
            .clone()
            .map(read_shared_utf8_text)
            .transpose()?;
        let overrides = match sources.override_file.clone() {
            Some(path) => Some(read_shared_utf8_text(path)?),
            None => sources.inline_override.as_deref().map(str::to_owned),
        };
        Ok(Self {
            sources,
            advanced,
            simple,
            overrides,
        })
    }

    fn parse(&self) -> io::Result<Value> {
        let mut value = match self
            .sources
            .advanced
            .as_deref()
            .zip(self.advanced.as_deref())
        {
            Some((path, text)) => parse_json(text, path)?,
            None => Value::Object(Map::new()),
        };
        if let Some((path, text)) = self.sources.simple.as_deref().zip(self.simple.as_deref()) {
            merge(&mut value, parse_json(text, path)?, false);
        }
        if let Some(text) = self.overrides.as_deref() {
            let layer = match self.sources.override_file.as_deref() {
                Some(path) => parse_json(text, path)?,
                None => serde_json::from_str(text).map_err(|error| {
                    invalid(format!("{OVERRIDES} must be an inline JSON object or an existing JSON file: {error}"))
                })?,
            };
            let object = layer
                .as_object()
                .ok_or_else(|| invalid(format!("{OVERRIDES} must contain a JSON object")))?;
            let unknown: Vec<_> = object
                .keys()
                .filter(|key| defaults().get(*key).is_none())
                .map(String::as_str)
                .collect();
            if !unknown.is_empty() {
                return Err(invalid(format!(
                    "{OVERRIDES} contains unknown config sections: {}",
                    unknown.join(", ")
                )));
            }
            merge(&mut value, layer, false);
        }
        Ok(value)
    }
}

pub fn load_raw(cwd: &Path) -> io::Result<(PathBuf, Value)> {
    let layers = Layers::read(resolve_sources(cwd))?;
    let value = layers.parse()?;
    Ok((layers.sources.primary().to_path_buf(), value))
}

struct Generation {
    stamp: Option<[Option<PhysicalFileGeneration>; 3]>,
    snapshot: Snapshot,
}

pub(crate) struct ConfigRead {
    observed: io::Result<Arc<Generation>>,
    previous: Option<Arc<Generation>>,
    language: Language,
}

impl ConfigRead {
    pub(crate) fn language(&self) -> Language {
        self.language
    }

    pub(crate) fn normalized(self, keep_previous: bool) -> io::Result<Config> {
        match self.observed {
            Ok(current) => Ok(current.snapshot.config.clone()),
            Err(error) => match self.previous.filter(|_| keep_previous) {
                Some(previous) => Ok(previous.snapshot.config.clone()),
                None => Err(error),
            },
        }
    }
}

pub(crate) fn generation(cwd: &Path) -> ConfigRead {
    read_generation(cwd, false)
}

fn read_generation(cwd: &Path, refresh: bool) -> ConfigRead {
    static CACHE: Mutex<VecDeque<Arc<Generation>>> = Mutex::new(VecDeque::new());
    let sources = resolve_sources(cwd);
    let previous = {
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        cache
            .iter()
            .position(|entry| entry.snapshot.sources == sources)
            .and_then(|index| cache.remove(index))
            .inspect(|entry| cache.push_front(Arc::clone(entry)))
    };
    let stamp = sources.stamp().ok();
    if let Some(hit) = previous
        .as_ref()
        .filter(|hit| !refresh && stamp.is_some() && hit.stamp == stamp)
    {
        return ConfigRead {
            observed: Ok(Arc::clone(hit)),
            previous: None,
            language: hit.snapshot.config.cli.language,
        };
    }
    let mut language = Language::Zh;
    let observed = (|| {
        let layers = Layers::read(sources)?;
        let raw = layers.parse()?;
        language = raw_language(&raw);
        let config = Config::parse(&raw)?;
        let current = Arc::new(Generation {
            stamp,
            snapshot: Snapshot {
                config,
                sources: layers.sources,
            },
        });
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        let index = cache
            .iter()
            .position(|entry| entry.snapshot.sources == current.snapshot.sources);
        if let Some(hit) = index.map(|index| &cache[index]) {
            if !refresh && current.stamp.is_some() && hit.stamp == current.stamp {
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
    ConfigRead {
        observed,
        previous,
        language,
    }
}

pub fn load_language(cwd: &Path) -> Language {
    load_raw(cwd).map_or(Language::Zh, |(_, raw)| raw_language(&raw))
}

fn raw_language(raw: &Value) -> Language {
    Language::parse(field(raw, &["cli", "language"]).as_str().unwrap_or(""))
}

pub fn load_snapshot(cwd: &Path) -> io::Result<Snapshot> {
    snapshot(generation(cwd))
}

pub(crate) fn reload_snapshot(cwd: &Path) -> io::Result<Snapshot> {
    // File notifications are authoritative even on filesystems whose metadata
    // cannot distinguish two same-size writes within one timestamp tick.
    snapshot(read_generation(cwd, true))
}

fn snapshot(read: ConfigRead) -> io::Result<Snapshot> {
    let generation = read.observed?;
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

fn string_field(value: &Value, path: &[&str]) -> String {
    field(value, path)
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn selection_field(value: &Value, path: &[&str], default: &str) -> io::Result<String> {
    let value = field(value, path);
    if !json_truthy(value) {
        return Ok(default.into());
    }
    value
        .as_str()
        .map(|name| name.trim().to_ascii_lowercase())
        .ok_or_else(|| invalid(format!("{} must be a string", path.join("."))))
}

fn number_field(value: &Value, path: &[&str]) -> io::Result<f64> {
    number_value(field(value, path))
        .ok_or_else(|| invalid(format!("{} must be a number", path.join("."))))
}

fn number_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.trim().parse().ok())
        .or_else(|| value.as_bool().map(|value| f64::from(u8::from(value))))
        .filter(|value| value.is_finite())
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
            value
                .as_str()?
                .trim()
                .parse::<i64>()
                .ok()
                .map(|n| n.max(0) as u64)
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
    /// Explicit validation includes disabled expressions; runtime parsing does not.
    pub fn validate_scan_filters(value: &Value) -> io::Result<()> {
        let filters = field(value, &["filesystem", "scan_filters"]).as_array()
            .ok_or_else(|| invalid("filesystem.scan_filters must be a list"))?;
        for (index, filter) in filters.iter().enumerate() {
            ScanFilter::parse(index, filter, true)?;
            if matches!(filter["name"].as_str().map(str::trim), Some("blacklist" | "whitelist")) {
                PathRule::parse(filter)?;
            }
        }
        Ok(())
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
        let process_mode = ProcessMode::parse(&selection_field(
            value,
            &["runtime", "process_mode"],
            "normal",
        )?)?;
        let recursive_extract = Recursion::parse(
            &field(value, &["recursive_extract"])
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| field(value, &["recursive_extract"]).to_string()),
        )?;
        let recursive_authorization = AuthorizationConfig {
            enabled: bool_field(value, &["recursive_authorization", "enabled"])?,
            byte_ratio_exponent: number_field(
                value,
                &["recursive_authorization", "byte_ratio_exponent"],
            )?,
            project_ratio_exponent: number_field(
                value,
                &["recursive_authorization", "project_ratio_exponent"],
            )?,
            minimum_authorization_score: number_field(
                value,
                &["recursive_authorization", "minimum_authorization_score"],
            )?,
        };
        if recursive_authorization.byte_ratio_exponent <= 0.0 {
            return Err(invalid(
                "recursive_authorization.byte_ratio_exponent must be positive",
            ));
        }
        if recursive_authorization.project_ratio_exponent <= 0.0 {
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
            .map(|(index, filter)| ScanFilter::parse(index, filter, scan_filters_enabled))
            .collect::<io::Result<Arc<[_]>>>()?;
        let modules = field(value, &["analysis", "modules"])
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
        Ok(Self {
            cli: CliConfig {
                language: raw_language(value),
            },
            runtime: RuntimeConfig { process_mode },
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
                content_requirement: ContentRequirement::parse(&selection_field(
                    value,
                    &["extraction", "content_requirement"],
                    "complete",
                )?)?,
            },
            post_extract: PostExtractConfig {
                archive_cleanup_mode: CleanupMode::parse(&string_field(
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
            count => positive_decimal(count)
                .map(Self::Fixed)
                .ok_or_else(|| {
                    invalid("recursive_extract must be \"*\", \"?\", or a positive integer")
                }),
        }
    }
}

// Python int accepts Unicode decimal digits and single underscores between
// digits. Use the existing Unicode property database, not a second hand-kept
// digit table. Saturation preserves the effective "deeper than any task" limit.
fn positive_decimal(value: &str) -> Option<usize> {
    use regex_syntax::hir::{Class, HirKind};
    static DECIMAL_RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    let value = value.strip_prefix('+').unwrap_or(value);
    let mut result = 0usize;
    let mut digit_before = false;
    for character in value.chars() {
        if character == '_' {
            if !digit_before { return None; }
            digit_before = false;
            continue;
        }
        let digit = if character.is_ascii_digit() {
            character as u32 - '0' as u32
        } else {
            let ranges = DECIMAL_RANGES.get_or_init(|| {
                let hir = regex_syntax::Parser::new().parse(r"\p{Nd}").expect("Unicode decimal class");
                let HirKind::Class(Class::Unicode(class)) = hir.kind() else { unreachable!() };
                class.iter().map(|range| (range.start() as u32, range.end() as u32)).collect()
            });
            let code = character as u32;
            let &(start, _) = ranges.iter().find(|&&(start, end)| start <= code && code <= end)?;
            (code - start) % 10
        };
        result = result.saturating_mul(10).saturating_add(digit as usize);
        digit_before = true;
    }
    (digit_before && result > 0).then_some(result)
}

impl ProcessMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "background" => Ok(Self::Background),
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            _ => Err(invalid(
                "runtime.process_mode must be background, normal, or high",
            )),
        }
    }
}

impl CleanupMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "d" => Ok(Self::Delete),
            "r" => Ok(Self::Recycle),
            "k" => Ok(Self::Keep),
            _ => Err(invalid("archive_cleanup_mode must be one of: d, r, k")),
        }
    }
}

impl ContentRequirement {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "complete" => Ok(Self::Complete),
            "allow_partial" => Ok(Self::AllowPartial),
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
        Self::parse_for_runtime(value, true)
    }

    fn parse_for_runtime(value: &Value, compile: bool) -> io::Result<Self> {
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
            "Unsupported path rule",
        )?;
        let parse = |key: &str| -> io::Result<Vec<RuleEntry>> {
            let Some(value) = object.get(key) else {
                return Ok(Vec::new());
            };
            let entries: Vec<RuleEntry> = Vec::deserialize(value)
                .map_err(|error| invalid(format!("{key} must be a list of rule objects: {error}")))?;
            if let Some(index) = entries.iter().position(|entry| entry.value.is_empty()) {
                return Err(invalid(format!("{key}[{index}] requires a nonempty value string")));
            }
            Ok(entries)
        };
        // Disabled rules still undergo structural validation. Retain their raw
        // form for reload equality and explicit config validation, but do not
        // compile expressions that cannot participate in this runtime scan.
        let (paths, files, extensions, full_names) =
            (parse("paths")?, parse("files")?, parse("extensions")?, parse("full_names")?);
        let compiled = if compile {
            Some(NativePathRule::compile(paths, files, extensions, full_names)?)
        } else {
            None
        };
        let mut raw = object.clone();
        raw.remove("name");
        raw.remove("enabled");
        for key in ["paths", "files", "extensions", "full_names"] {
            raw.entry(key.to_owned()).or_insert_with(|| Value::Array(Vec::new()));
        }
        Ok(Self { raw: Arc::new(Value::Object(raw)), compiled })
    }

    pub(crate) fn compiled(&self) -> NativePathRule {
        self.compiled.as_ref().expect("enabled runtime rule is compiled").clone()
    }
}

impl ScanFilter {
    fn parse(index: usize, value: &Value, globally_enabled: bool) -> io::Result<Self> {
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
                ScanFilterKind::Blacklist(PathRule::parse_for_runtime(value, enabled && globally_enabled).map_err(|error| {
                    invalid(format!("filesystem.scan_filters[{index}]: {error}"))
                })?)
            }
            "whitelist" => {
                ScanFilterKind::Whitelist(PathRule::parse_for_runtime(value, enabled && globally_enabled).map_err(|error| {
                    invalid(format!("filesystem.scan_filters[{index}]: {error}"))
                })?)
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
                    optional(
                        &value[key],
                        |v| utc_minute(v.as_str()?),
                        "Time bounds must be null or UTC minutes: YYYY-MM-DDTHH:mmZ",
                    )
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
mod filter_runtime_tests {
    use super::*;

    #[test]
    fn normalized_configuration_equality_ignores_syntax_but_not_runtime_changes() {
        let before = Config::parse(&serde_json::json!({})).unwrap();
        let same = Config::parse(&serde_json::json!({"runtime":{"process_mode":"NORMAL"}})).unwrap();
        assert!(before == same);
        let changed = Config::parse(&serde_json::json!({"runtime":{"process_mode":"background"}})).unwrap();
        assert!(before != changed);
        let omitted_rules = PathRule::parse(&serde_json::json!({"name":"blacklist","enabled":true})).unwrap();
        let empty_rules = PathRule::parse(&serde_json::json!({"paths":[],"files":[],"extensions":[],"full_names":[]})).unwrap();
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
        assert!(Config::validate_scan_filters(&raw).is_err());
        raw["filesystem"]["scan_filters"][0]["name"] = Value::String(" blacklist ".into());
        assert!(Config::parse(&raw).is_ok());
        assert!(Config::validate_scan_filters(&raw).is_err());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String(String::new());
        assert!(Config::parse(&raw).is_err());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String("[".into());
        raw["filesystem"]["scan_filters"][0]["enabled"] = Value::Bool(true);
        assert!(Config::parse(&raw).is_err());
        raw["filesystem"]["scan_filters_enabled"] = Value::Bool(false);
        assert!(Config::parse(&raw).is_ok());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["regex"] = Value::String("bad".into());
        assert!(Config::parse(&raw).is_err());
        let a = PathRule::parse_for_runtime(&serde_json::json!({"name":"blacklist"}), false).unwrap();
        let b = PathRule::parse_for_runtime(&serde_json::json!({"name":"whitelist", "paths":[]}), false).unwrap();
        assert!(a == b);
    }
}

#[cfg(test)]
mod recursion_lexical_tests {
    use super::*;

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
