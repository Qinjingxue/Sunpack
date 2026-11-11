use super::{i18n::Language, resources};
use crate::scan::path_filter::{NativePathRule, RuleEntry};
use serde_json::{Map, Value};
use std::{
    env, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const SIMPLE: &str = "sunpack_config.json";
const ADVANCED: &str = "sunpack_advanced_config.json";
const OVERRIDES: &str = "SUNPACK_CONFIG_OVERRIDES";
const DEFAULTS: &str = include_str!("../../../../sunpack_advanced_config.json");

#[derive(Clone)]
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

#[derive(Clone, Copy)]
pub struct CliConfig {
    pub language: Language,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMode {
    Background,
    Normal,
    High,
}

#[derive(Clone, Copy)]
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

#[derive(Clone, Copy)]
pub struct PasswordConfig {
    pub clipboard_passwords_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recursion {
    Infinite,
    Prompt,
    Fixed(usize),
}

#[derive(Clone, Copy)]
pub struct AuthorizationConfig {
    pub enabled: bool,
    pub byte_ratio_exponent: f64,
    pub project_ratio_exponent: f64,
    pub minimum_authorization_score: f64,
}

#[derive(Clone, Copy)]
pub struct EmbeddedConfig {
    pub enabled: bool,
    pub recursive_candidate_ratio: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentRequirement {
    Complete,
    AllowPartial,
}

#[derive(Clone, Copy)]
pub struct ExtractionConfig {
    pub content_requirement: ContentRequirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupMode {
    Delete,
    Recycle,
    Keep,
}

#[derive(Clone, Copy)]
pub struct PostExtractConfig {
    pub archive_cleanup_mode: CleanupMode,
    pub flatten_single_directory: bool,
}

#[derive(Clone)]
pub struct FilesystemConfig {
    pub scan_filters_enabled: bool,
    pub scan_filters: Arc<[ScanFilter]>,
}

pub type NumericBounds = [Option<u64>; 5];

#[derive(Clone)]
pub struct ScanFilter {
    pub enabled: bool,
    pub kind: ScanFilterKind,
}

#[derive(Clone)]
pub enum ScanFilterKind {
    Blacklist(PathRule),
    Whitelist(PathRule),
    SizeRange(NumericBounds),
    MtimeRange(NumericBounds),
    Unknown(Box<str>),
}

#[derive(Clone)]
pub struct PathRule(NativePathRule);

#[derive(Clone, Copy)]
pub struct PerformanceConfig {
    pub persistent_server_idle_seconds: f64,
    pub worker: WorkerConfig,
}

#[derive(Clone, Copy)]
pub struct WorkerConfig {
    pub space_poll_interval_ms: u64,
    pub space_status_report_interval_ms: u64,
}

#[derive(Clone)]
pub struct AnalysisConfig {
    pub modules: Arc<[AnalysisModule]>,
}

#[derive(Clone)]
pub struct AnalysisModule {
    pub name: Box<str>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigSources {
    pub simple: Option<PathBuf>,
    pub advanced: Option<PathBuf>,
    pub override_file: Option<PathBuf>,
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

fn resolve_sources(cwd: &Path) -> (ConfigSources, Option<String>) {
    let roots = resources::resource_roots(cwd);
    let search = |name| {
        roots
            .iter()
            .map(|root| root.join(name))
            .find(|path| path.is_file())
    };
    let simple = if resources::package_root().is_some() {
        resources::program_data_dir()
            .ok()
            .map(|root| root.join(SIMPLE))
            .filter(|path| path.is_file())
    } else {
        search(SIMPLE)
    };
    let mut sources = ConfigSources {
        simple,
        advanced: search(ADVANCED),
        override_file: None,
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
    (sources, inline)
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
    fn read(cwd: &Path) -> io::Result<Self> {
        use crate::io::resource_lifecycle::read_shared_utf8_text;
        let (sources, inline) = resolve_sources(cwd);
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
            None => inline,
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

    fn stamp(&self) -> [Option<[u64; 2]>; 3] {
        use crate::fast_hash_core::xxh64;
        [&self.advanced, &self.simple, &self.overrides].map(|source| {
            source
                .as_deref()
                .map(|text| [xxh64(text.as_bytes(), 0), xxh64(text.as_bytes(), 1)])
        })
    }
}

pub fn load_raw(cwd: &Path) -> io::Result<(PathBuf, Value)> {
    let layers = Layers::read(cwd)?;
    let value = layers.parse()?;
    Ok((
        layers
            .sources
            .simple
            .or(layers.sources.advanced)
            .expect("configuration has a source"),
        value,
    ))
}

enum Data {
    Raw(Value),
    Normalized(Result<Config, Box<str>>),
}

pub(crate) struct Generation {
    stamp: [Option<[u64; 2]>; 3],
    sources: ConfigSources,
    language: Language,
    data: Mutex<Data>,
}

impl Generation {
    pub(crate) fn language(&self) -> Language {
        self.language
    }

    pub(crate) fn normalized(&self) -> io::Result<Config> {
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        if let Data::Raw(raw) = &*data {
            *data = Data::Normalized(Config::parse(raw).map_err(|error| error.to_string().into()));
        }
        match &*data {
            Data::Normalized(Ok(config)) => Ok(config.clone()),
            Data::Normalized(Err(message)) => Err(invalid(message.as_ref())),
            Data::Raw(_) => unreachable!(),
        }
    }
}

pub(crate) fn generation(cwd: &Path) -> io::Result<Arc<Generation>> {
    static CACHE: Mutex<Option<Arc<Generation>>> = Mutex::new(None);
    let layers = Layers::read(cwd)?;
    let stamp = layers.stamp();
    let before = {
        let cached = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(hit) = cached
            .as_ref()
            .filter(|hit| hit.stamp == stamp && hit.sources == layers.sources)
        {
            return Ok(hit.clone());
        }
        cached.clone()
    };
    let raw = layers.parse()?;
    let language = if raw["cli"].is_object() {
        Language::parse(raw["cli"]["language"].as_str().unwrap_or(""))
    } else {
        Language::Zh
    };
    let current = Arc::new(Generation {
        stamp,
        sources: layers.sources,
        language,
        data: Mutex::new(Data::Raw(raw)),
    });
    let mut cached = CACHE.lock().unwrap_or_else(|error| error.into_inner());
    match (cached.as_ref(), before.as_ref()) {
        (Some(hit), _) if hit.stamp == current.stamp && hit.sources == current.sources => {
            return Ok(hit.clone())
        }
        (Some(hit), Some(before)) if Arc::ptr_eq(hit, before) => *cached = Some(current.clone()),
        (None, None) => *cached = Some(current.clone()),
        _ => {}
    }
    Ok(current)
}

pub fn load_language(cwd: &Path) -> Language {
    generation(cwd).map_or(Language::Zh, |generation| generation.language)
}

pub fn load_snapshot(cwd: &Path) -> io::Result<Snapshot> {
    let generation = generation(cwd)?;
    Ok(Snapshot {
        config: generation.normalized()?,
        sources: generation.sources.clone(),
    })
}

pub fn load(cwd: &Path) -> io::Result<Config> {
    generation(cwd)?.normalized()
}

fn field<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
        path.iter().try_fold(value, |value, &key| value.get(key))
    }
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

fn number_field(value: &Value, path: &[&str]) -> io::Result<f64> {
    let value = field(value, path);
    value
        .as_f64()
        .or_else(|| value.as_str()?.trim().parse().ok())
        .or_else(|| value.as_bool().map(|value| f64::from(u8::from(value))))
        .filter(|value| value.is_finite())
        .ok_or_else(|| invalid(format!("{} must be a number", path.join("."))))
}

fn integer_field(value: &Value, path: &[&str], min: u64) -> io::Result<u64> {
    let value = field(value, path);
    let parsed = value
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
        .or_else(|| value.as_f64().map(|n| n.max(0.0) as u64));
    parsed
        .map(|n| n.max(min))
        .ok_or_else(|| invalid(format!("{} must be an integer", path.join("."))))
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
        let process_mode = ProcessMode::parse(&string_field(value, &["runtime", "process_mode"]))?;
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
        let scan_filters = filters
            .iter()
            .enumerate()
            .map(|(index, filter)| ScanFilter::parse(index, filter))
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
                language: Language::parse(&string_field(value, &["cli", "language"])),
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
                content_requirement: ContentRequirement::parse(&string_field(
                    value,
                    &["extraction", "content_requirement"],
                ))?,
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
                scan_filters_enabled: bool_field(value, &["filesystem", "scan_filters_enabled"])?,
                scan_filters,
            },
            performance: PerformanceConfig {
                persistent_server_idle_seconds: number_field(
                    value,
                    &["performance", "persistent_server_idle_seconds"],
                )?
                .max(0.0),
                worker: WorkerConfig {
                    space_poll_interval_ms: integer_field(
                        value,
                        &["performance", "worker", "space_poll_interval_ms"],
                        1,
                    )?,
                    space_status_report_interval_ms: integer_field(
                        value,
                        &["performance", "worker", "space_status_report_interval_ms"],
                        0,
                    )?,
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
            count => count
                .parse::<usize>()
                .ok()
                .filter(|&n| n > 0)
                .map(Self::Fixed)
                .ok_or_else(|| {
                    invalid("recursive_extract must be \"*\", \"?\", or a positive integer")
                }),
        }
    }
}

impl ProcessMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "background" => Ok(Self::Background),
            "" | "normal" => Ok(Self::Normal),
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
            "" | "complete" => Ok(Self::Complete),
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
            serde_json::from_value(value.clone())
                .map_err(|error| invalid(format!("{key} must be a list of rule objects: {error}")))
        };
        NativePathRule::compile(
            parse("paths")?,
            parse("files")?,
            parse("extensions")?,
            parse("full_names")?,
        )
        .map(Self)
    }

    pub(crate) fn compiled(&self) -> NativePathRule {
        self.0.clone()
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
                ScanFilterKind::Blacklist(PathRule::parse(value).map_err(|error| {
                    invalid(format!("filesystem.scan_filters[{index}]: {error}"))
                })?)
            }
            "whitelist" => {
                ScanFilterKind::Whitelist(PathRule::parse(value).map_err(|error| {
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
