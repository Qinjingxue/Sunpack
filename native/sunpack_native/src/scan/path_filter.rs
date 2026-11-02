//! One compiled rule model. Mutable search state belongs to a batch, never a rule.
use pyo3::prelude::*;
use regex_automata::{
    meta::{Cache, Regex},
    Input,
};
use regex_syntax::hir::{literal::Extractor, Hir, HirKind, Look};
use serde::Deserialize;
use std::{borrow::Cow, cell::OnceCell, collections::HashSet, path::Path, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    value: String,
    regex: bool,
}

fn wildcard_pattern(value: &str) -> String {
    // Only * and ? are special. Anchoring keeps ordinary rules full matches;
    // neither wildcard crosses a path separator. Consecutive stars are equal.
    let mut pattern = String::from("\\A(?:");
    let mut start = 0;
    let mut star = false;
    for (index, c) in value.char_indices() {
        if c != '*' && c != '?' {
            star = false;
            continue;
        }
        pattern.push_str(&regex::escape(&value[start..index]));
        if c == '?' {
            pattern.push_str("[^/]");
        } else if !star {
            pattern.push_str("[^/]*");
        }
        star = c == '*';
        start = index + 1;
    }
    pattern.push_str(&regex::escape(&value[start..]));
    pattern.push_str(")\\z");
    pattern
}

fn compile_patterns(patterns: &[String]) -> PyResult<Option<Regex>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    Regex::builder()
        // Acceleration budget, not a matching/failure limit: a full lazy DFA
        // cache can be cleared or the meta engine can fall back to its NFA.
        .configure(Regex::config().hybrid_cache_capacity(256 * 1024))
        .build_many(patterns)
        .map(Some)
        .map_err(|error| {
            use std::error::Error;
            let mut message = error.to_string();
            let mut source = error.source();
            while let Some(cause) = source {
                message.push_str(": ");
                message.push_str(&cause.to_string());
                source = cause.source();
            }
            pyo3::exceptions::PyValueError::new_err(message)
        })
}

type TextScratch = Option<Cache>;

struct TextMatcher {
    exact: HashSet<String>,
    patterns: Option<Regex>,
}

impl TextMatcher {
    fn regex_memory_usage(&self) -> usize {
        self.patterns.as_ref().map_or(0, Regex::memory_usage)
    }
    fn compile(values: Vec<String>, mut patterns: Vec<String>) -> PyResult<Self> {
        let mut exact = HashSet::new();
        for value in values {
            if value.contains(['*', '?']) {
                patterns.push(wildcard_pattern(&value));
            } else {
                exact.insert(value);
            }
        }
        Ok(Self {
            exact,
            patterns: compile_patterns(&patterns)?,
        })
    }
    fn from_entries(entries: Vec<RuleEntry>, field: &str) -> PyResult<Self> {
        let (mut values, mut patterns) = (Vec::new(), Vec::new());
        for entry in entries {
            if entry.regex {
                patterns.push(entry.value);
            } else {
                if entry.value.contains(['/', '\\']) {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "{field} must not contain a path separator"
                    )));
                }
                values.push(entry.value);
            }
        }
        Self::compile(values, patterns)
    }
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.patterns.is_none()
    }
    fn matches(&self, value: &str, scratch: &mut TextScratch) -> bool {
        self.exact.contains(value)
            || self.patterns.as_ref().is_some_and(|re| {
                let cache = scratch.get_or_insert_with(|| re.create_cache());
                re.search_half_with(cache, &Input::new(value).earliest(true))
                    .is_some()
            })
    }
}

struct PathMatcher {
    names: TextMatcher,
    rooted: TextMatcher,
    patterns: TextMatcher,
    // None means at least one pattern can match below an arbitrary prefix.
    routes: Option<Vec<String>>,
}

#[derive(Default)]
struct PathScratch {
    names: TextScratch,
    rooted: TextScratch,
    patterns: TextScratch,
}

fn start_anchored(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Look(Look::Start) => true,
        HirKind::Capture(c) => start_anchored(&c.sub),
        HirKind::Concat(items) => items.first().is_some_and(start_anchored),
        HirKind::Alternation(items) => items.iter().all(start_anchored),
        _ => false,
    }
}

fn regex_routes(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .ok()?;
    if !start_anchored(&hir) {
        return None;
    }
    // Extractor bounds expansion. Infinite/empty/invalid UTF-8 prefixes disable
    // this optimization; they never reject an otherwise valid expression.
    let seq = Extractor::new().extract(&hir);
    let mut result = HashSet::new();
    for literal in seq.literals()? {
        let bytes = literal.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        result.insert(String::from_utf8(bytes.to_vec()).ok()?);
    }
    Some(result.into_iter().collect())
}

impl PathMatcher {
    fn compile(entries: Vec<RuleEntry>) -> PyResult<Self> {
        let (mut names, mut paths, mut patterns) = (Vec::new(), Vec::new(), Vec::new());
        let mut routes = Some(Vec::new());
        for entry in entries {
            if entry.regex {
                if let Some(combined) = routes.as_mut() {
                    if let Some(prefixes) = regex_routes(&entry.value) {
                        combined.extend(prefixes);
                    } else {
                        routes = None;
                    }
                }
                patterns.push(entry.value);
            } else {
                let value = entry.value.replace('\\', "/").trim_matches('/').to_owned();
                if value.is_empty() {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Path must not be empty",
                    ));
                }
                if value.contains('/') {
                    if let Some(combined) = routes.as_mut() {
                        if value.contains(['*', '?']) {
                            if let Some(prefixes) = regex_routes(&wildcard_pattern(&value)) {
                                combined.extend(prefixes);
                            } else {
                                routes = None;
                            }
                        } else {
                            combined.push(value.clone());
                        }
                    }
                    paths.push(value);
                } else {
                    names.push(value);
                }
            }
        }
        Ok(Self {
            names: TextMatcher::compile(names, Vec::new())?,
            rooted: TextMatcher::compile(paths, Vec::new())?,
            patterns: TextMatcher::compile(Vec::new(), patterns)?,
            routes,
        })
    }
    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.rooted.is_empty() && self.patterns.is_empty()
    }
    fn matches(&self, relative: &str, scratch: &mut PathScratch) -> bool {
        if !self.names.is_empty()
            && relative
                .split('/')
                .any(|s| self.names.matches(s, &mut scratch.names))
        {
            return true;
        }
        // Directory prefixes supply subtree inheritance even for patterns
        // ending in \z, including in flat watch/output inventories.
        let mut prefix = relative;
        loop {
            if self.rooted.matches(prefix, &mut scratch.rooted)
                || self.patterns.matches(prefix, &mut scratch.patterns)
            {
                return true;
            }
            match prefix.rsplit_once('/') {
                Some((parent, _)) => prefix = parent,
                None => return false,
            }
        }
    }
    fn allows_directory(&self, relative: &str, scratch: &mut PathScratch) -> bool {
        if self.is_empty() || !self.names.is_empty() || self.matches(relative, scratch) {
            return true;
        }
        self.routes.as_ref().is_none_or(|routes| {
            routes
                .iter()
                .any(|route| relative.starts_with(route) || route.starts_with(relative))
        })
    }
}

#[derive(Clone, Copy)]
enum FilePart {
    Extension,
    Stem,
    Full,
}

pub(super) struct PathRule {
    paths: PathMatcher,
    files: [(FilePart, TextMatcher); 3],
}
#[derive(Default)]
pub(super) struct PathRuleScratch {
    paths: PathScratch,
    files: [TextScratch; 3],
}
impl PathRuleScratch {
    pub(super) fn regex_memory_usage(&self) -> usize {
        self.files
            .iter()
            .chain([&self.paths.names, &self.paths.rooted, &self.paths.patterns])
            .filter_map(Option::as_ref)
            .map(Cache::memory_usage)
            .sum::<usize>()
    }
}

pub(super) struct FilterPath<'a> {
    path: &'a Path,
    root: &'a Path,
    relative_directory: OnceCell<String>,
    name: OnceCell<Cow<'a, str>>,
    extension_start: OnceCell<Option<usize>>,
}
impl<'a> FilterPath<'a> {
    pub(super) fn new(path: &'a Path, root: &'a Path) -> Self {
        Self {
            path,
            root,
            relative_directory: OnceCell::new(),
            name: OnceCell::new(),
            extension_start: OnceCell::new(),
        }
    }
    fn name(&self) -> &str {
        self.name
            .get_or_init(|| self.path.file_name().unwrap_or_default().to_string_lossy())
    }
    fn part(&self, part: FilePart) -> Option<&str> {
        let name = self.name();
        if matches!(part, FilePart::Full) {
            return Some(name);
        }
        let start = *self
            .extension_start
            .get_or_init(|| name.rfind('.').map(|index| index + 1));
        match part {
            FilePart::Extension => start.map(|start| &name[start..]),
            FilePart::Stem => Some(start.map_or(name, |start| &name[..start - 1])),
            FilePart::Full => unreachable!(),
        }
    }
    fn relative_directory(&self, is_dir: bool) -> &str {
        self.relative_directory.get_or_init(|| {
            let relative = self.path.strip_prefix(self.root).unwrap_or(self.path);
            let directory = if is_dir {
                relative
            } else {
                relative.parent().unwrap_or(Path::new(""))
            };
            directory.to_string_lossy().replace('\\', "/")
        })
    }
}

impl PathRule {
    pub(super) fn regex_memory_usage(&self) -> usize {
        self.files
            .iter()
            .map(|(_, matcher)| matcher.regex_memory_usage())
            .sum::<usize>()
            + self.paths.names.regex_memory_usage()
            + self.paths.rooted.regex_memory_usage()
            + self.paths.patterns.regex_memory_usage()
    }
    fn compile(
        paths: Vec<RuleEntry>,
        files: Vec<RuleEntry>,
        extensions: Vec<RuleEntry>,
        full_names: Vec<RuleEntry>,
    ) -> PyResult<Self> {
        Ok(Self {
            paths: PathMatcher::compile(paths)?,
            files: [
                (
                    FilePart::Extension,
                    TextMatcher::from_entries(extensions, "Extension")?,
                ),
                (
                    FilePart::Stem,
                    TextMatcher::from_entries(files, "Filename")?,
                ),
                (
                    FilePart::Full,
                    TextMatcher::from_entries(full_names, "Filename + extension")?,
                ),
            ],
        })
    }
    pub(super) fn rejects(
        &self,
        candidate: &FilterPath<'_>,
        is_dir: bool,
        whitelist: bool,
        scratch: &mut PathRuleScratch,
    ) -> bool {
        if is_dir {
            if self.paths.is_empty() {
                return false;
            }
            let relative = candidate.relative_directory(true);
            if relative.is_empty() {
                return false;
            }
            return if whitelist {
                !self.paths.allows_directory(relative, &mut scratch.paths)
            } else {
                self.paths.matches(relative, &mut scratch.paths)
            };
        }
        for ((part, matcher), scratch) in self.files.iter().zip(&mut scratch.files) {
            if matcher.is_empty() {
                continue;
            }
            let matched = candidate
                .part(*part)
                .is_some_and(|value| matcher.matches(value, scratch));
            if matched != whitelist {
                return true;
            }
        }
        !self.paths.is_empty()
            && (self
                .paths
                .matches(candidate.relative_directory(false), &mut scratch.paths)
                != whitelist)
    }
}

fn entries(value: &Bound<'_, PyAny>, field: &str) -> PyResult<Vec<RuleEntry>> {
    let entries: Vec<RuleEntry> = serde_json::from_value(crate::watch_store::py_to_json(value)?)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{field}: {e}")))?;
    for (index, entry) in entries.iter().enumerate() {
        if entry.value.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{field}[{index}].value must not be empty"
            )));
        }
    }
    Ok(entries)
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativePathRule {
    pub(super) rule: Arc<PathRule>,
}
#[pymethods]
impl NativePathRule {
    #[new]
    fn new(
        paths: &Bound<'_, PyAny>,
        files: &Bound<'_, PyAny>,
        extensions: &Bound<'_, PyAny>,
        full_names: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        Ok(Self {
            rule: Arc::new(PathRule::compile(
                entries(paths, "paths")?,
                entries(files, "files")?,
                entries(extensions, "extensions")?,
                entries(full_names, "full_names")?,
            )?),
        })
    }
    fn rejects(&self, path: &str, root: &str, is_dir: bool, whitelist: bool) -> bool {
        self.rule.rejects(
            &FilterPath::new(Path::new(path), Path::new(root)),
            is_dir,
            whitelist,
            &mut PathRuleScratch::default(),
        )
    }
    fn accepted_indices(
        &self,
        py: Python<'_>,
        root: Option<&str>,
        paths: Vec<String>,
        is_dirs: Vec<bool>,
        whitelist: bool,
    ) -> PyResult<Vec<usize>> {
        if paths.len() != is_dirs.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "paths and is_dirs lengths differ",
            ));
        }
        Ok(py.detach(|| {
            let mut scratch = PathRuleScratch::default();
            paths
                .iter()
                .zip(is_dirs)
                .enumerate()
                .filter_map(|(index, (path, is_dir))| {
                    let path = Path::new(path);
                    let root = root
                        .map(Path::new)
                        .unwrap_or_else(|| path.parent().unwrap_or(Path::new("")));
                    (!self.rule.rejects(
                        &FilterPath::new(path, root),
                        is_dir,
                        whitelist,
                        &mut scratch,
                    ))
                    .then_some(index)
                })
                .collect()
        }))
    }
}
