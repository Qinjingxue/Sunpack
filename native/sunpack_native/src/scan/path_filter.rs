//! One compiled rule model. Mutable search state belongs to a batch, never a rule.
use pyo3::prelude::*;
use regex_automata::{
    meta::{Cache, Regex},
    util::syntax,
    Input,
};
use regex_syntax::hir::{literal::Extractor, Hir, HirKind, Look};
use serde::Deserialize;
use std::{cell::OnceCell, collections::HashSet, path::Path, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    value: String,
    regex: bool,
}

fn compile_patterns(patterns: &[String]) -> PyResult<Option<Regex>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    Regex::builder()
        .syntax(syntax::Config::new().case_insensitive(true))
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

#[derive(Default)]
struct TextScratch {
    literals: Option<Cache>,
    patterns: Option<Cache>,
    folded: String,
}
impl TextScratch {
    fn regex_memory_usage(&self) -> usize {
        self.literals.as_ref().map_or(0, Cache::memory_usage)
            + self.patterns.as_ref().map_or(0, Cache::memory_usage)
    }
}

struct TextMatcher {
    exact: HashSet<String>,
    literals: Option<Regex>,
    patterns: Option<Regex>,
    ascii_literals: bool,
}

impl TextMatcher {
    fn regex_memory_usage(&self) -> usize {
        self.literals.as_ref().map_or(0, Regex::memory_usage)
            + self.patterns.as_ref().map_or(0, Regex::memory_usage)
    }
    fn compile(literals: Vec<String>, patterns: Vec<String>) -> PyResult<Self> {
        let ascii_literals = literals.iter().all(|s| s.is_ascii());
        let exact = literals
            .iter()
            .filter(|s| s.is_ascii())
            .map(|s| s.to_ascii_lowercase())
            .collect();
        // Unicode simple folding, including Kelvin sign/K and long s/S, must
        // agree with regex rules. The ASCII hot path needs no regex cache.
        let escaped: Vec<_> = literals
            .iter()
            .map(|s| format!("\\A(?:{})\\z", regex::escape(s)))
            .collect();
        Ok(Self {
            exact,
            literals: compile_patterns(&escaped)?,
            patterns: compile_patterns(&patterns)?,
            ascii_literals,
        })
    }
    fn is_empty(&self) -> bool {
        self.literals.is_none() && self.patterns.is_none()
    }
    fn search(re: &Option<Regex>, cache: &mut Option<Cache>, value: &str) -> bool {
        re.as_ref().is_some_and(|re| {
            let cache = cache.get_or_insert_with(|| re.create_cache());
            re.search_half_with(cache, &Input::new(value).earliest(true))
                .is_some()
        })
    }
    fn matches(&self, value: &str, scratch: &mut TextScratch) -> bool {
        if value.is_ascii() {
            if self.exact.contains(value) {
                return true;
            }
            if !self.exact.is_empty() && value.bytes().any(|b| b.is_ascii_uppercase()) {
                scratch.folded.clear();
                scratch
                    .folded
                    .extend(value.bytes().map(|b| char::from(b.to_ascii_lowercase())));
                if self.exact.contains(&scratch.folded) {
                    return true;
                }
            }
        }
        ((!value.is_ascii() || !self.ascii_literals)
            && Self::search(&self.literals, &mut scratch.literals, value))
            || Self::search(&self.patterns, &mut scratch.patterns, value)
    }
}

struct PathMatcher {
    names: TextMatcher,
    rooted: TextMatcher,
    patterns: TextMatcher,
    literal_routes: Vec<String>,
    // None means at least one regex can match below an arbitrary prefix.
    regex_routes: Option<Vec<String>>,
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
    // ASCII-insensitive prefix comparisons below safely over-approximate both
    // case modes. Avoid expanding every default-folded letter into alternates.
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .ok()?;
    if !start_anchored(&hir) {
        return None;
    }
    // Extractor bounds expansion. Infinite/empty/non-ASCII prefixes disable
    // this optimization; they never reject an otherwise valid expression.
    let seq = Extractor::new().extract(&hir);
    let mut result = HashSet::new();
    for literal in seq.literals()? {
        let bytes = literal.as_bytes();
        if bytes.is_empty() || !bytes.is_ascii() {
            return None;
        }
        result.insert(String::from_utf8(bytes.to_ascii_lowercase()).ok()?);
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
                    paths.push(value);
                } else {
                    names.push(value);
                }
            }
        }
        Ok(Self {
            names: TextMatcher::compile(names, Vec::new())?,
            rooted: TextMatcher::compile(paths.clone(), Vec::new())?,
            patterns: TextMatcher::compile(Vec::new(), patterns)?,
            literal_routes: paths,
            regex_routes: routes,
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
        // Unknown Unicode prefix relations stay open. Actual matching above
        // still uses the same Unicode semantics as every regex rule.
        if !relative.is_ascii() {
            return true;
        }
        let compatible = |route: &String| {
            if !route.is_ascii() {
                return true;
            }
            let (short, long) = if relative.len() < route.len() {
                (relative, route.as_str())
            } else {
                (route.as_str(), relative)
            };
            short.eq_ignore_ascii_case(&long[..short.len()])
        };
        self.literal_routes.iter().any(compatible)
            || self
                .regex_routes
                .as_ref()
                .is_none_or(|routes| routes.iter().any(compatible))
    }
}

pub(super) struct PathRule {
    paths: PathMatcher,
    files: TextMatcher,
}
#[derive(Default)]
pub(super) struct PathRuleScratch {
    paths: PathScratch,
    files: TextScratch,
}
impl PathRuleScratch {
    pub(super) fn regex_memory_usage(&self) -> usize {
        self.files.regex_memory_usage()
            + self.paths.names.regex_memory_usage()
            + self.paths.rooted.regex_memory_usage()
            + self.paths.patterns.regex_memory_usage()
    }
}

pub(super) struct FilterPath<'a> {
    path: &'a Path,
    root: &'a Path,
    relative: OnceCell<String>,
}
impl<'a> FilterPath<'a> {
    pub(super) fn new(path: &'a Path, root: &'a Path) -> Self {
        Self {
            path,
            root,
            relative: OnceCell::new(),
        }
    }
    fn relative(&self, is_dir: bool) -> &str {
        self.relative.get_or_init(|| {
            let relative = self.path.strip_prefix(self.root).unwrap_or(self.path);
            let relative = if relative.as_os_str().is_empty() && !is_dir {
                self.path.file_name().map(Path::new).unwrap_or(relative)
            } else {
                relative
            };
            relative.to_string_lossy().replace('\\', "/")
        })
    }
}

impl PathRule {
    pub(super) fn regex_memory_usage(&self) -> usize {
        self.files.regex_memory_usage()
            + self.paths.names.regex_memory_usage()
            + self.paths.rooted.regex_memory_usage()
            + self.paths.patterns.regex_memory_usage()
    }
    fn compile(paths: Vec<RuleEntry>, files: Vec<RuleEntry>) -> PyResult<Self> {
        let (mut literals, mut patterns) = (Vec::new(), Vec::new());
        for entry in files {
            if entry.regex {
                patterns.push(entry.value);
            } else {
                if entry.value.contains(['/', '\\']) {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Filename must not contain a path separator",
                    ));
                }
                literals.push(entry.value);
            }
        }
        Ok(Self {
            paths: PathMatcher::compile(paths)?,
            files: TextMatcher::compile(literals, patterns)?,
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
            let relative = candidate.relative(true);
            if relative.is_empty() {
                return false;
            }
            return if whitelist {
                !self.paths.allows_directory(relative, &mut scratch.paths)
            } else {
                self.paths.matches(relative, &mut scratch.paths)
            };
        }
        let name = candidate
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if whitelist {
            (!self.files.is_empty() && !self.files.matches(&name, &mut scratch.files))
                || (!self.paths.is_empty()
                    && !self
                        .paths
                        .matches(candidate.relative(false), &mut scratch.paths))
        } else {
            self.files.matches(&name, &mut scratch.files)
                || (!self.paths.is_empty()
                    && self
                        .paths
                        .matches(candidate.relative(false), &mut scratch.paths))
        }
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
    fn new(paths: &Bound<'_, PyAny>, files: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            rule: Arc::new(PathRule::compile(
                entries(paths, "paths")?,
                entries(files, "files")?,
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
