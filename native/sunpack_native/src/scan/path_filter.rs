//! Shared, immutable path rules for directory scans, watch catalogs and inventories.
use pyo3::prelude::*;
use regex::{RegexSet, RegexSetBuilder};
use std::cell::OnceCell;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

struct NameMatcher {
    exact: HashSet<String>,
    patterns: RegexSet,
}

impl NameMatcher {
    fn compile(globs: Vec<String>) -> PyResult<Self> {
        let mut exact = HashSet::new();
        let mut patterns = Vec::new();
        for glob in globs {
            if glob.contains(['*', '?']) {
                patterns.push(format!("^{}$", glob_body(&glob)));
            } else {
                exact.insert(glob.to_lowercase());
            }
        }
        Ok(Self {
            exact,
            patterns: regex_set(patterns)?,
        })
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.patterns.is_empty()
    }

    fn matches(&self, name: &str) -> bool {
        (self.exact.contains(name)
            || (!self.exact.is_empty()
                && name.chars().any(char::is_uppercase)
                && self.exact.contains(&name.to_lowercase())))
            || self.patterns.is_match(name)
    }
}

struct PathMatcher {
    names: NameMatcher,
    paths: RegexSet,
    ancestors: RegexSet,
}

impl PathMatcher {
    fn compile(globs: Vec<String>) -> PyResult<Self> {
        let mut names = Vec::new();
        let mut paths = Vec::new();
        let mut ancestors = Vec::new();
        for glob in globs {
            let glob = normalize_glob(&glob);
            if glob.is_empty() {
                continue;
            }
            if !glob.contains('/') {
                names.push(glob);
                continue;
            }
            // A directory match includes its subtree, even without a trailing /**.
            let mut base = glob.as_str();
            while let Some(prefix) = base.strip_suffix("/**") {
                base = prefix;
            }
            paths.push(format!("^{}(?:/.*)?$", glob_body(base)));
            // Keep directories on the route to a possible match. A ** may span
            // directories even inside a component, so its prefix stays open.
            for (index, _) in base.match_indices('/') {
                ancestors.push(format!("^{}$", glob_body(&base[..index])));
            }
            if let Some(index) = base.find("**") {
                ancestors.push(format!("^{}$", glob_body(&base[..index + 2])));
            }
        }
        Ok(Self {
            names: NameMatcher::compile(names)?,
            paths: regex_set(paths)?,
            ancestors: regex_set(ancestors)?,
        })
    }

    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.paths.is_empty()
    }

    fn matches(&self, relative: &str) -> bool {
        (!self.names.is_empty() && relative.split('/').any(|name| self.names.matches(name)))
            || self.paths.is_match(relative)
    }

    fn allows_directory(&self, relative: &str) -> bool {
        // An unanchored name can occur at any depth below this directory.
        self.is_empty()
            || !self.names.is_empty()
            || self.matches(relative)
            || self.ancestors.is_match(relative)
    }
}

pub(super) struct PathRule {
    paths: PathMatcher,
    files: NameMatcher,
    extensions: HashSet<String>,
}

/// One stack-local candidate; path normalization is shared and only done if
/// cheap filename/extension checks cannot decide the result.
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
        self.relative
            .get_or_init(|| relative_path(self.path, self.root, is_dir))
    }
}

impl PathRule {
    fn compile(paths: Vec<String>, files: Vec<String>, extensions: Vec<String>) -> PyResult<Self> {
        Ok(Self {
            paths: PathMatcher::compile(paths)?,
            files: NameMatcher::compile(
                files
                    .into_iter()
                    .filter_map(|value| {
                        let name = normalize_glob(&value).rsplit('/').next()?.to_string();
                        (!name.is_empty()).then_some(name)
                    })
                    .collect(),
            )?,
            extensions: extensions
                .into_iter()
                .filter_map(|ext| {
                    let ext = ext.trim().to_lowercase();
                    if ext.is_empty() {
                        None
                    } else if ext.starts_with('.') {
                        Some(ext)
                    } else {
                        Some(format!(".{ext}"))
                    }
                })
                .collect(),
        })
    }

    pub(super) fn rejects(
        &self,
        candidate: &FilterPath<'_>,
        is_dir: bool,
        whitelist: bool,
    ) -> bool {
        if is_dir {
            let relative = candidate.relative(true);
            if relative.is_empty() {
                return false;
            }
            return if whitelist {
                !self.paths.allows_directory(relative)
            } else {
                self.paths.matches(relative)
            };
        }
        let name = candidate
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let extension_matches = || {
            candidate
                .path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    self.extensions
                        .contains(&format!(".{}", ext.to_lowercase()))
                })
        };
        if whitelist {
            (!self.files.is_empty() && !self.files.matches(&name))
                || (!self.extensions.is_empty() && !extension_matches())
                || (!self.paths.is_empty() && !self.paths.matches(candidate.relative(false)))
        } else {
            (!self.extensions.is_empty() && extension_matches())
                || self.files.matches(&name)
                || (!self.paths.is_empty() && self.paths.matches(candidate.relative(false)))
        }
    }
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativePathRule {
    pub(super) rule: Arc<PathRule>,
}

#[pymethods]
impl NativePathRule {
    #[new]
    fn new(
        path_globs: Vec<String>,
        file_globs: Vec<String>,
        extensions: Vec<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            rule: Arc::new(PathRule::compile(path_globs, file_globs, extensions)?),
        })
    }

    fn rejects(&self, path: &str, root: &str, is_dir: bool, whitelist: bool) -> bool {
        self.rule.rejects(
            &FilterPath::new(Path::new(path), Path::new(root)),
            is_dir,
            whitelist,
        )
    }
}

fn relative_path(path: &Path, root: &Path, is_dir: bool) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let relative = if relative.as_os_str().is_empty() && !is_dir {
        path.file_name().map(Path::new).unwrap_or(relative)
    } else {
        relative
    };
    relative.to_string_lossy().replace('\\', "/")
}

fn normalize_glob(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .trim_matches('/')
        .to_string()
}

fn regex_set(patterns: Vec<String>) -> PyResult<RegexSet> {
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .build()
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
}

/// Only * and ? are syntax. ** can cross separators; **/ also matches zero levels.
fn glob_body(glob: &str) -> String {
    let mut result = String::new();
    let mut chars = glob.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    result.push_str("(?:.*/)?");
                } else {
                    result.push_str(".*");
                }
            }
            '*' => result.push_str("[^/]*"),
            '?' => result.push_str("[^/]"),
            _ => result.push_str(&regex::escape(&character.to_string())),
        }
    }
    result
}
