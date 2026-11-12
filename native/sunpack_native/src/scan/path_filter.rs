//! One compiled rule model. Mutable search state belongs to a batch, never a rule.
use regex_automata::{
    meta::{Cache, Regex},
    Input,
};
use regex_syntax::hir::{literal::Extractor, Hir, HirKind, Look};
use serde::Deserialize;
use std::io;
use std::{borrow::Cow, cell::OnceCell, collections::HashSet, path::Path, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleEntry {
    pub(crate) value: String,
    pub(crate) regex: bool,
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

fn compile_patterns(patterns: &[String]) -> io::Result<Option<Regex>> {
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
            invalid_rule(message)
        })
}

type TextScratch = Option<Cache>;

struct TextMatcher {
    exact: HashSet<String>,
    patterns: Option<Regex>,
}

impl TextMatcher {
    fn compile(values: Vec<String>, mut patterns: Vec<String>) -> io::Result<Self> {
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
    fn from_entries(entries: Vec<RuleEntry>, field: &str) -> io::Result<Self> {
        let (mut values, mut patterns) = (Vec::new(), Vec::new());
        for entry in entries {
            if entry.regex {
                patterns.push(entry.value);
            } else {
                if entry.value.contains(['/', '\\']) {
                    return Err(invalid_rule(format!(
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
    // Only the last directory's ancestor chain is retained. This is batch-local
    // scratch, so neither file count nor a long-running Watch grows the cache.
    relative: String,
    prefixes: Vec<(usize, bool)>,
    one_shot: bool,
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
    fn compile(entries: Vec<RuleEntry>) -> io::Result<Self> {
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
                    return Err(invalid_rule("Path must not be empty"));
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
        let (start, mut matched) = if scratch.one_shot {
            (0, false)
        } else {
            if scratch.relative == relative {
                if let Some((_, matched)) = scratch.prefixes.last() {
                    return *matched;
                }
            }
            let common = scratch
                .relative
                .bytes()
                .zip(relative.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            while scratch.prefixes.last().is_some_and(|&(end, _)| {
                end > common || (end < relative.len() && relative.as_bytes()[end] != b'/')
            }) {
                scratch.prefixes.pop();
            }
            scratch
                .prefixes
                .last()
                .map_or((0, false), |&(end, matched)| (end + 1, matched))
        };
        if start <= relative.len() {
            let mut end = start;
            for component in relative[start..].split('/') {
                end += component.len();
                // Inherit a match at any directory prefix, including expressions
                // ending in \z. Flat inventories may change branches or order;
                // only complete common components can reuse their result.
                matched = matched
                    || self.names.matches(component, &mut scratch.names)
                    || self.rooted.matches(&relative[..end], &mut scratch.rooted)
                    || self
                        .patterns
                        .matches(&relative[..end], &mut scratch.patterns);
                if scratch.one_shot {
                    if matched {
                        return true;
                    }
                } else {
                    scratch.prefixes.push((end, matched));
                }
                end += 1;
            }
        }
        if !scratch.one_shot {
            scratch.relative.clear();
            scratch.relative.push_str(relative);
        }
        matched
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
    pub(super) fn has_directory_rules(&self) -> bool {
        !self.paths.is_empty()
    }

    fn compile(
        paths: Vec<RuleEntry>,
        files: Vec<RuleEntry>,
        extensions: Vec<RuleEntry>,
        full_names: Vec<RuleEntry>,
    ) -> io::Result<Self> {
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

fn invalid_rule(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Clone)]
pub(crate) struct NativePathRule {
    pub(super) rule: Arc<PathRule>,
}

impl NativePathRule {
    pub(crate) fn compile(
        paths: Vec<RuleEntry>,
        files: Vec<RuleEntry>,
        extensions: Vec<RuleEntry>,
        full_names: Vec<RuleEntry>,
    ) -> io::Result<Self> {
        for (field, entries) in [
            ("paths", &paths),
            ("files", &files),
            ("extensions", &extensions),
            ("full_names", &full_names),
        ] {
            if let Some(index) = entries.iter().position(|entry| entry.value.is_empty()) {
                return Err(invalid_rule(format!(
                    "{field}[{index}].value must not be empty"
                )));
            }
        }
        Ok(Self {
            rule: Arc::new(PathRule::compile(paths, files, extensions, full_names)?),
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_cache_pressure_keeps_concurrent_batch_results() {
        let rule = PathRule::compile(
            vec![],
            vec![],
            vec![],
            vec![RuleEntry {
                value: r"\A[01]*1[01]{18}\z".into(),
                regex: true,
            }],
        )
        .unwrap();
        let names: Vec<_> = (0..1024u64)
            .map(|index| format!("{:064b}", index.wrapping_mul(0x9e37_79b9_7f4a_7c15)))
            .collect();
        std::thread::scope(|workers| {
            for _ in 0..4 {
                workers.spawn(|| {
                    let mut scratch = PathRuleScratch::default();
                    for name in &names {
                        let path = Path::new("C:/input").join(name);
                        let candidate = FilterPath::new(&path, Path::new("C:/input"));
                        assert_eq!(
                            !rule.rejects(&candidate, false, true, &mut scratch),
                            name.as_bytes()[45] == b'1'
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn reused_path_scratch_follows_ancestors_in_arbitrary_order() {
        let root = Path::new("C:/input");
        let relatives = [
            "a/keep/deep",
            "ab/keep",
            "a/keeper",
            "中文/keep",
            "",
            "a/other",
            "a/keep",
            "中文/keeper",
            "ab",
            "a",
            "別/keep",
        ];
        for (value, regex) in [
            ("keep", false),
            ("a/keep", false),
            ("a/k??p", false),
            (r"\Aa/keep\z|\A中文/keep\z", true),
            (r"(?:\A|/)keep\z", true),
            (r"\A\z", true),
        ] {
            let rule = PathRule::compile(
                vec![RuleEntry {
                    value: value.into(),
                    regex,
                }],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
            for whitelist in [false, true] {
                let mut scratch = PathRuleScratch::default();
                for relative in relatives.iter().chain(relatives.iter().rev()) {
                    let directory = root.join(relative);
                    for (path, is_dir) in
                        [(&directory, true), (&directory.join("payload.001"), false)]
                    {
                        for base in [root, path.parent().unwrap()] {
                            let candidate = FilterPath::new(path, base);
                            let mut single = PathRuleScratch::default();
                            single.paths.one_shot = true;
                            assert_eq!(
                                rule.rejects(&candidate, is_dir, whitelist, &mut scratch),
                                rule.rejects(&candidate, is_dir, whitelist, &mut single),
                                "{value:?} {path:?} under {base:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
