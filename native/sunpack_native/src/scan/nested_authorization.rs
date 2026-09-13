use crate::scan::directory::NativeDirectorySnapshot;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

type CandidateTuple = (String, Vec<String>);

struct RawEntry {
    key: String,
    scope_key: String,
    root_branch_key: Option<String>,
    local_branch_key: Option<String>,
    is_dir: bool,
    size: u64,
}

#[derive(Default)]
struct ScopeCandidates {
    projects: usize,
    member_keys: HashSet<String>,
    branch_keys: HashSet<String>,
}

#[derive(Default)]
struct ScopeStats {
    total_bytes: u64,
    candidate_bytes: u64,
    candidate_projects: usize,
    candidate_member_count: usize,
    other_file_count: usize,
    foreign_branch_count: usize,
}

impl ScopeStats {
    fn other_project_count(&self) -> usize {
        self.other_file_count
            .saturating_add(self.foreign_branch_count)
    }
}

struct ScopeAccumulator {
    stats: ScopeStats,
    all_branches: HashSet<String>,
}

impl ScopeAccumulator {
    fn new(candidates: &ScopeCandidates) -> Self {
        Self {
            stats: ScopeStats {
                candidate_projects: candidates.projects,
                candidate_member_count: candidates.member_keys.len(),
                ..ScopeStats::default()
            },
            all_branches: HashSet::new(),
        }
    }

    fn finish(mut self, candidates: &ScopeCandidates) -> ScopeStats {
        self.stats.foreign_branch_count = self
            .all_branches
            .difference(&candidates.branch_keys)
            .count();
        self.stats
    }
}

struct CandidateContext {
    entry_path: String,
    scope_path: PathBuf,
    scope_key: String,
    member_keys: HashSet<String>,
    candidate_bytes: u64,
    direct_child: bool,
}

struct Evaluation {
    byte_ratio: f64,
    project_ratio: f64,
    score: f64,
}

#[pyfunction]
#[pyo3(signature = (
    raw_snapshot,
    root_path,
    candidates,
    byte_ratio_exponent,
    project_ratio_exponent,
    authorization_bias,
    minimum_authorization_score,
    minimum_archive_byte_ratio,
    hard_maximum_other_projects
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_nested_candidates(
    py: Python<'_>,
    raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    root_path: &str,
    candidates: Vec<CandidateTuple>,
    byte_ratio_exponent: f64,
    project_ratio_exponent: f64,
    authorization_bias: f64,
    minimum_authorization_score: f64,
    minimum_archive_byte_ratio: f64,
    hard_maximum_other_projects: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    let root = PathBuf::from(root_path);
    let root_key = path_key(&root);
    let mut raw_entries = Vec::new();
    let mut file_sizes: HashMap<String, u64> = HashMap::new();

    for (path, is_dir, size, _) in raw_snapshot.records() {
        let key = path_key_from_str(path);
        let Some(relative) = relative_key(&key, &root_key) else {
            continue;
        };
        if relative.is_empty() || relative_contains_internal_metadata(relative) {
            continue;
        }
        let (scope_key, root_branch_key, local_branch_key) =
            if let Some((first, remainder)) = relative.split_once('\\') {
                let scope_key = format!("{root_key}\\{first}");
                let local_branch_key = if let Some((first_local, _)) = remainder.split_once('\\') {
                    Some(format!("{scope_key}\\{first_local}"))
                } else if is_dir {
                    Some(key.clone())
                } else {
                    None
                };
                (scope_key.clone(), Some(scope_key), local_branch_key)
            } else {
                let root_branch_key = is_dir.then(|| key.clone());
                (root_key.clone(), root_branch_key.clone(), root_branch_key)
            };
        let size = if is_dir { 0 } else { size.unwrap_or(0) };
        if !is_dir {
            file_sizes.insert(key.clone(), size);
        }
        raw_entries.push(RawEntry {
            key,
            scope_key,
            root_branch_key,
            local_branch_key,
            is_dir,
            size,
        });
    }

    let mut contexts = Vec::with_capacity(candidates.len());
    let mut scopes: HashMap<String, ScopeCandidates> = HashMap::new();
    let mut root_candidates = ScopeCandidates::default();

    for (entry_path, raw_members) in candidates {
        let entry = PathBuf::from(&entry_path);
        let Some((scope_path, direct_child)) = semantic_scope(&entry, &root) else {
            contexts.push(CandidateContext {
                entry_path,
                scope_path: PathBuf::new(),
                scope_key: String::new(),
                member_keys: HashSet::new(),
                candidate_bytes: 0,
                direct_child: false,
            });
            continue;
        };
        let scope_key = path_key(&scope_path);
        let members = if raw_members.is_empty() {
            vec![entry.to_string_lossy().into_owned()]
        } else {
            raw_members
        };
        let member_keys: HashSet<String> = members
            .into_iter()
            .map(|member| path_key(Path::new(&member)))
            .collect();
        let candidate_bytes = member_keys
            .iter()
            .map(|member| file_sizes.get(member).copied().unwrap_or(0))
            .fold(0u64, u64::saturating_add);

        add_candidate(&mut root_candidates, &root, &entry, &member_keys);
        add_candidate(
            scopes.entry(scope_key.clone()).or_default(),
            &scope_path,
            &entry,
            &member_keys,
        );
        contexts.push(CandidateContext {
            entry_path,
            scope_path,
            scope_key,
            member_keys,
            candidate_bytes,
            direct_child,
        });
    }

    let mut root_accumulator = ScopeAccumulator::new(&root_candidates);
    let mut scope_accumulators: HashMap<String, ScopeAccumulator> = scopes
        .iter()
        .filter(|(key, _)| key.as_str() != root_key.as_str())
        .map(|(key, candidates)| (key.clone(), ScopeAccumulator::new(candidates)))
        .collect();
    for entry in &raw_entries {
        accumulate_entry(
            &mut root_accumulator,
            entry,
            &root_candidates,
            entry.root_branch_key.as_deref(),
        );
        if let (Some(accumulator), Some(candidates)) = (
            scope_accumulators.get_mut(&entry.scope_key),
            scopes.get(&entry.scope_key),
        ) {
            accumulate_entry(
                accumulator,
                entry,
                candidates,
                entry.local_branch_key.as_deref(),
            );
        }
    }
    let root_stats = root_accumulator.finish(&root_candidates);
    let scope_stats: HashMap<String, ScopeStats> = scope_accumulators
        .into_iter()
        .map(|(key, accumulator)| {
            let candidates = scopes.get(&key).expect("scope candidates must exist");
            (key, accumulator.finish(candidates))
        })
        .collect();

    contexts
        .into_iter()
        .map(|context| {
            let result = PyDict::new(py);
            let local_stats = scope_stats.get(&context.scope_key).unwrap_or(&root_stats);
            let local = evaluate(
                local_stats,
                byte_ratio_exponent,
                project_ratio_exponent,
                authorization_bias,
            );
            let root_evaluation = evaluate(
                &root_stats,
                byte_ratio_exponent,
                project_ratio_exponent,
                authorization_bias,
            );
            let (authorization_score, limiting_context) = if root_evaluation.score < local.score {
                (root_evaluation.score, "root")
            } else {
                (local.score, "local")
            };
            let minimum_byte_ratio = local.byte_ratio.min(root_evaluation.byte_ratio);
            let observed_other_projects = local_stats
                .other_project_count()
                .max(root_stats.other_project_count());

            let (allowed, reason) = if context.scope_key.is_empty() {
                (false, "outside_scan_root")
            } else if minimum_byte_ratio < minimum_archive_byte_ratio {
                (false, "archive_byte_ratio_below_floor")
            } else if observed_other_projects > hard_maximum_other_projects {
                (false, "too_many_other_projects")
            } else if authorization_score < minimum_authorization_score {
                (false, "authorization_score_below_threshold")
            } else {
                (true, "authorization_score_met")
            };

            result.set_item("entry_path", context.entry_path)?;
            result.set_item("scope_path", context.scope_path.to_string_lossy())?;
            result.set_item("root_path", root.to_string_lossy())?;
            result.set_item("allowed", allowed)?;
            result.set_item("reason", reason)?;
            result.set_item("direct_child", context.direct_child)?;
            result.set_item("limiting_context", limiting_context)?;
            result.set_item("candidate_bytes", context.candidate_bytes)?;
            result.set_item("candidate_member_count", context.member_keys.len())?;
            set_scope_items(&result, "local", local_stats, &local)?;
            set_scope_items(&result, "root", &root_stats, &root_evaluation)?;
            result.set_item("authorization_score", authorization_score)?;
            Ok(result.unbind())
        })
        .collect()
}

fn add_candidate(
    scope: &mut ScopeCandidates,
    scope_path: &Path,
    entry_path: &Path,
    member_keys: &HashSet<String>,
) {
    scope.projects += 1;
    scope.member_keys.extend(member_keys.iter().cloned());
    if let Some(branch) = immediate_branch(entry_path, scope_path, false) {
        scope.branch_keys.insert(path_key(&branch));
    }
}

fn accumulate_entry(
    accumulator: &mut ScopeAccumulator,
    entry: &RawEntry,
    candidates: &ScopeCandidates,
    branch_key: Option<&str>,
) {
    if !entry.is_dir {
        accumulator.stats.total_bytes = accumulator.stats.total_bytes.saturating_add(entry.size);
        if candidates.member_keys.contains(&entry.key) {
            accumulator.stats.candidate_bytes =
                accumulator.stats.candidate_bytes.saturating_add(entry.size);
        } else {
            accumulator.stats.other_file_count += 1;
        }
    }
    if let Some(branch) = branch_key {
        accumulator.all_branches.insert(branch.to_owned());
    }
}

fn immediate_branch(path: &Path, scope: &Path, is_dir: bool) -> Option<PathBuf> {
    let relative = path.strip_prefix(scope).ok()?;
    let mut components = relative.components();
    let first = components.next()?;
    if !is_dir && components.next().is_none() {
        return None;
    }
    Some(scope.join(first.as_os_str()))
}

fn evaluate(
    stats: &ScopeStats,
    byte_ratio_exponent: f64,
    project_ratio_exponent: f64,
    authorization_bias: f64,
) -> Evaluation {
    let byte_ratio = ratio(stats.candidate_bytes, stats.total_bytes);
    let project_ratio = project_ratio(stats.candidate_projects, stats.other_project_count());
    let score = odds_fusion_score(
        byte_ratio,
        project_ratio,
        byte_ratio_exponent,
        project_ratio_exponent,
        authorization_bias,
    );
    Evaluation {
        byte_ratio,
        project_ratio,
        score,
    }
}

fn project_ratio(candidate_projects: usize, other_projects: usize) -> f64 {
    let total_projects = candidate_projects.saturating_add(other_projects);
    if total_projects == 0 {
        0.0
    } else {
        candidate_projects as f64 / total_projects as f64
    }
}

fn odds_fusion_score(
    byte_ratio: f64,
    project_ratio: f64,
    byte_ratio_exponent: f64,
    project_ratio_exponent: f64,
    authorization_bias: f64,
) -> f64 {
    if byte_ratio <= 0.0 || project_ratio <= 0.0 {
        return 0.0;
    }
    const EPSILON: f64 = 1e-12;
    let byte_ratio = byte_ratio.clamp(EPSILON, 1.0 - EPSILON);
    let project_ratio = project_ratio.clamp(EPSILON, 1.0 - EPSILON);
    let log_odds = authorization_bias
        + byte_ratio_exponent * (byte_ratio / (1.0 - byte_ratio)).ln()
        + project_ratio_exponent * (project_ratio / (1.0 - project_ratio)).ln();
    if log_odds >= 0.0 {
        1.0 / (1.0 + (-log_odds).exp())
    } else {
        let odds = log_odds.exp();
        odds / (1.0 + odds)
    }
}

fn set_scope_items(
    result: &Bound<'_, PyDict>,
    prefix: &str,
    stats: &ScopeStats,
    evaluation: &Evaluation,
) -> PyResult<()> {
    result.set_item(format!("{prefix}_candidate_bytes"), stats.candidate_bytes)?;
    result.set_item(format!("{prefix}_total_bytes"), stats.total_bytes)?;
    result.set_item(
        format!("{prefix}_candidate_byte_ratio"),
        evaluation.byte_ratio,
    )?;
    result.set_item(
        format!("{prefix}_candidate_project_count"),
        stats.candidate_projects,
    )?;
    result.set_item(
        format!("{prefix}_candidate_member_count"),
        stats.candidate_member_count,
    )?;
    result.set_item(format!("{prefix}_other_file_count"), stats.other_file_count)?;
    result.set_item(
        format!("{prefix}_foreign_branch_count"),
        stats.foreign_branch_count,
    )?;
    result.set_item(
        format!("{prefix}_other_project_count"),
        stats.other_project_count(),
    )?;
    result.set_item(
        format!("{prefix}_candidate_project_ratio"),
        evaluation.project_ratio,
    )?;
    result.set_item(format!("{prefix}_authorization_score"), evaluation.score)?;
    Ok(())
}

fn semantic_scope(path: &Path, root: &Path) -> Option<(PathBuf, bool)> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    let first = components.next()?;
    if components.next().is_none() {
        return Some((root.to_path_buf(), true));
    }
    Some((root.join(first.as_os_str()), false))
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

fn path_key_from_str(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

fn relative_key<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if path == root {
        return Some("");
    }
    path.strip_prefix(root)?.strip_prefix('\\')
}

fn relative_contains_internal_metadata(relative: &str) -> bool {
    relative
        .split('\\')
        .any(|component| component.eq_ignore_ascii_case(".sunpack"))
}

fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_scope_uses_first_directory_below_root() {
        let root = Path::new("C:\\out");
        assert_eq!(
            semantic_scope(Path::new("C:\\out\\wrapper\\inner.zip"), root),
            Some((PathBuf::from("C:\\out\\wrapper"), false))
        );
        assert_eq!(
            semantic_scope(Path::new("C:\\out\\root.rar"), root),
            Some((PathBuf::from("C:\\out"), true))
        );
    }

    #[test]
    fn project_ratio_uses_candidate_share_of_all_projects() {
        assert_eq!(project_ratio(0, 0), 0.0);
        assert_eq!(project_ratio(1, 0), 1.0);
        assert_eq!(project_ratio(1, 19), 0.05);
        assert_eq!(project_ratio(2, 3), 0.4);
    }

    #[test]
    fn odds_fusion_accelerates_at_extreme_ratios() {
        let score = |bytes, projects| odds_fusion_score(bytes, projects, 1.0, 1.0, 0.0);
        assert!(score(0.99, 1.0 / 6.0) > 0.95);
        assert!((score(0.99, 0.05) - 0.839).abs() < 0.002);
        assert!(score(0.99, 1.0 / 31.0) < 0.77);
        assert!(score(0.999, 0.05) > score(0.99, 0.05));
    }

    #[test]
    fn immediate_branch_ignores_direct_files_but_tracks_directories() {
        let root = Path::new("C:\\out");
        assert_eq!(
            immediate_branch(Path::new("C:\\out\\a.zip"), root, false),
            None
        );
        assert_eq!(
            immediate_branch(Path::new("C:\\out\\wrapper"), root, true),
            Some(PathBuf::from("C:\\out\\wrapper"))
        );
        assert_eq!(
            immediate_branch(Path::new("C:\\out\\wrapper\\a.zip"), root, false),
            Some(PathBuf::from("C:\\out\\wrapper"))
        );
    }

    #[test]
    fn internal_sunpack_metadata_is_not_user_context() {
        assert!(relative_contains_internal_metadata(
            ".sunpack\\metadata.json"
        ));
        assert!(!relative_contains_internal_metadata("game\\readme.txt"));
    }
}
