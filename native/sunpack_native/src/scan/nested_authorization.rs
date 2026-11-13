use crate::core::config::AuthorizationConfig;
use crate::scan::directory::NativeDirectorySnapshot;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

pub(crate) fn authorize_nested_candidates<'a, Members: Iterator<Item = &'a str>>(
    snapshot: &NativeDirectorySnapshot,
    root: &Path,
    candidates: impl ExactSizeIterator<Item = (&'a str, Members)>,
    policy: AuthorizationConfig,
) -> Vec<bool> {
    let root_key = path_key(&root);
    let mut contexts = Vec::with_capacity(candidates.len());
    let mut scopes: HashMap<String, ScopeCandidates> = HashMap::new();
    let mut root_candidates = ScopeCandidates::default();

    for (entry_path, raw_members) in candidates {
        let entry = Path::new(entry_path);
        let Some((scope_path, _)) = semantic_scope(entry, root) else {
            contexts.push(None);
            continue;
        };
        let scope_key = path_key(&scope_path);
        let mut member_keys: HashSet<_> = raw_members.map(path_key_from_str).collect();
        if member_keys.is_empty() {
            member_keys.insert(path_key(entry));
        }
        add_candidate(&mut root_candidates, root, entry, &member_keys);
        if scope_key != root_key {
            add_candidate(
                scopes.entry(scope_key.clone()).or_default(),
                &scope_path,
                entry,
                &member_keys,
            );
        }
        contexts.push(Some(scope_key));
    }

    let mut root_accumulator = ScopeAccumulator::new(&root_candidates);
    let mut scope_accumulators: HashMap<String, ScopeAccumulator> = scopes
        .iter()
        .map(|(key, candidates)| (key.clone(), ScopeAccumulator::new(candidates)))
        .collect();
    // Snapshot storage stays borrowed. Only candidate members need sizes;
    // directory branches are deduplicated as they arrive, not per file.
    for (path, is_dir, size, _) in snapshot.records() {
        let key = path_key_from_str(path);
        let Some(relative) = relative_key(&key, &root_key) else {
            continue;
        };
        if relative.is_empty() {
            continue;
        }
        let (scope_key, root_branch, local_branch) =
            if let Some((first, remainder)) = relative.split_once('\\') {
                let scope_end = root_key.len() + 1 + first.len();
                let scope_key = &key[..scope_end];
                let local_branch = if let Some((first_local, _)) = remainder.split_once('\\') {
                    Some(&key[..scope_end + 1 + first_local.len()])
                } else {
                    is_dir.then_some(key.as_str())
                };
                (scope_key, Some(scope_key), local_branch)
            } else {
                let branch = is_dir.then_some(key.as_str());
                (root_key.as_str(), branch, branch)
            };
        let size = if is_dir { 0 } else { size.unwrap_or(0) };
        accumulate_entry(
            &mut root_accumulator,
            &key,
            is_dir,
            size,
            &root_candidates,
            root_branch,
        );
        if let (Some(accumulator), Some(candidates)) =
            (scope_accumulators.get_mut(scope_key), scopes.get(scope_key))
        {
            accumulate_entry(accumulator, &key, is_dir, size, candidates, local_branch);
        }
    }
    let evaluate_scope = |stats| {
        evaluate(
            stats,
            policy.byte_ratio_exponent,
            policy.project_ratio_exponent,
        )
    };
    let root_score = evaluate_scope(root_accumulator.finish(&root_candidates));
    let scores: HashMap<_, _> = scope_accumulators
        .into_iter()
        .map(|(key, accumulator)| {
            let candidates = scopes.get(&key).expect("scope candidates must exist");
            (key, evaluate_scope(accumulator.finish(candidates)))
        })
        .collect();
    contexts
        .into_iter()
        .map(|key| {
            key.is_some_and(|key| {
                let score = scores
                    .get(&key)
                    .copied()
                    .unwrap_or(root_score)
                    .min(root_score);
                score >= policy.minimum_authorization_score
            })
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
    key: &str,
    is_dir: bool,
    size: u64,
    candidates: &ScopeCandidates,
    branch_key: Option<&str>,
) {
    if !is_dir {
        accumulator.stats.total_bytes = accumulator.stats.total_bytes.saturating_add(size);
        if candidates.member_keys.contains(key) {
            accumulator.stats.candidate_bytes =
                accumulator.stats.candidate_bytes.saturating_add(size);
        } else {
            accumulator.stats.other_file_count += 1;
        }
    }
    if let Some(branch) = branch_key {
        if !accumulator.all_branches.contains(branch) {
            accumulator.all_branches.insert(branch.to_owned());
        }
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

fn evaluate(stats: ScopeStats, byte_ratio_exponent: f64, project_ratio_exponent: f64) -> f64 {
    let byte_ratio = ratio(stats.candidate_bytes, stats.total_bytes);
    let project_ratio = project_ratio(stats.candidate_projects, stats.other_project_count());
    odds_fusion_score(
        byte_ratio,
        project_ratio,
        byte_ratio_exponent,
        project_ratio_exponent,
    )
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
) -> f64 {
    if byte_ratio <= 0.0 || project_ratio <= 0.0 {
        return 0.0;
    }
    const EPSILON: f64 = 1e-12;
    let byte_ratio = byte_ratio.clamp(EPSILON, 1.0 - EPSILON);
    let project_ratio = project_ratio.clamp(EPSILON, 1.0 - EPSILON);
    let log_odds = byte_ratio_exponent * (byte_ratio / (1.0 - byte_ratio)).ln()
        + project_ratio_exponent * (project_ratio / (1.0 - project_ratio)).ln();
    if log_odds >= 0.0 {
        1.0 / (1.0 + (-log_odds).exp())
    } else {
        let odds = log_odds.exp();
        odds / (1.0 + odds)
    }
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
    crate::path_keys::path_key(&path.to_string_lossy())
}

fn path_key_from_str(path: &str) -> String {
    crate::path_keys::path_key(path)
}

fn relative_key<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if path == root {
        return Some("");
    }
    path.strip_prefix(root)?.strip_prefix('\\')
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
        let score = |bytes, projects| odds_fusion_score(bytes, projects, 1.0, 1.0);
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
}
