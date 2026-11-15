use crate::core::config::AuthorizationConfig;
use crate::scan::directory::NativeDirectorySnapshot;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Scope {
    member_keys: HashSet<String>,
    branches: HashSet<String>,
    total_bytes: u64,
    candidate_bytes: u64,
    candidate_projects: usize,
    other_projects: usize,
}

pub(crate) fn authorize_nested_candidates<'a, Members: Iterator<Item = &'a str>>(
    snapshot: &NativeDirectorySnapshot,
    root: &Path,
    candidates: impl ExactSizeIterator<Item = (&'a str, Members)>,
    policy: AuthorizationConfig,
) -> Vec<bool> {
    let root_key = path_key(root);
    let mut contexts = Vec::with_capacity(candidates.len());
    let mut scopes: HashMap<String, Scope> = HashMap::new();
    let mut root_scope = Scope::default();

    for (entry_path, raw_members) in candidates {
        let entry = Path::new(entry_path);
        let Some(scope_path) = semantic_scope(entry, root) else {
            contexts.push(None);
            continue;
        };
        let scope_key = path_key(&scope_path);
        root_scope.add_candidate(root, entry);
        let mut local = (scope_key != root_key).then(|| {
            let local = scopes.entry(scope_key.clone()).or_default();
            local.add_candidate(&scope_path, entry);
            local
        });
        let mut members = raw_members.peekable();
        let use_entry = members.peek().is_none();
        for member in members.chain(use_entry.then_some(entry_path)) {
            let key = crate::path_keys::path_key(member);
            if let Some(scope) = &mut local {
                scope.member_keys.insert(key.clone());
            }
            root_scope.member_keys.insert(key);
        }
        contexts.push(Some(scope_key));
    }

    // Candidate branches are already in each set. The first occurrence of any
    // other branch counts as a competing project alongside non-member files.
    for (path, is_dir, size, _) in snapshot.records() {
        let key = crate::path_keys::path_key(path);
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
        root_scope.accumulate_entry(&key, is_dir, size, root_branch);
        if let Some(scope) = scopes.get_mut(scope_key) {
            scope.accumulate_entry(&key, is_dir, size, local_branch);
        }
    }
    let evaluate_scope = |scope: &Scope| {
        evaluate(
            scope,
            policy.byte_ratio_exponent,
            policy.project_ratio_exponent,
        )
    };
    let root_score = evaluate_scope(&root_scope);
    let scores: HashMap<_, _> = scopes
        .into_iter()
        .map(|(key, scope)| (key, evaluate_scope(&scope)))
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

impl Scope {
    fn add_candidate(&mut self, scope_path: &Path, entry_path: &Path) {
        self.candidate_projects += 1;
        if let Some(branch) = immediate_branch(entry_path, scope_path) {
            self.branches.insert(path_key(&branch));
        }
    }

    fn accumulate_entry(&mut self, key: &str, is_dir: bool, size: u64, branch_key: Option<&str>) {
        if !is_dir {
            self.total_bytes = self.total_bytes.saturating_add(size);
            if self.member_keys.contains(key) {
                self.candidate_bytes = self.candidate_bytes.saturating_add(size);
            } else {
                self.other_projects += 1;
            }
        }
        if let Some(branch) = branch_key {
            if !self.branches.contains(branch) {
                self.branches.insert(branch.to_owned());
                self.other_projects += 1;
            }
        }
    }
}

fn immediate_branch(path: &Path, scope: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(scope).ok()?;
    let mut components = relative.components();
    let first = components.next()?;
    components.next()?;
    Some(scope.join(first.as_os_str()))
}

fn evaluate(scope: &Scope, byte_ratio_exponent: f64, project_ratio_exponent: f64) -> f64 {
    let byte_ratio = ratio(scope.candidate_bytes, scope.total_bytes);
    let project_ratio = project_ratio(scope.candidate_projects, scope.other_projects);
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

fn semantic_scope(path: &Path, root: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    let first = components.next()?;
    if components.next().is_none() {
        return Some(root.to_path_buf());
    }
    Some(root.join(first.as_os_str()))
}

fn path_key(path: &Path) -> String {
    crate::path_keys::path_key(&path.to_string_lossy())
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
#[path = "../../tests/unit/scan/nested_authorization/tests.rs"]
mod tests;
