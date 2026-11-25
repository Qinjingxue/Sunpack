//! The filesystem boundary shared by discovery, relation recovery and Watch.
use crate::path_keys::path_key;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct NativeDiscoveryScope {
    pub root: String,
    pub max_depth: Option<usize>,
    key: String,
    excluded: Option<Arc<HashSet<String>>>,
}

impl NativeDiscoveryScope {
    pub(crate) fn has_exclusions(&self) -> bool {
        self.excluded.is_some()
    }

    pub(crate) fn same_exclusions(&self, other: &Self) -> bool {
        self.excluded == other.excluded
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        if key == self.key {
            return !self.excluded.as_ref().is_some_and(|excluded| excluded.contains(key));
        }
        let Some(relative) = key
            .strip_prefix(&self.key)
            .and_then(|p| p.strip_prefix('\\'))
        else {
            return false;
        };
        !self
            .max_depth
            .is_some_and(|depth| relative.bytes().filter(|c| *c == b'\\').count() > depth)
            && !self.excludes_key(key)
    }

    fn excludes_key(&self, key: &str) -> bool {
        let Some(excluded) = &self.excluded else {
            return false;
        };
        let mut current = key.trim_end_matches('\\');
        loop {
            if excluded.contains(current) {
                return true;
            }
            let Some((parent, _)) = current.rsplit_once('\\') else {
                return false;
            };
            if parent.len() < self.key.len() {
                return false;
            }
            current = parent;
        }
    }

    pub(crate) fn exclude_roots(&mut self, roots: impl Iterator<Item = String>) {
        let mut roots = roots.peekable();
        if roots.peek().is_some() {
            let excluded = self.excluded.get_or_insert_with(Arc::default);
            Arc::make_mut(excluded).extend(roots.map(|path| subtree_key(&path)));
        }
    }

    pub(crate) fn directory_depth(&self, path: &str) -> Option<usize> {
        let key = path_key(path);
        let key = key.trim_end_matches('\\');
        if key == self.key {
            return Some(0);
        }
        let relative = key.strip_prefix(&self.key)?.strip_prefix('\\')?;
        Some(relative.bytes().filter(|byte| *byte == b'\\').count() + 1)
    }
}

impl NativeDiscoveryScope {
    pub fn new(root: String, max_depth: Option<usize>, excluded_subtrees: Vec<String>) -> Self {
        let key = subtree_key(&root);
        let excluded = (!excluded_subtrees.is_empty()).then(|| {
            Arc::new(excluded_subtrees.into_iter().map(|path| subtree_key(&path)).collect())
        });
        Self {
            root,
            max_depth,
            key,
            excluded,
        }
    }

    pub(crate) fn excluded_subtrees(&self) -> Vec<String> {
        self.excluded.iter().flat_map(|excluded| excluded.iter().cloned()).collect()
    }

    pub fn contains(&self, path: &str) -> bool {
        self.contains_key(&path_key(path))
    }

    pub fn excludes(&self, path: &str) -> bool {
        self.has_exclusions() && self.excludes_key(&path_key(path))
    }
}

fn subtree_key(path: &str) -> String {
    let mut key = path_key(path);
    key.truncate(key.trim_end_matches('\\').len());
    key
}

pub(crate) fn create_output_root_exclusive(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::create_dir(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                match create_output_root_exclusive(parent) {
                    Ok(()) => crate::io::atomic_file::sync_parent(parent)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && parent.is_dir() => {}
                    Err(error) => return Err(error),
                }
            }
            std::fs::create_dir(path)
        }
        result => result,
    }
}

/// Until publication succeeds, only an exclusively created, still empty root
/// may be rolled back. Reused directories and concurrent arrivals are retained.
pub(crate) struct OutputRootCreation<'a> {
    path: &'a std::path::Path,
    rollback: bool,
}

impl<'a> OutputRootCreation<'a> {
    pub(crate) fn create(path: &'a std::path::Path, exclusive: bool) -> std::io::Result<Self> {
        if let Err(error) = create_output_root_exclusive(path) {
            if exclusive || error.kind() != std::io::ErrorKind::AlreadyExists || !path.is_dir() {
                return Err(error);
            }
        }
        Ok(Self { path, rollback: exclusive })
    }

    pub(crate) fn commit(mut self) { self.rollback = false; }
}

impl Drop for OutputRootCreation<'_> {
    fn drop(&mut self) {
        if self.rollback { let _ = std::fs::remove_dir(self.path); }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/scan/scope/tests.rs"]
mod tests;
