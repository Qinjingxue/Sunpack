//! The filesystem boundary shared by discovery, relation recovery and Watch.
use crate::path_keys::path_key;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub(crate) struct NativeDiscoveryScope {
    pub root: String,
    pub max_depth: Option<usize>,
    key: String,
    excluded: HashSet<String>,
}

impl NativeDiscoveryScope {
    pub(crate) fn has_exclusions(&self) -> bool {
        !self.excluded.is_empty()
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        if key == self.key {
            return !self.excluded.contains(key);
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
        if self.excluded.is_empty() {
            return false;
        }
        let mut current = key.trim_end_matches('\\');
        loop {
            if self.excluded.contains(current) {
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
        self.excluded
            .extend(roots.map(|p| path_key(&p).trim_end_matches('\\').to_owned()));
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
        let key = path_key(&root).trim_end_matches('\\').to_owned();
        Self {
            root,
            max_depth,
            key,
            excluded: excluded_subtrees
                .iter()
                .map(|p| path_key(p).trim_end_matches('\\').to_owned())
                .collect(),
        }
    }

    pub(crate) fn excluded_subtrees(&self) -> Vec<String> {
        self.excluded.iter().cloned().collect()
    }

    pub fn contains(&self, path: &str) -> bool {
        self.contains_key(&path_key(path))
    }

    pub fn intersects_output(&self, path: &str) -> bool {
        let key = path_key(path);
        self.contains_key(&key)
            || self
                .key
                .strip_prefix(key.trim_end_matches('\\'))
                .is_some_and(|relative| relative.starts_with('\\'))
    }

    pub fn excludes(&self, path: &str) -> bool {
        self.has_exclusions() && self.excludes_key(&path_key(path))
    }
}

pub(crate) fn create_output_root_exclusive(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(path)
}

/// Until publication succeeds, only an exclusively created, still empty root
/// may be rolled back. Reused directories and concurrent arrivals are retained.
pub(crate) struct OutputRootCreation<'a> {
    path: &'a std::path::Path,
    rollback: bool,
}

impl<'a> OutputRootCreation<'a> {
    pub(crate) fn create(path: &'a std::path::Path, exclusive: bool) -> std::io::Result<Self> {
        if exclusive { create_output_root_exclusive(path)?; }
        else { std::fs::create_dir_all(path)?; }
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
mod tests {
    use super::*;

    #[test]
    fn output_publication_failure_rolls_back_only_new_empty_root() {
        let marker = crate::test_support::temp_file("output_publication_failure", b"");
        let root = marker.with_extension("output");
        let publish = |exclusive, arrival| -> std::io::Result<()> {
            let _creation = OutputRootCreation::create(&root, exclusive)?;
            if arrival { std::fs::write(root.join("external.txt"), b"keep")?; }
            // Identity/alias publication fails after mkdir, before the caller
            // can add this directory to its extraction rollback receipts.
            Err(std::io::ErrorKind::PermissionDenied.into())
        };
        assert!(publish(true, false).is_err());
        assert!(!root.exists());
        std::fs::create_dir(&root).unwrap();
        assert!(publish(false, false).is_err());
        assert!(root.is_dir());
        assert!(publish(true, false).is_err()); // existing directory is not ours
        assert!(root.is_dir());
        std::fs::remove_dir(&root).unwrap();
        assert!(publish(true, true).is_err());
        assert_eq!(std::fs::read(root.join("external.txt")).unwrap(), b"keep");
        std::fs::remove_file(root.join("external.txt")).unwrap();
        std::fs::remove_dir(&root).unwrap();
        OutputRootCreation::create(&root, true).unwrap().commit();
        assert!(root.is_dir());
        std::fs::remove_dir(&root).unwrap();
        std::fs::remove_file(marker).unwrap();
    }
}
