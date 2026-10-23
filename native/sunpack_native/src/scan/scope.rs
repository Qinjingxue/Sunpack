//! The filesystem boundary shared by discovery, relation recovery and Watch.
use crate::path_keys::path_key;
use pyo3::prelude::*;
use std::collections::HashSet;

#[pyclass(module = "sunpack_native", frozen, skip_from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct NativeDiscoveryScope {
    #[pyo3(get)]
    pub root: String,
    #[pyo3(get)]
    pub max_depth: Option<usize>,
    key: String,
    excluded: HashSet<String>,
}

impl NativeDiscoveryScope {
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

#[pymethods]
impl NativeDiscoveryScope {
    #[new]
    #[pyo3(signature = (root, max_depth=Some(0), excluded_subtrees=Vec::new()))]
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

    #[getter]
    pub(crate) fn excluded_subtrees(&self) -> Vec<String> {
        self.excluded.iter().cloned().collect()
    }

    pub fn contains(&self, path: &str) -> bool {
        let key = path_key(path);
        if key == self.key {
            return !self.excluded.contains(&key);
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
            && !self.excludes(path)
    }

    pub fn intersects_output(&self, path: &str) -> bool {
        let key = path_key(path);
        self.contains(path)
            || self
                .key
                .strip_prefix(key.trim_end_matches('\\'))
                .is_some_and(|relative| relative.starts_with('\\'))
    }

    pub fn excludes(&self, path: &str) -> bool {
        let key = path_key(path);
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
}

#[pyfunction]
pub(crate) fn create_output_root(py: Python<'_>, path: String) -> PyResult<()> {
    py.detach(|| {
        let path = std::path::Path::new(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(path)
    })
    .map_err(Into::into)
}
