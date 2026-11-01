use crate::io::resource_lifecycle::TrackedFile;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyString};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

/// Keep literal password lines, including whitespace and a UTF-8 BOM, just as
/// the text-file/str.splitlines path did. Only the current line is buffered.
#[pyfunction]
#[pyo3(signature = (path, initial=None))]
pub(crate) fn read_password_file(
    py: Python<'_>,
    path: PathBuf,
    initial: Option<Vec<String>>,
) -> PyResult<Py<PyList>> {
    let passwords = py.detach(move || -> io::Result<Vec<Arc<str>>> {
        let file = TrackedFile::open_reader(path, "password_file")?;
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        let mut line = String::new();
        let mut passwords = Vec::new();
        // CLI supplies its leading candidates to merge/dedupe before creating
        // Python strings. Plain file readers retain their original duplicates.
        let mut seen: Option<HashSet<Arc<str>>> = initial.as_ref().map(|_| HashSet::new());
        let mut append = |value: &str| {
            if seen.as_ref().is_some_and(|seen| seen.contains(value)) {
                return;
            }
            let value: Arc<str> = Arc::from(value);
            if let Some(seen) = seen.as_mut() {
                seen.insert(Arc::clone(&value));
            }
            passwords.push(value);
        };
        for value in initial.iter().flatten() {
            append(value);
        }
        while reader.read_line(&mut line)? != 0 {
            for value in line
                .split([
                    '\n', '\r', '\u{000b}', '\u{000c}', '\u{001c}', '\u{001d}', '\u{001e}',
                    '\u{0085}', '\u{2028}', '\u{2029}',
                ])
                .filter(|part| !part.is_empty())
            {
                append(value);
            }
            line.clear();
        }
        Ok(passwords)
    })?;
    // The dedupe index has already been released. Consume each retained line
    // while creating its sole Python string, rather than holding both tables.
    Ok(PyList::new(
        py,
        passwords.into_iter().map(|value| PyString::new(py, &value)),
    )?
    .unbind())
}
