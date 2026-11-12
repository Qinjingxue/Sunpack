use crate::io::resource_lifecycle::TrackedFile;
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

/// Keep literal password lines, including whitespace and a UTF-8 BOM, just as
/// the text-file/str.splitlines path did. Only the current line is buffered.
pub(crate) fn read_password_file(
    path: PathBuf,
    initial: Option<Vec<Arc<str>>>,
) -> io::Result<Vec<Arc<str>>> {
    let file = TrackedFile::open_reader(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut line = String::new();
    let mut passwords = Vec::new();
    // Supplying leading candidates enables deduplication in order of first use.
    let mut seen: Option<HashSet<Arc<str>>> = initial.as_ref().map(|_| HashSet::new());
    for value in initial.into_iter().flatten() {
        if seen
            .as_mut()
            .is_some_and(|seen| seen.insert(Arc::clone(&value)))
        {
            passwords.push(value);
        }
    }
    while reader.read_line(&mut line)? != 0 {
        // Some worker backends consume NUL-terminated passwords. Passing this
        // line through could authenticate its prefix and report a false match.
        if line.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "passwords must not contain NUL characters",
            ));
        }
        for value in line
            .split([
                '\n', '\r', '\u{000b}', '\u{000c}', '\u{001c}', '\u{001d}', '\u{001e}', '\u{0085}',
                '\u{2028}', '\u{2029}',
            ])
            .filter(|part| !part.is_empty())
        {
            if seen.as_ref().is_some_and(|seen| seen.contains(value)) {
                continue;
            }
            let value: Arc<str> = Arc::from(value);
            if let Some(seen) = seen.as_mut() {
                seen.insert(Arc::clone(&value));
            }
            passwords.push(value);
        }
        line.clear();
    }
    Ok(passwords)
}
