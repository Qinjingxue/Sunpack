//! Windows filesystem case mapping: one UTF-16 unit stays one unit. Unicode
//! text lowercasing can merge distinct names (for example İ and i + U+0307).

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn RtlDowncaseUnicodeChar(source: u16) -> u16;
}

pub(crate) fn case_key(value: &str) -> String {
    if value.is_ascii() {
        return value.to_ascii_lowercase();
    }
    value
        .chars()
        .map(|ch| {
            #[cfg(windows)]
            if ch as u32 <= u16::MAX as u32 {
                // NT's filesystem mapping is independent of the process locale
                // and does not expand characters or fold surrogate pairs.
                return char::from_u32(unsafe { RtlDowncaseUnicodeChar(ch as u16) } as u32)
                    .unwrap_or(ch);
            }
            ch.to_ascii_lowercase()
        })
        .collect()
}

#[pyo3::pyfunction(name = "windows_path_key")]
pub(crate) fn path_key(value: &str) -> String {
    let key = case_key(value);
    if key.contains('/') {
        key.replace('/', "\\")
    } else {
        key
    }
}

/// A trailing separator keeps each parent's descendants adjacent in sort order,
/// even when a sibling name contains punctuation before '\\'. Only the last
/// retained root can contain the next key, so reduction is linear after sorting.
pub(crate) fn merge_roots<T>(
    roots: impl IntoIterator<Item = T>,
    key: impl Fn(&T) -> String,
) -> Vec<T> {
    let mut keyed: Vec<_> = roots
        .into_iter()
        .map(|root| {
            let mut key = key(&root);
            key.truncate(key.trim_end_matches('\\').len());
            key.push('\\');
            (key, root)
        })
        .collect();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut merged: Vec<(String, T)> = Vec::with_capacity(keyed.len());
    for (key, root) in keyed {
        if merged
            .last()
            .is_some_and(|(parent, _)| key.starts_with(parent))
        {
            continue;
        }
        merged.push((key, root));
    }
    merged.into_iter().map(|(_, root)| root).collect()
}

#[pyo3::pyfunction]
pub(crate) fn merge_release_roots(py: pyo3::Python<'_>, paths: Vec<String>) -> Vec<String> {
    py.detach(|| merge_roots(paths, |path| path_key(path)))
}
