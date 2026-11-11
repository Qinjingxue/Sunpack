//! Windows filesystem case mapping: one UTF-16 unit stays one unit. Unicode
//! text lowercasing can merge distinct names (for example İ and i + U+0307).

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn RtlDowncaseUnicodeChar(source: u16) -> u16;
}

/// Use the same non-expanding filesystem map for strings and handle buffers.
#[cfg(windows)]
pub(crate) fn case_key_unit(unit: u16) -> u16 {
    if unit <= 0x7f {
        (unit as u8).to_ascii_lowercase() as u16
    } else {
        unsafe { RtlDowncaseUnicodeChar(unit) }
    }
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
                return char::from_u32(case_key_unit(ch as u16) as u32).unwrap_or(ch);
            }
            ch.to_ascii_lowercase()
        })
        .collect()
}

pub(crate) fn path_key(value: &str) -> String {
    let key = case_key(value);
    if key.contains('/') {
        key.replace('/', "\\")
    } else {
        key
    }
}

pub(crate) fn path_ancestors(key: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(key.trim_end_matches('\\')), |key| {
        key.rsplit_once('\\').map(|(parent, _)| parent)
    })
}

pub(crate) fn normalize_windows_extended_prefix(mut path: String) -> String {
    if path.starts_with(r"\\?\UNC\") {
        path.replace_range(..8, r"\\");
    } else if path.starts_with(r"\\?\") {
        path.replace_range(..4, "");
    }
    path
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

pub(crate) fn merge_release_roots(paths: Vec<String>) -> Vec<String> {
    merge_roots(paths, |path| path_key(path))
}
