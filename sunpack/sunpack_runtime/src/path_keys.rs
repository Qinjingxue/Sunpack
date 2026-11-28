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
    let mut key = String::with_capacity(value.len());
    case_key_into(value, &mut key);
    key
}

pub(crate) fn case_key_into(value: &str, key: &mut String) {
    key.clear();
    if value.is_ascii() {
        key.push_str(value);
        key.make_ascii_lowercase();
        return;
    }
    key.reserve(value.len());
    key.extend(value.chars().map(|ch| {
        #[cfg(windows)]
        if ch as u32 <= u16::MAX as u32 {
            // NT's filesystem mapping is independent of the process locale
            // and does not expand characters or fold surrogate pairs.
            return char::from_u32(case_key_unit(ch as u16) as u32).unwrap_or(ch);
        }
        ch.to_ascii_lowercase()
    }));
}

pub(crate) fn path_key(value: &str) -> String {
    let mut key = String::with_capacity(value.len());
    path_key_into(value, &mut key);
    key
}

pub(crate) fn path_key_into(value: &str, key: &mut String) {
    case_key_into(value, key);
    if let Some(first) = memchr::memchr(b'/', key.as_bytes()) {
        // Replacing one ASCII separator with another preserves UTF-8.
        for byte in unsafe { key.as_bytes_mut() }[first..].iter_mut() {
            if *byte == b'/' {
                *byte = b'\\';
            }
        }
    }
}

/// Join groups that refer to the same physical path, including transitive overlaps.
pub(crate) fn path_components<'a>(
    groups: impl ExactSizeIterator<Item = impl Iterator<Item = &'a str>>,
) -> (Vec<usize>, std::collections::HashMap<String, usize>) {
    let mut parents: Vec<_> = (0..groups.len()).collect();
    let mut owners = std::collections::HashMap::new();
    for (index, paths) in groups.enumerate() {
        for path in paths {
            if let Some(other) = owners.insert(path_key(path), index) {
                let left = component_root(&mut parents, index);
                let right = component_root(&mut parents, other);
                parents[left] = right;
            }
        }
    }
    (parents, owners)
}

pub(crate) fn component_root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

pub(crate) fn path_ancestors(key: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(key.trim_end_matches('\\')), |key| {
        key.rsplit_once('\\').map(|(parent, _)| parent)
    })
}

pub(crate) fn descendant_key_range(key: &str) -> std::ops::Range<String> {
    let base = key.trim_end_matches('\\');
    // ']' immediately follows '\\' in byte order.
    format!("{base}\\")..format!("{base}]")
}

pub(crate) fn normalize_windows_extended_prefix(mut path: String) -> String {
    if path.starts_with(r"\\?\UNC\") {
        path.replace_range(..8, r"\\");
    } else if path.starts_with(r"\\?\") {
        path.replace_range(..4, "");
    }
    path
}

/// Resolve the existing prefix too: outputs below a junction need their real
/// namespace before mkdir, even when more than one suffix component is absent.
pub(crate) fn resolved_path_key(path: &std::path::Path) -> String {
    for ancestor in path.ancestors() {
        if let Ok(canonical) = std::fs::canonicalize(ancestor) {
            if let Ok(relative) = path.strip_prefix(ancestor) {
                let resolved = if relative.as_os_str().is_empty() {
                    canonical
                } else {
                    canonical.join(relative)
                };
                return path_key(&normalize_windows_extended_prefix(
                    resolved.to_string_lossy().into_owned(),
                ));
            }
        }
    }
    path_key(&normalize_windows_extended_prefix(path.to_string_lossy().into_owned()))
}

/// Persist both names once at output publication. Event lookup stays lexical
/// and must never resolve a retargeted junction to guess an old alias pair.
pub(crate) fn output_path_aliases(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let absolute = normalize_windows_extended_prefix(
        std::path::absolute(path)?.to_string_lossy().into_owned(),
    );
    let resolved = resolved_path_key(std::path::Path::new(&absolute));
    if path_key(&absolute) == resolved {
        Ok(vec![absolute])
    } else {
        Ok(vec![absolute, resolved])
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
    keyed.dedup_by(|child, parent| child.0.starts_with(&parent.0));
    keyed.into_iter().map(|(_, root)| root).collect()
}
