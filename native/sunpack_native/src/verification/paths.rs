//! Output-name projection shared by source manifests and verification.
//! Keep the Windows mapping and numbered collisions aligned with the worker.
use crate::io::scratch::SpillMap;
use std::borrow::Cow;
use std::io;

/// The worker rejects rooted/drive paths and traversal, but accepts ./ and
/// repeated separators. Test the raw name before normalizing its components.
pub(crate) fn unsafe_archive_path(raw: &str) -> bool {
    raw.starts_with(['/', '\\'])
        || (raw.as_bytes().get(1) == Some(&b':') && raw.as_bytes()[0].is_ascii_alphabetic())
        || raw.split(['/', '\\']).any(|part| part == "..")
}

#[derive(Default)]
pub(crate) struct OutputPathAllocator {
    used: SpillMap<()>,
    next_numbers: SpillMap<usize>,
    directories: SpillMap<String>,
}

impl OutputPathAllocator {
    pub(crate) fn project(&mut self, raw: &str, is_directory: bool) -> io::Result<String> {
        if unsafe_archive_path(raw) {
            return Ok(raw.to_string());
        }
        let clean = windows_output_relative_path(clean_relative_archive_path(raw));
        if is_directory {
            self.allocate_directory(&clean)
        } else {
            self.allocate(clean.into_owned())
        }
    }

    pub(crate) fn allocate(&mut self, requested: String) -> io::Result<String> {
        let (parent, name) = requested.rsplit_once('/').unwrap_or(("", &requested));
        let parent = self.allocate_directory(parent)?;
        let requested = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        self.allocate_name(requested, false)
    }

    pub(crate) fn allocate_directory(&mut self, requested: &str) -> io::Result<String> {
        let mut missing = Vec::new();
        let mut cursor = requested.trim_end_matches('/');
        let mut parent = loop {
            if cursor.is_empty() {
                break String::new();
            }
            if let Some(mapped) = self.directories.get(&crate::path_keys::case_key(cursor))? {
                break mapped;
            }
            let (above, name) = cursor.rsplit_once('/').unwrap_or(("", cursor));
            missing.push((cursor, name));
            cursor = above;
        };
        for (original, name) in missing.into_iter().rev() {
            let path = if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            };
            parent = self.allocate_name(path, true)?;
            self.directories
                .put(crate::path_keys::case_key(original), parent.clone())?;
        }
        Ok(parent)
    }

    fn allocate_name(&mut self, requested: String, is_directory: bool) -> io::Result<String> {
        let key = crate::path_keys::case_key(&requested);
        if self.used.insert_new(key.clone(), ())? {
            return Ok(requested);
        }
        let mut next = self.next_numbers.get(&key)?.unwrap_or(1);
        let slash = requested.rfind('/').map_or(0, |position| position + 1);
        let dot = requested[slash..]
            .rfind('.')
            .filter(|&position| position > 0 && !is_directory);
        let split = dot.map_or(requested.len(), |position| slash + position);
        loop {
            let candidate = format!("{}({}){}", &requested[..split], next, &requested[split..]);
            next += 1;
            if self
                .used
                .insert_new(crate::path_keys::case_key(&candidate), ())?
            {
                self.next_numbers.put(key, next)?;
                return Ok(candidate);
            }
        }
    }
}

pub(crate) fn clean_relative_archive_path(value: &str) -> Cow<'_, str> {
    if !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
    {
        return Cow::Borrowed(value);
    }
    Cow::Owned(
        value
            .replace('\\', "/")
            .trim_matches('/')
            .split('/')
            .filter(|part| !part.is_empty() && *part != "." && *part != "..")
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn is_windows_invalid_name_char(value: char) -> bool {
    (value as u32) < 0x20 || matches!(value, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

/// Mirrors `is_windows_reserved_device_name` in the 7z bridge.
fn is_windows_reserved_device_name(part: &str) -> bool {
    let bytes = part.as_bytes();
    let mut stem = part.find('.').unwrap_or(bytes.len());
    while stem > 0 && bytes[stem - 1] == b' ' {
        stem -= 1;
    }
    if stem != 3 && stem != 4 {
        return false;
    }
    let prefix = [
        bytes[0].to_ascii_lowercase(),
        bytes[1].to_ascii_lowercase(),
        bytes[2].to_ascii_lowercase(),
    ];
    if stem == 3 {
        return matches!(&prefix, b"con" | b"prn" | b"aux" | b"nul");
    }
    matches!(bytes[3], b'1'..=b'9') && matches!(&prefix, b"com" | b"lpt")
}

fn windows_output_part_needs_mapping(part: &str) -> bool {
    part.chars().any(is_windows_invalid_name_char)
        || part.ends_with(['.', ' '])
        || is_windows_reserved_device_name(part)
}

/// Mirrors `make_windows_safe_path_part` in the 7z bridge.
fn windows_output_part(part: &str) -> String {
    let mut mapped: String = part
        .chars()
        .map(|value| {
            if is_windows_invalid_name_char(value) {
                '_'
            } else {
                value
            }
        })
        .collect();
    let kept = mapped.trim_end_matches(['.', ' ']).len();
    let trailing = mapped.len() - kept;
    mapped.truncate(kept);
    mapped.extend(std::iter::repeat('_').take(trailing));
    if is_windows_reserved_device_name(&mapped) {
        mapped.insert(0, '_');
    }
    mapped
}

/// Project a cleaned archive path onto the name the worker writes on disk.
/// The mapping is idempotent, so already-projected output paths pass through.
pub(crate) fn windows_output_relative_path(cleaned: Cow<'_, str>) -> Cow<'_, str> {
    if !cleaned.split('/').any(windows_output_part_needs_mapping) {
        return cleaned;
    }
    Cow::Owned(
        cleaned
            .split('/')
            .map(windows_output_part)
            .collect::<Vec<_>>()
            .join("/"),
    )
}
