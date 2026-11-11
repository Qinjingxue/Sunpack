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

/// One ordinary Windows filename component, shared by logical names and output routing.
pub(crate) fn output_name_component(value: &str) -> String {
    let part = value.rsplit(['\\', '/']).next().unwrap_or(value);
    if part.is_empty() {
        return "archive".to_owned();
    }
    if windows_output_part_needs_mapping(part) {
        windows_output_part(part)
    } else {
        part.to_owned()
    }
}
