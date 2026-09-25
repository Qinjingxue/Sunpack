use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use std::io;

const CHUNK_BYTES: usize = 1024 * 1024;
const SFX_STUB_SCAN_BYTES: u64 = 1024 * 1024;
const NSIS_OVERLAY_PROBE_BYTES: u64 = 64;
const GODOT_PCK_MAGIC: &[u8; 4] = b"GDPC";
const GODOT_PCK_HEADER_BYTES: usize = 8;
const GODOT_PCK_TRAILER_BYTES: u64 = 12;
const GODOT_PCK_SECTION_ALIGNMENT_BYTES: usize = 8;
const GODOT_PCK_SUPPORTED_VERSIONS: [u32; 3] = [2, 3, 4];
const QT_IFW_TAIL_WINDOW_BYTES: u64 = 1024 * 1024;
const QT_IFW_MAGIC_COOKIE: u64 = 0xC2630A1C99D668F8;
const QT_IFW_MAGIC_MARKERS: [u64; 4] = [0x12023233, 0x12023234, 0x12023235, 0x12023236];
const PYINSTALLER_COOKIE: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const NSIS_FIRST_HEADER_SIGNATURE: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
const SEVEN_ZIP_SFX_MARKERS: &[&[u8]] = &[
    b"7-Zip SFX",
    b"7z SFX",
    b"7-Zip self-extracting archive",
    b"7\0-\0Z\0i\0p\0 \0S\0F\0X\0",
    b"7\0z\0 \0S\0F\0X\0",
    b"7\0-\0Z\0i\0p\0 \0s\0e\0l\0f\0-\0e\0x\0t\0r\0a\0c\0t\0i\0n\0g\0 \0a\0r\0c\0h\0i\0v\0e\0",
];
const WINRAR_SFX_MARKERS: &[&[u8]] = &[
    b"WinRAR SFX",
    b"RAR decompression sfx archive",
    b"W\0i\0n\0R\0A\0R\0 \0S\0F\0X\0",
];
const SQUIRREL_AWARE_VERSION_UTF16: &[u8] =
    b"S\0q\0u\0i\0r\0r\0e\0l\0A\0w\0a\0r\0e\0V\0e\0r\0s\0i\0o\0n\0";
const SQUIRREL_SETUP_LOG_UTF16: &[u8] = b"S\0q\0u\0i\0r\0r\0e\0l\0S\0e\0t\0u\0p\0.\0l\0o\0g\0";

const PROFILES: &[(&str, &[&[u8]])] = &[
    (
        "inno_setup",
        &[b"Inno Setup Setup Data (", b"JR.Inno.Setup"],
    ),
    (
        "squirrel_windows",
        &[SQUIRREL_AWARE_VERSION_UTF16, SQUIRREL_SETUP_LOG_UTF16],
    ),
    ("par_packer", &[b"PAR::Packer", b"PAR_TEMP"]),
    ("nuitka_onefile", &[b"NUITKA_ONEFILE_PARENT"]),
];

/// Identify known executable application/installer bundles without exposing file bytes to Python.
#[pyfunction]
#[pyo3(signature = (path, scan_limit_bytes, executable_image_end, pck_section_offset=0))]
pub(crate) fn executable_runtime_bundle_profile(
    py: Python<'_>,
    path: &str,
    scan_limit_bytes: u64,
    executable_image_end: u64,
    pck_section_offset: u64,
) -> String {
    let path = path.to_owned();
    py.detach(move || {
        runtime_bundle_profile_native(
            &path,
            scan_limit_bytes,
            executable_image_end,
            pck_section_offset,
        )
        .unwrap_or_default()
    })
}

fn runtime_bundle_profile_native(
    path: &str,
    scan_limit_bytes: u64,
    executable_image_end: u64,
    pck_section_offset: u64,
) -> io::Result<String> {
    if path.is_empty() || scan_limit_bytes == 0 {
        return Ok(String::new());
    }

    let image_scan_limit = if executable_image_end > 0 {
        scan_limit_bytes.min(executable_image_end)
    } else {
        scan_limit_bytes
    };
    let reader = ManagedReader::open(path)?;
    if godot_embedded_pck_layout_matches(&reader, pck_section_offset)? {
        return Ok("godot_embedded_pck".to_owned());
    }
    if let Some(profile) = scan_image_profiles(&reader, image_scan_limit)? {
        return Ok(profile.to_owned());
    }
    if nsis_overlay_layout_matches(&reader, executable_image_end)? {
        return Ok("nsis".to_owned());
    }
    if qt_ifw_tail_layout_matches(&reader)? {
        return Ok("qt_installer_framework".to_owned());
    }
    if tail_contains(&reader, PYINSTALLER_COOKIE, 256)? {
        return Ok("pyinstaller".to_owned());
    }
    Ok(String::new())
}

pub(crate) fn executable_sfx_stub_profile(path: &str, executable_image_end: u64) -> String {
    sfx_stub_profile_native(path, executable_image_end).unwrap_or_default()
}

fn sfx_stub_profile_native(path: &str, executable_image_end: u64) -> io::Result<String> {
    if path.is_empty() || executable_image_end == 0 {
        return Ok(String::new());
    }

    let reader = ManagedReader::open(path)?;
    let probe_size = reader
        .len()
        .min(executable_image_end)
        .min(SFX_STUB_SCAN_BYTES);
    if probe_size == 0 {
        return Ok(String::new());
    }
    let image = reader.read_at(0, probe_size as usize)?;

    if contains_any(&image, SEVEN_ZIP_SFX_MARKERS) {
        return Ok("seven_zip_sfx".to_owned());
    }
    if contains_any(&image, WINRAR_SFX_MARKERS) {
        return Ok("winrar_sfx".to_owned());
    }
    Ok(String::new())
}

fn contains_any(haystack: &[u8], patterns: &[&[u8]]) -> bool {
    patterns
        .iter()
        .any(|pattern| find_subslice(haystack, pattern).is_some())
}

fn godot_embedded_pck_layout_matches(
    reader: &ManagedReader,
    pck_section_offset: u64,
) -> io::Result<bool> {
    if pck_section_offset > 0 && pck_section_offset < reader.len() {
        let available = reader.len() - pck_section_offset;
        let probe_size = available.min(
            (GODOT_PCK_SECTION_ALIGNMENT_BYTES + GODOT_PCK_HEADER_BYTES - 1) as u64,
        ) as usize;
        if probe_size >= GODOT_PCK_HEADER_BYTES {
            let probe = reader.read_at(pck_section_offset, probe_size)?;
            for offset in 0..GODOT_PCK_SECTION_ALIGNMENT_BYTES {
                let Some(header) = probe.get(offset..offset + GODOT_PCK_HEADER_BYTES) else {
                    break;
                };
                if godot_pck_header_matches(header) {
                    return Ok(true);
                }
            }
        }
    }

    let file_size = reader.len();
    if file_size < GODOT_PCK_TRAILER_BYTES + GODOT_PCK_HEADER_BYTES as u64 {
        return Ok(false);
    }
    let trailer = reader.read_at(
        file_size - GODOT_PCK_TRAILER_BYTES,
        GODOT_PCK_TRAILER_BYTES as usize,
    )?;
    if &trailer[8..12] != GODOT_PCK_MAGIC {
        return Ok(false);
    }
    let pck_size = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    if pck_size < GODOT_PCK_HEADER_BYTES as u64
        || pck_size > file_size - GODOT_PCK_TRAILER_BYTES
    {
        return Ok(false);
    }
    let pck_start = file_size - GODOT_PCK_TRAILER_BYTES - pck_size;
    let header = reader.read_at(pck_start, GODOT_PCK_HEADER_BYTES)?;
    Ok(godot_pck_header_matches(&header))
}

fn godot_pck_header_matches(header: &[u8]) -> bool {
    if header.len() < GODOT_PCK_HEADER_BYTES || &header[..4] != GODOT_PCK_MAGIC {
        return false;
    }
    let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
    GODOT_PCK_SUPPORTED_VERSIONS.contains(&version)
}

fn nsis_overlay_layout_matches(
    reader: &ManagedReader,
    executable_image_end: u64,
) -> io::Result<bool> {
    if executable_image_end == 0 || executable_image_end >= reader.len() {
        return Ok(false);
    }
    let available = reader.len() - executable_image_end;
    let probe_size = available.min(NSIS_OVERLAY_PROBE_BYTES) as usize;
    let header = reader.read_at(executable_image_end, probe_size)?;
    Ok(find_subslice(&header, NSIS_FIRST_HEADER_SIGNATURE).is_some())
}

fn scan_image_profiles(
    reader: &ManagedReader,
    scan_limit_bytes: u64,
) -> io::Result<Option<&'static str>> {
    let patterns: Vec<&[u8]> = PROFILES
        .iter()
        .flat_map(|(_, required)| required.iter().copied())
        .collect();
    let overlap = patterns
        .iter()
        .map(|pattern| pattern.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut matched = vec![false; patterns.len()];
    let mut remaining = scan_limit_bytes.min(reader.len());
    let mut offset = 0u64;
    let mut carry = Vec::with_capacity(overlap);
    let mut chunk = vec![0u8; CHUNK_BYTES];

    while remaining > 0 {
        let requested = usize::try_from(remaining.min(CHUNK_BYTES as u64)).unwrap_or(CHUNK_BYTES);
        let data = reader.read_at(offset, requested)?;
        let count = data.len();
        if count == 0 {
            break;
        }
        let mut sample = Vec::with_capacity(carry.len() + count);
        sample.extend_from_slice(&carry);
        chunk[..count].copy_from_slice(&data);
        sample.extend_from_slice(&chunk[..count]);
        for (index, pattern) in patterns.iter().enumerate() {
            if !matched[index] && find_subslice(&sample, pattern).is_some() {
                matched[index] = true;
            }
        }
        let mut pattern_index = 0usize;
        for (profile, required) in PROFILES {
            let end = pattern_index + required.len();
            if matched[pattern_index..end].iter().all(|value| *value) {
                return Ok(Some(profile));
            }
            pattern_index = end;
        }
        carry.clear();
        carry.extend_from_slice(&sample[sample.len().saturating_sub(overlap)..]);
        remaining -= count as u64;
        offset += count as u64;
    }
    Ok(None)
}

fn qt_ifw_tail_layout_matches(reader: &ManagedReader) -> io::Result<bool> {
    let file_size = reader.len();
    let window_start = file_size.saturating_sub(QT_IFW_TAIL_WINDOW_BYTES);
    let tail = reader.read_at(window_start, (file_size - window_start) as usize)?;
    let cookie = QT_IFW_MAGIC_COOKIE.to_le_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = find_subslice(&tail[search_start..], &cookie) {
        let offset = search_start + relative;
        if offset >= 16 {
            let marker = u64::from_le_bytes(tail[offset - 8..offset].try_into().unwrap());
            let binary_content_size =
                u64::from_le_bytes(tail[offset - 16..offset - 8].try_into().unwrap());
            let end_of_binary_content = window_start + offset as u64 + cookie.len() as u64;
            if QT_IFW_MAGIC_MARKERS.contains(&marker)
                && (24..=end_of_binary_content).contains(&binary_content_size)
            {
                return Ok(true);
            }
        }
        search_start = offset + 1;
    }
    Ok(false)
}

fn tail_contains(reader: &ManagedReader, pattern: &[u8], window_bytes: u64) -> io::Result<bool> {
    let size = reader.len();
    let start = size.saturating_sub(window_bytes);
    let tail = reader.read_at(start, (size - start) as usize)?;
    Ok(find_subslice(&tail, pattern).is_some())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    #[test]
    fn identifies_profile_split_across_chunks() {
        let mut data = vec![b'x'; CHUNK_BYTES - 4];
        data.extend_from_slice(b"PAR::Packer");
        data.extend_from_slice(b"gap PAR_TEMP");
        let path = temp_file("runtime_profile_chunk", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            data.len() as u64,
            data.len() as u64,
            0,
        )
        .unwrap();
        assert_eq!(profile, "par_packer");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ignores_profile_markers_beyond_the_pe_image() {
        let data = b"MZpayload Inno Setup Setup Data ( gap JR.Inno.Setup";
        let path = temp_file("runtime_profile_overlay", data);
        let profile =
            runtime_bundle_profile_native(path.to_str().unwrap(), data.len() as u64, 2, 0).unwrap();
        assert!(profile.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_nsis_overlay_header_without_scanning_the_payload() {
        let image_end = 64u64;
        let mut data = vec![b'x'; image_end as usize];
        data.extend_from_slice(b"\x04\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst\x00\x00\x00\x00");
        data.extend_from_slice(&vec![b'z'; 4096]);
        let path = temp_file("runtime_profile_nsis", &data);
        let profile =
            runtime_bundle_profile_native(path.to_str().unwrap(), image_end, image_end, 0).unwrap();
        assert_eq!(profile, "nsis");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_godot_embedded_pck_from_named_section_offset() {
        let pck_offset = 64u64;
        let mut data = vec![b'x'; pck_offset as usize];
        data.extend_from_slice(b"\0\0GDPC");
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"payload");
        let path = temp_file("runtime_profile_godot_section", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            data.len() as u64,
            pck_offset,
            pck_offset,
        )
        .unwrap();
        assert_eq!(profile, "godot_embedded_pck");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_godot_embedded_pck_from_self_describing_footer() {
        let mut data = b"MZ ordinary executable".to_vec();
        data.resize(64, 0);
        let mut pck = b"GDPC".to_vec();
        pck.extend_from_slice(&3u32.to_le_bytes());
        pck.extend_from_slice(b"project payload");
        data.extend_from_slice(&pck);
        data.extend_from_slice(&(pck.len() as u64).to_le_bytes());
        data.extend_from_slice(GODOT_PCK_MAGIC);
        let path = temp_file("runtime_profile_godot_footer", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            data.len() as u64,
            64,
            0,
        )
        .unwrap();
        assert_eq!(profile, "godot_embedded_pck");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_godot_magic_with_unsupported_pack_version() {
        let mut data = b"MZ ordinary executable".to_vec();
        data.resize(64, 0);
        let mut pck = b"GDPC".to_vec();
        pck.extend_from_slice(&99u32.to_le_bytes());
        pck.extend_from_slice(b"payload");
        data.extend_from_slice(&pck);
        data.extend_from_slice(&(pck.len() as u64).to_le_bytes());
        data.extend_from_slice(GODOT_PCK_MAGIC);
        let path = temp_file("runtime_profile_godot_version", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        assert!(profile.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_godot_footer_magic_without_valid_back_pointer() {
        let mut data = b"MZ ordinary executable".to_vec();
        data.resize(64, 0);
        data.extend_from_slice(b"not a pck");
        data.extend_from_slice(&9u64.to_le_bytes());
        data.extend_from_slice(GODOT_PCK_MAGIC);
        let path = temp_file("runtime_profile_godot_false_footer", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        assert!(profile.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_seven_zip_sfx_stub_from_pe_image_marker() {
        let mut data = b"MZ 7-Zip SFX".to_vec();
        data.resize(256, 0);
        let path = temp_file("seven_zip_sfx_stub", &data);
        assert_eq!(
            sfx_stub_profile_native(path.to_str().unwrap(), data.len() as u64).unwrap(),
            "seven_zip_sfx"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_winrar_sfx_stub_from_pe_image_marker() {
        let mut data = b"MZ WinRAR SFX".to_vec();
        data.resize(256, 0);
        let path = temp_file("winrar_sfx_stub", &data);
        assert_eq!(
            sfx_stub_profile_native(path.to_str().unwrap(), data.len() as u64).unwrap(),
            "winrar_sfx"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn arbitrary_pe_image_is_not_an_sfx_stub() {
        let mut data = b"MZ ordinary application".to_vec();
        data.resize(256, 0);
        let path = temp_file("plain_pe_not_sfx", &data);
        assert!(
            sfx_stub_profile_native(path.to_str().unwrap(), data.len() as u64)
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_qt_ifw_tail_layout() {
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&64u64.to_le_bytes());
        data.extend_from_slice(&QT_IFW_MAGIC_MARKERS[0].to_le_bytes());
        data.extend_from_slice(&QT_IFW_MAGIC_COOKIE.to_le_bytes());
        let path = temp_file("runtime_profile_qt", &data);
        let profile = runtime_bundle_profile_native(path.to_str().unwrap(), 2, 2, 0).unwrap();
        assert_eq!(profile, "qt_installer_framework");
        let _ = fs::remove_file(path);
    }
}
