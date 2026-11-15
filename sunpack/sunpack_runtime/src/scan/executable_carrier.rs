use crate::io::reader::ManagedReader;
use memchr::memmem;
use std::io;
use std::sync::OnceLock;

const SFX_STUB_SCAN_BYTES: u64 = 1024 * 1024;
const SEVEN_ZIP_SFX_MARKERS: [&[u8]; 6] = [
    b"7-Zip SFX",
    b"7z SFX",
    b"7-Zip self-extracting archive",
    b"7\0-\0Z\0i\0p\0 \0S\0F\0X\0",
    b"7\0z\0 \0S\0F\0X\0",
    b"7\0-\0Z\0i\0p\0 \0s\0e\0l\0f\0-\0e\0x\0t\0r\0a\0c\0t\0i\0n\0g\0 \0a\0r\0c\0h\0i\0v\0e\0",
];
const WINRAR_SFX_MARKERS: [&[u8]; 3] = [
    b"WinRAR SFX",
    b"RAR decompression sfx archive",
    b"W\0i\0n\0R\0A\0R\0 \0S\0F\0X\0",
];

pub(crate) fn executable_sfx_stub_profile(
    reader: &ManagedReader,
    executable_image_end: u64,
) -> io::Result<&'static str> {
    let probe_size = reader
        .len()
        .min(executable_image_end)
        .min(SFX_STUB_SCAN_BYTES);
    if probe_size == 0 {
        return Ok("");
    }
    let image = reader.read_direct_at(0, probe_size as usize)?;

    // Fixed, bounded matchers are shared; file bytes remain local to this probe.
    static SEVEN_ZIP: OnceLock<[memmem::Finder<'static>; 6]> = OnceLock::new();
    static WINRAR: OnceLock<[memmem::Finder<'static>; 3]> = OnceLock::new();
    let seven_zip = SEVEN_ZIP.get_or_init(|| SEVEN_ZIP_SFX_MARKERS.map(memmem::Finder::new));
    let winrar = WINRAR.get_or_init(|| WINRAR_SFX_MARKERS.map(memmem::Finder::new));
    if contains_any(&image, seven_zip) {
        return Ok("seven_zip_sfx");
    }
    if contains_any(&image, winrar) {
        return Ok("winrar_sfx");
    }
    Ok("")
}

fn contains_any(haystack: &[u8], patterns: &[memmem::Finder<'_>]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern.find(haystack).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    #[test]
    fn identifies_seven_zip_sfx_stub_from_pe_image_marker() {
        let mut data = b"MZ 7-Zip SFX".to_vec();
        data.resize(256, 0);
        let path = temp_file("seven_zip_sfx_stub", &data);
        assert_eq!(
            executable_sfx_stub_profile(&ManagedReader::open(&path).unwrap(), data.len() as u64)
                .unwrap(),
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
            executable_sfx_stub_profile(&ManagedReader::open(&path).unwrap(), data.len() as u64)
                .unwrap(),
            "winrar_sfx"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn arbitrary_pe_image_is_not_an_sfx_stub() {
        let mut data = b"MZ ordinary application".to_vec();
        data.resize(256, 0);
        let path = temp_file("plain_pe_not_sfx", &data);
        assert!(executable_sfx_stub_profile(
            &ManagedReader::open(&path).unwrap(),
            data.len() as u64
        )
        .unwrap()
        .is_empty());
        let _ = fs::remove_file(path);
    }
}
