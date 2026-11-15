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
