use super::*;
use crate::test_support::temp_file;
use std::fs;

#[test]
fn zip_scan_honors_utf8_filename_flag() {
    let raw_name = "中文/说明.txt".as_bytes();
    let local = b"local payload before central directory".to_vec();
    let central_offset = local.len() as u32;
    let mut central = vec![0; ZIP_CENTRAL_HEADER_LENGTH];
    central[0..4].copy_from_slice(ZIP_CENTRAL_DIRECTORY_SIGNATURE);
    central[8..10].copy_from_slice(&ZIP_UTF8_FLAG.to_le_bytes());
    central[28..30].copy_from_slice(&(raw_name.len() as u16).to_le_bytes());
    central.extend_from_slice(raw_name);
    let eocd = [
        ZIP_EOCD_SIGNATURE,
        &[0, 0, 0, 0],
        &1u16.to_le_bytes(),
        &1u16.to_le_bytes(),
        &(central.len() as u32).to_le_bytes(),
        &central_offset.to_le_bytes(),
        &((2 * ZIP_EOCD_SIGNATURE.len()) as u16).to_le_bytes(),
        ZIP_EOCD_SIGNATURE,
        ZIP_EOCD_SIGNATURE,
    ]
    .concat();
    let contents = [local, central, eocd].concat();
    let path = temp_file("zip_names", &contents);
    let archive = ArchiveInput::file(
        path.to_string_lossy().into_owned(),
        "zip".into(),
        "zip_names".into(),
    );
    assert_eq!(analyze_zip_filename_encoding(&archive).unwrap(), None);
    let _ = fs::remove_file(path);
}

#[test]
fn zip_eocd_prefers_exact_tail_and_falls_back_to_latest_record() {
    use crate::formats::zip::find_eocd_prefer_exact;

    let mut end_record = [0; 22];
    end_record[..4].copy_from_slice(ZIP_EOCD_SIGNATURE);
    let mut with_comment = end_record;
    with_comment[20..].copy_from_slice(&23u16.to_le_bytes());
    let mut tail = [with_comment.as_slice(), &end_record, b"x"].concat();
    assert_eq!(find_eocd_prefer_exact(&tail).unwrap().offset, 0);
    tail.push(b'y');
    assert_eq!(find_eocd_prefer_exact(&tail).unwrap().offset, 22);
}

#[test]
fn zip_scan_validates_unicode_path_extra_field() {
    let raw_name = "日本語.txt".as_bytes().to_vec();
    let unicode_name = "正しい名前.txt".as_bytes();
    let mut extra = Vec::new();
    extra.extend_from_slice(&ZIP_UNICODE_PATH_EXTRA_FIELD.to_le_bytes());
    extra.extend_from_slice(&((5 + unicode_name.len()) as u16).to_le_bytes());
    extra.push(1);
    extra.extend_from_slice(&crc32fast::hash(&raw_name).to_le_bytes());
    extra.extend_from_slice(unicode_name);

    assert!(valid_unicode_path_name(&raw_name, &extra));
    extra[5] ^= 1;
    assert!(!valid_unicode_path_name(&raw_name, &extra));
}

#[test]
fn scoring_keeps_repeated_shift_jis_parent_from_looking_like_gbk() {
    let parent = "無知_製品0519c";
    let mut owned = Vec::new();
    for index in 0..2500 {
        let value = format!("{parent}/assets/file_{index:04}.bin");
        let (bytes, _, had_errors) = SHIFT_JIS.encode(&value);
        assert!(!had_errors);
        owned.push(bytes.into_owned());
    }
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    assert_eq!(select_codepage(&refs), Some("932"));
}

#[test]
fn scoring_keeps_shift_jis_kanji_only_name() {
    let (bytes, _, had_errors) = SHIFT_JIS.encode("更新履歴.txt");
    assert!(!had_errors);
    let refs = [bytes.as_ref()];
    assert_eq!(select_codepage(&refs), Some("932"));
}

#[test]
fn numbered_names_do_not_repeat_encoding_evidence() {
    let (first, _, first_invalid) = BIG5.encode("風景_001.jpg");
    let (second, _, second_invalid) = BIG5.encode("風景_002.jpg");
    assert!(!first_invalid && !second_invalid);
    let single = select_codepage(&[first.as_ref()]);
    assert!(matches!(single, None | Some("950")));
    assert_eq!(select_codepage(&[first.as_ref(), second.as_ref()]), single);
}
