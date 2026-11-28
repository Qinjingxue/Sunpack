use super::*;
use crate::io::archive_state::{InputExtent, InputPart};
use crate::test_support::temp_file;

// Exercise the production dispatcher, not just a format parser or worker
// extraction. The proof straddles physical extents with unrelated prefixes.
fn logical_input(format: &str, bytes: &[u8], split: usize, mode: OpenMode) -> (ArchiveInput, Vec<std::path::PathBuf>) {
    let mut paths = Vec::new();
    let mut parts = Vec::new();
    for (index, data) in [&bytes[..split], &bytes[split..]].into_iter().enumerate() {
        let mut carrier = vec![0xa7; 19 + index];
        let start = carrier.len() as u64;
        carrier.extend_from_slice(data);
        let end = carrier.len() as u64;
        carrier.extend_from_slice(b"unrelated tail");
        let path = temp_file("logical_password_opaque", &carrier);
        let mut part = InputPart::range(InputExtent {
            view: None,
            path: path.to_string_lossy().into_owned(), start, end: Some(end),
        });
        part.volume_number = Some(index as u32 + 1);
        part.canonical_name = format!("logical.{:03}", index + 1);
        paths.push(path);
        parts.push(part);
    }
    let mut input = ArchiveInput::file(paths[0].to_string_lossy().into_owned(), format.to_owned(), String::new());
    input.mode = mode;
    input.parts = parts.into_boxed_slice();
    (input, paths)
}

#[test]
fn enc_quick_proof_uses_the_analyzed_carrier_offset_with_known_or_unknown_end() {
    let fixture = include_bytes!("../../../../sunpack_enc/tests/data/algorithm_0.mov");
    let mut carrier = b"unrelated prefix".to_vec();
    let start = carrier.len() as u64;
    carrier.extend_from_slice(fixture);
    let end = carrier.len() as u64;
    carrier.extend_from_slice(b"unrelated suffix");
    let path = temp_file("enc_password_carrier", &carrier);
    let path_string = path.to_string_lossy().into_owned();
    let mut input = ArchiveInput::file(path_string.clone(), "enc".into(), String::new());
    input.mode = OpenMode::FileRange;
    for extent_end in [Some(end), None] {
        input.parts = vec![InputPart::range(InputExtent {
            view: None,
            path: path_string.clone(), start, end: extent_end,
        })].into_boxed_slice();
        let result = verify(&mut context::Preparation::default(), &input,
            &[Arc::from("wrong"), Arc::from("sunpack-test")], &[], None).unwrap();
        assert_eq!(result.status, "match");
        assert_eq!(result.matched_index, Some(1));
        assert_eq!(result.match_evidence, Some("enc_v4_quick_block"));
        assert_eq!(result.final_confirmation_required, Some(false));
    }
    std::fs::remove_file(path).unwrap();
}

fn aes_zip(spanned: bool) -> (Vec<u8>, usize, u64) {
    let salt = [0xa5; 16];
    let mut derived = [0u8; 66];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"logical-secret", &salt, 1000, &mut derived);
    let extra = [1, 0x99, 7, 0, 2, 0, b'A', b'E', 3, 0, 0];
    let mut local = vec![0; 30];
    local[..4].copy_from_slice(b"PK\x03\x04");
    local[6] = 1;
    local[8] = 99;
    local[26] = 1;
    local[28] = extra.len() as u8;
    local.push(b'a');
    local.extend(extra);
    local.extend(salt);
    local.extend_from_slice(&derived[64..]);
    let cd_start = local.len();
    let mut central = vec![0; 46];
    central[..4].copy_from_slice(b"PK\x01\x02");
    central[8] = 1;
    central[10] = 99;
    central[28] = 1;
    central.push(b'a');
    local.extend_from_slice(&central);
    let eocd = local.len() as u64;
    let mut end = [0u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[4] = u8::from(spanned);
    end[6] = u8::from(spanned);
    end[8] = 1;
    end[10] = 1;
    end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(if spanned { 0 } else { cd_start as u32 }).to_le_bytes());
    local.extend(end);
    (local, cd_start, eocd)
}

#[test]
fn zip_fast_proof_uses_analyzed_ranges_and_disk_relative_volumes() {
    for (mode, spanned) in [(OpenMode::FileRange, false), (OpenMode::NativeVolumes, false),
        (OpenMode::SfxWithVolumes, false), (OpenMode::NativeVolumes, true)] {
        let (bytes, central_start, eocd) = aes_zip(spanned);
        let (mut input, paths) = logical_input("zip", &bytes, if spanned { central_start } else { 50 }, mode);
        input.analysis.zip_spanned = spanned;
        input.analysis.zip_eocd_offset = Some(eocd);
        {
            let mut preparation = context::Preparation::default();
            let passwords = [Arc::from("wrong"), Arc::from("logical-secret"), Arc::from("logical-secret")];
            let result = verify(&mut preparation, &input, &passwords, &[], None).unwrap();
            assert_eq!(result.status, "match");
            assert_eq!(result.matched_indices, [1, 2]);
            assert_eq!(result.attempts, 3);
            assert_eq!(result.match_evidence, Some("winzip_aes_password_verifier"));
            assert!(result.final_confirmation_required.unwrap_or(true));
        }
        for path in paths { std::fs::remove_file(path).unwrap(); }
    }
}

#[test]
fn zip_local_proof_precedes_unavailable_tail_and_walks_only_known_plain_sizes() {
    let (mut encrypted, central, _) = aes_zip(false);
    encrypted.truncate(central); // No central directory or EOCD exists.
    let mut plain = vec![0u8; 30];
    plain[..4].copy_from_slice(b"PK\x03\x04");
    plain[18] = 5;
    plain[26] = 1;
    plain.push(b'p');
    plain.extend_from_slice(b"plain");
    for spanned in [false, true] {
        let mut bytes = if spanned { b"PK\x07\x08".to_vec() } else { Vec::new() };
        bytes.extend_from_slice(&plain);
        bytes.extend_from_slice(&encrypted);
        let (mut input, paths) = logical_input("zip", &bytes, bytes.len() - 8,
            if spanned { OpenMode::NativeVolumes } else { OpenMode::FileRange });
        input.analysis.zip_spanned = spanned;
        input.analysis.zip_eocd_offset = Some(1_000_000); // Must not be read.
        {
            let mut preparation = context::Preparation::default();
            let result = verify(&mut preparation, &input,
                &[Arc::from("wrong"), Arc::from("logical-secret"), Arc::from("logical-secret")], &[], None).unwrap();
            assert_eq!(result.match_evidence, Some("winzip_aes_password_verifier"));
            assert_eq!(result.matched_indices, [1, 2]);
            assert!(result.final_confirmation_required.unwrap_or(true));
        }
        for path in paths { std::fs::remove_file(path).unwrap(); }
    }
}

#[test]
fn certain_zip_directory_supplies_proof_after_descriptor_sized_plain_head() {
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    for spanned in [false, true] {
        let mut head = vec![0u8; 31];
        head[..4].copy_from_slice(b"PK\x03\x04");
        head[6] = 8;
        head[26] = 1;
        head[30] = b'p';
        head.extend_from_slice(b"PK\x07\x08");
        head.extend_from_slice(&[0u8; 12]);
        let (mut tail, central, eocd) = aes_zip(false);
        if spanned {
            tail[central + 34..central + 36].copy_from_slice(&1u16.to_le_bytes());
            tail[eocd as usize + 4] = 1;
            tail[eocd as usize + 6] = 1;
        } else {
            tail[central + 42..central + 46].copy_from_slice(&(head.len() as u32).to_le_bytes());
            tail[eocd as usize + 16..eocd as usize + 20]
                .copy_from_slice(&((head.len() + central) as u32).to_le_bytes());
        }
        let paths = [temp_file("zip_cd_head", &head), temp_file("zip_cd_right", &tail)];
        let sources: Vec<_> = paths.iter().map(|path| InputExtent { view: None, path: path.to_string_lossy().into_owned(),
            start: 0, end: Some(std::fs::metadata(path).unwrap().len()) }).collect();
        let plan = Arc::new(VolumeAttemptPlan {
            sources: sources.clone().into_boxed_slice(),
            layouts: vec![VolumeLayout { minimum_slots: 0, slots: vec![
                VolumeSlot { number: 1, canonical_name: "x.001".into(), domain: 0 },
                VolumeSlot { number: 2, canonical_name: "x.002".into(), domain: 1 },
            ].into_boxed_slice() }].into_boxed_slice(),
            domains: vec![VolumeDomain { choices: Arc::new(vec![0]) }, VolumeDomain { choices: Arc::new(vec![1]) }].into_boxed_slice(),
            head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
        });
        {
            let mut preparation = context::Preparation::default();
            let result = zip::zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
                &[Arc::from("wrong"), Arc::from("logical-secret")], spanned, None, &[]).unwrap();
            assert_eq!(result.status, "match", "spanned={spanned}: {}", result.message);
            assert_eq!(result.matched_indices, [1]);
            assert_eq!(result.match_evidence, Some("winzip_aes_password_verifier"));
        }
        for path in paths { std::fs::remove_file(path).unwrap(); }
    }
}
