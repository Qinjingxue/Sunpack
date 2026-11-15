use super::*;

fn image(pe_offset: usize, pe64: bool) -> Vec<u8> {
    let optional_size = if pe64 { 240 } else { 224 };
    let optional = pe_offset + 24;
    let section = optional + optional_size;
    let headers_size = (section + 40 + 511) & !511;
    let mut bytes = vec![0; headers_size + 32];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(PE_SIGNATURE);
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x14cu16.to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&1u16.to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22]
        .copy_from_slice(&(optional_size as u16).to_le_bytes());
    bytes[pe_offset + 22..pe_offset + 24]
        .copy_from_slice(&IMAGE_FILE_EXECUTABLE_IMAGE.to_le_bytes());
    bytes[optional..optional + 2]
        .copy_from_slice(&(if pe64 { 0x20bu16 } else { 0x10b }).to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&(headers_size as u32).to_le_bytes());
    bytes[section + 16..section + 20].copy_from_slice(&32u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&(headers_size as u32).to_le_bytes());
    bytes
}

#[test]
fn prefix_confirms_pe32_and_pe64_without_io() {
    for pe64 in [false, true] {
        let bytes = image(0x80, pe64);
        let probe = probe_pe_prefix(&bytes[..512], bytes.len() as u64);
        assert_eq!(probe.state(), PeState::Confirmed);
        assert_eq!(probe.image_end(), Some(bytes.len() as u64));
    }
}

#[test]
fn missing_buffer_and_missing_file_structure_are_distinct() {
    for pe_offset in [0x180, 0x800] {
        let bytes = image(pe_offset, false);
        assert_eq!(
            probe_pe_prefix(&bytes[..512], bytes.len() as u64),
            PeProbe::NeedMore
        );
        assert_eq!(probe_pe_prefix(&bytes[..512], 512), PeProbe::NotPe);
        let path = crate::test_support::temp_file("pe_delayed_header", &bytes);
        assert_eq!(
            inspect_pe_image_native(path.to_str().unwrap()).unwrap(),
            probe_pe_prefix(&bytes, bytes.len() as u64)
        );
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn malformed_headers_and_raw_ranges_do_not_confirm_pe() {
    let original = image(0x80, false);
    for (offset, replacement) in [
        (0x3c, vec![0xff; 4]),
        (0x80, vec![0]),
        (0x84, vec![0; 2]),
        (0x86, vec![0; 2]),
        (0x94, vec![0; 2]),
        (0x98, vec![0; 2]),
        (0xd4, vec![0; 4]),
        (0xf4, vec![0xff; 4]),
        (0x188, vec![0xff; 4]),
        (0x18c, vec![0; 4]),
    ] {
        let mut bytes = original.clone();
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        assert_eq!(
            probe_pe_prefix(&bytes, bytes.len() as u64),
            PeProbe::NotPe,
            "offset {offset:x}"
        );
    }
    assert_eq!(probe_pe_prefix(b"MZ", 2), PeProbe::NotPe);
    assert_eq!(probe_pe_prefix(b"ordinary", 8), PeProbe::NotPe);
}

#[test]
fn full_detector_reads_only_header_regions_even_with_a_distant_pe_header() {
    let bytes = image(0x800, true);
    let mut ranges = Vec::new();
    let result =
        inspect_pe_headers::<std::convert::Infallible>(bytes.len() as u64, |offset, len| {
            ranges.push((offset, len));
            Ok(Some(Cow::Borrowed(
                &bytes[offset as usize..offset as usize + len],
            )))
        })
        .unwrap();
    assert_eq!(result.image_end(), Some(bytes.len() as u64));
    assert!(ranges.iter().all(|(_, len)| *len <= 240));
    assert!(ranges
        .iter()
        .all(|(offset, len)| *offset != 0 || *len <= 64));
}

#[test]
fn filesystem_probe_keeps_pe_facts_without_sfx_or_extra_reads() {
    for offset in [0x80, 0x800] {
        let bytes = image(offset, false);
        let anchor = crate::analysis_native::volume_anchor::probe_volume_anchor_from_head(
            "no_such_file.jpg",
            bytes.len() as u64,
            &bytes,
        );
        let anchor = anchor.anchor().unwrap();
        assert_eq!(anchor.bytes_read, 512);
        assert!(!anchor.sfx);
        assert!(anchor.format.is_empty());
        assert_eq!(
            anchor.pe_state,
            if offset == 0x80 {
                PeState::Confirmed
            } else {
                PeState::Candidate
            }
        );
        assert_eq!(
            anchor.pe_image_end,
            (offset == 0x80).then_some(bytes.len() as u64)
        );
    }
}

#[test]
fn invalid_section_counts_and_non_executable_images_stop_at_coff() {
    for pe64 in [false, true] {
        for (section_count, characteristics) in [
            (0, IMAGE_FILE_EXECUTABLE_IMAGE),
            (97, IMAGE_FILE_EXECUTABLE_IMAGE),
            (u16::MAX, IMAGE_FILE_EXECUTABLE_IMAGE),
            (1, 0),
            (1, 0x2000), // DLL without EXECUTABLE_IMAGE is not confirmed.
        ] {
            let pe_offset = 0x800;
            let mut bytes = image(pe_offset, pe64);
            bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&section_count.to_le_bytes());
            bytes[pe_offset + 22..pe_offset + 24]
                .copy_from_slice(&characteristics.to_le_bytes());
            // Claim enough physical space even for a 65535-section table.
            // The parser must reject COFF before requesting more bytes.
            let result = inspect_pe_headers::<std::convert::Infallible>(
                u32::MAX as u64,
                |offset, len| {
                    assert!(offset + len as u64 <= (pe_offset + 24) as u64);
                    Ok(Some(Cow::Borrowed(
                        &bytes[offset as usize..offset as usize + len],
                    )))
                },
            )
            .unwrap();
            assert_eq!(result, PeProbe::NotPe);
            let path = crate::test_support::temp_file("invalid_pe_coff", &bytes);
            assert_eq!(
                inspect_pe_image_native(path.to_str().unwrap()).unwrap(),
                PeProbe::NotPe
            );
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn ninety_six_sections_and_executable_dlls_remain_valid() {
    for pe64 in [false, true] {
        let pe_offset = 0x800;
        let optional = pe_offset + 24;
        let section = optional + if pe64 { 240 } else { 224 };
        let headers_size = (section + 96 * SECTION_HEADER_SIZE + 511) & !511;
        let mut bytes = image(pe_offset, pe64);
        bytes.resize(headers_size + 32, 0);
        bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&96u16.to_le_bytes());
        bytes[pe_offset + 22..pe_offset + 24].copy_from_slice(&0x2002u16.to_le_bytes());
        bytes[optional + 60..optional + 64]
            .copy_from_slice(&(headers_size as u32).to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(headers_size as u32).to_le_bytes());
        assert_eq!(
            probe_pe_prefix(&bytes[..512], bytes.len() as u64),
            PeProbe::NeedMore
        );
        let path = crate::test_support::temp_file("pe_96_section_dll", &bytes);
        assert_eq!(
            inspect_pe_image_native(path.to_str().unwrap())
                .unwrap()
                .image_end(),
            Some(bytes.len() as u64)
        );
        std::fs::remove_file(path).unwrap();
    }
}
