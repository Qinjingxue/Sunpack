use super::*;

fn stored_zip_with_eocd_offset(central_offset: u32) -> Vec<u8> {
    let name = b"a.txt";
    let payload = b"hello";
    let mut data = Vec::new();
    data.extend_from_slice(ZIP_LOCAL);
    data.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(name);
    data.extend_from_slice(payload);
    let central_start = data.len() as u32;
    data.extend_from_slice(ZIP_CENTRAL);
    data.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(name);
    let central_size = data.len() as u32 - central_start;
    data.extend_from_slice(ZIP_EOCD);
    data.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    data.extend_from_slice(&central_size.to_le_bytes());
    data.extend_from_slice(&central_offset.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data
}

fn status_of(result: Result<ZipPasswordContext, PreparedStatus>) -> &'static str {
    match result {
        Err(PreparedStatus::Status(status, _)) => status,
        Err(PreparedStatus::ReadFault(_)) => "read_fault",
        Ok(_) => "prepared",
    }
}

#[test]
fn zip64_directory_location_defers_instead_of_reporting_missing_volume() {
    let data = stored_zip_with_eocd_offset(u32::MAX);
    let len = data.len() as u64;
    let result = prepare_zip_stream(&mut std::io::Cursor::new(data), len, None);
    assert_eq!(status_of(result), "unknown_needs_final_verifier");
}

#[test]
fn ordinary_unencrypted_zip_is_still_not_required() {
    let data = stored_zip_with_eocd_offset(40);
    let len = data.len() as u64;
    let result = prepare_zip_stream(&mut std::io::Cursor::new(data), len, None);
    assert_eq!(status_of(result), "not_required");
}

#[test]
fn zip64_password_probe_resolves_disk_relative_entry_and_end_records() {
    use crate::io::reader::ReaderConfig;
    use crate::password::input::VolumeSpec;

    let mut prefix = vec![0; 64 * 1024];
    prefix[..4].copy_from_slice(b"PK\x07\x08");
    let local = &mut prefix[4..];
    local[..4].copy_from_slice(ZIP_LOCAL);
    local[4..6].copy_from_slice(&45u16.to_le_bytes());
    local[6] = 1;
    local[17] = 0x5a;
    local[26] = 1;
    local[30] = b'a';
    local[31..43].fill(0x9b);

    for split in [false, true] {
        let disk_number = if split { 2u32 } else { 0 };
        let central_offset = if split { 0 } else { prefix.len() as u64 };
        let mut tail = vec![0; 46];
        tail[..4].copy_from_slice(ZIP_CENTRAL);
        tail[4..8].copy_from_slice(&[45, 0, 45, 0]);
        tail[8] = 1;
        tail[19] = 0x5a;
        tail[28] = 1;
        tail[30] = 16;
        tail[34..36].copy_from_slice(&u16::MAX.to_le_bytes());
        tail[42..46].copy_from_slice(&u32::MAX.to_le_bytes());
        tail.push(b'a');
        tail.extend([1, 0, 12, 0]);
        tail.extend(4u64.to_le_bytes());
        tail.extend(0u32.to_le_bytes());

        let entries = if split {
            // The first directory entry belongs to the missing middle disk.
            // The following entry points directly into the available anchor.
            let mut missing = tail.clone();
            let field = missing.len() - 4;
            missing[field..].copy_from_slice(&1u32.to_le_bytes());
            missing.extend(tail);
            tail = missing;
            2u64
        } else { 1 };
        let central_size = tail.len() as u64;
        tail.extend(b"PK\x06\x06");
        tail.extend(44u64.to_le_bytes());
        tail.extend([45, 0, 45, 0]);
        tail.extend(disk_number.to_le_bytes());
        tail.extend(disk_number.to_le_bytes());
        tail.extend(entries.to_le_bytes());
        tail.extend(entries.to_le_bytes());
        tail.extend(central_size.to_le_bytes());
        tail.extend(central_offset.to_le_bytes());
        tail.extend(b"PK\x06\x07");
        tail.extend(disk_number.to_le_bytes());
        tail.extend((central_offset + central_size).to_le_bytes());
        tail.extend((disk_number + 1).to_le_bytes());
        let eocd = (prefix.len() + tail.len()) as u64;
        tail.extend(ZIP_EOCD);
        tail.extend([0xff; 16]);
        tail.extend(0u16.to_le_bytes());

        let prepared = if split {
            let volumes = VolumeSet::new(
                [prefix.clone(), tail]
                    .into_iter()
                    .enumerate()
                    .map(|(disk, bytes)| VolumeSpec {
                        reader: ManagedReader::from_bytes(bytes, ReaderConfig::default()),
                        number: if disk == 0 { 1 } else { disk_number + 1 },
                        start: 0,
                        end: None,
                    })
                    .collect(),
            );
            prepare_zip_volume_directory(&volumes, Some(eocd), None)
        } else {
            let mut archive = prefix.clone();
            archive.extend(tail);
            let len = archive.len() as u64;
            prepare_zip_directory_stream(&mut std::io::Cursor::new(archive), len, Some(eocd), None)
        };
        match prepared {
            Ok(ZipPasswordContext::ZipCrypto { header, check_byte, .. }) => {
                assert_eq!(header, [0x9b; 12]);
                assert_eq!(check_byte, 0x5a);
            }
            _ => panic!("ZIP64 did not resolve the encryption header"),
        }
    }
}
