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
