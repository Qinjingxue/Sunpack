use super::*;

#[test]
fn fixed_request_roundtrip_preserves_journal_query_fields() {
    let file_id = 0x1234u128.to_le_bytes();
    let request = Request {
        opcode: Opcode::ReadChangeReasons,
        request_id: 42,
        previous_usn: 100,
        current_usn: 101,
        file_id,
        file_id_len: 8,
        volume_guid: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
    };
    assert_eq!(
        Request::decode(&request.encode().unwrap()).unwrap(),
        request
    );
}

#[test]
fn fixed_response_roundtrip_preserves_all_fields() {
    let response = Response {
        status: Status::JournalReset,
        request_id: 0x0102_0304_0506_0708,
        win32_error: 0x1112_1314,
        journal_id: 0x2122_2324_2526_2728,
        reasons_all: 0x3132_3334,
        reasons_without_close: 0x4142_4344,
        next_usn: 0x5152_5354_5556_5758,
    };

    assert_eq!(Response::decode(&response.encode()).unwrap(), response);
}
