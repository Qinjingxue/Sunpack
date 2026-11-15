use super::*;

#[test]
fn prompt_line_continues_across_more_than_one_frame_limit() {
    let mut input = PromptInput::default();
    let chunk = vec![b'x'; 4096];
    for _ in 0..(MAX_FIELD / chunk.len()) {
        input.push(chunk.clone()).unwrap();
        assert!(input.line().is_none());
    }
    input.push(b"tail\r".to_vec()).unwrap();
    let line = input.line().unwrap();
    assert_eq!(line.len(), MAX_FIELD + 5);
    assert!(line.ends_with("tail\r"));
    input.push(b"\nnext\n".to_vec()).unwrap();
    assert_eq!(input.line().as_deref(), Some("next\n"));
}

#[test]
fn output_frames_keep_utf8_boundaries_and_binary_payloads() {
    // Ordinary short-output tests never cross the protocol limit. Check
    // every possible split inside a UTF-8 scalar with one reusable buffer.
    let limit = 64 * 1024;
    let mut bytes = Vec::with_capacity(limit + 4);
    for scalar in ["é", "中", "😀"] {
        for split in 1..scalar.len() {
            bytes.clear();
            bytes.resize(limit - split, b'a');
            bytes.extend_from_slice(scalar.as_bytes());
            bytes.push(b'\n');
            for kind in [1, 2] {
                let end = frame_chunk_len(kind, &bytes);
                assert_eq!(end, limit - split);
                let (first, rest) = bytes.split_at(end);
                assert!(std::str::from_utf8(first).is_ok());
                assert_eq!(std::str::from_utf8(rest).unwrap(), format!("{scalar}\n"));
                assert_eq!(frame_chunk_len(kind, rest), rest.len());
            }
            // Control payloads are binary, never interpreted as text.
            assert_eq!(frame_chunk_len(0, &bytes), bytes.len());
        }
    }
    bytes.fill(0x80);
    assert_eq!(frame_chunk_len(1, &bytes), limit);
    assert_eq!(frame_chunk_len(2, &[]), 0);
    assert_eq!(frame_chunk_len(0, &(-1_i32).to_be_bytes()), 4);
    assert_eq!(frame_chunk_len(3, &[]), 0);
}
