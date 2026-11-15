use super::*;
use crate::io::cancellation::{is_cancellation, Cancellation};
use serde_json::{json, Value};
use std::io::Write;

#[test]
fn framing_keeps_complete_events_across_fragmentation_and_errors() {
    let expected = json!({
        "type": "progress", "job_id": "目录😀\u{0}\r\n\\\"",
        "values": [null, true, false, 0, 255, 256, u64::MAX, i64::MIN, 0.125]
    });
    let frame = encode_worker_frame(&expected).unwrap();
    for offset in 0..=frame.len() {
        let mut decoder = NativeWorkerFrameDecoder::new();
        let mut events = decoder.feed(&frame[..offset]).unwrap();
        let tail = [&frame[offset..], &frame].concat();
        events.extend(decoder.feed(&tail).unwrap());
        decoder.finish().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.into_iter().all(|event| event.summary == expected));
        if offset > 0 && offset < frame.len() {
            decoder.feed(&frame[..offset]).unwrap();
            assert!(decoder
                .finish()
                .unwrap_err()
                .to_string()
                .contains("truncated"));
        }
    }
    let mut decoder = NativeWorkerFrameDecoder::new();
    let tail = [frame.as_slice(), b"broken frame"].concat();
    assert_eq!(decoder.feed(&tail).unwrap()[0].summary, expected);
    assert!(decoder
        .check()
        .unwrap_err()
        .to_string()
        .contains("frame header"));
}

#[test]
fn requests_cross_chunk_boundaries_and_cancel_without_a_partial_job() {
    let value = json!({
        "archive_input": {"ranges": [{"path": "目录😀".repeat(120_000), "start": 1 << 20}]},
        "job_id": "large",
        "password_candidates": ["first", "last"],
    });
    let small = json!({"worker_command": "shutdown"});
    assert_eq!(small_request(&small).unwrap().unwrap(), encode_worker_frame(&small).unwrap());
    assert!(small_request(&value).unwrap().is_none());

    struct Blocks {
        cancel: Option<Cancellation>,
        blocks: Vec<Vec<u8>>,
    }
    impl Write for Blocks {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert!(bytes.len() <= HEADER.len() + REQUEST_CHUNK_BYTES);
            self.blocks.push(bytes.to_vec());
            if let Some(cancel) = self.cancel.take() { cancel.cancel(); }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let cancel = Cancellation::new();
    let mut output = Blocks { cancel: None, blocks: Vec::new() };
    write_request(&mut output, &value, &cancel).unwrap().unwrap();
    assert!(output.blocks.len() > 2);
    let mut payload = Vec::new();
    for (index, block) in output.blocks.iter().enumerate() {
        assert_eq!(&block[..4], b"SPBF");
        let size = u32::from_le_bytes(block[4..8].try_into().unwrap());
        assert_eq!((size & !MORE) as usize, block.len() - HEADER.len());
        assert_eq!(size & MORE != 0, index + 1 < output.blocks.len());
        payload.extend_from_slice(&block[8..]);
    }
    let mut decoded = Decoder::new(&payload);
    assert_eq!(Value::deserialize(&mut decoded).unwrap(), value);
    assert!(decoded.data.is_empty());

    let mut output = Blocks { cancel: Some(cancel.clone()), blocks: Vec::new() };
    let error = write_request(&mut output, &value, &cancel).unwrap().unwrap_err();
    assert!(is_cancellation(&error));
    assert_eq!(output.blocks.len(), 2);
    assert_eq!(output.blocks[1], HEADER);
}
