use super::{encode_worker_frame, NativeWorkerFrameDecoder};
use serde_json::json;

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
