use super::*;
use crate::scan::worker_wire::encode_worker_frame;

fn manifest_frame(job: &str) -> WorkerFrame {
    let sentinel = "__binary_magic__";
    let mut bytes = encode_worker_frame(&json!({
        "type": "manifest_chunk", "job_id": job, "seq": 0,
        "rows": [[format!("{job}-renamed.txt"), 3, 1, 123, sentinel]],
    }))
    .unwrap();
    let body = bytes
        .windows(sentinel.len())
        .position(|part| part == sentinel.as_bytes())
        .unwrap();
    bytes.splice(
        body - 5..body + sentinel.len(),
        [8, 3, 0, 0, 0, b'a', b'b', b'c'],
    );
    let size = (bytes.len() - 8) as u32;
    bytes[4..8].copy_from_slice(&size.to_le_bytes());
    parse_worker_transport_event(&bytes).unwrap()
}

fn result_frame(job: &str, files: u64) -> WorkerFrame {
    parse_worker_transport_event(
        &encode_worker_frame(&json!({
            "type": "result", "job_id": job,
            "verified_manifest": {
                "file_count": files, "complete": true, "total_size": 3,
                "chunk_count": 1,
            },
        }))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn worker_chunks_move_into_their_own_result_only() {
    let mut first = NativeWorkerResultAccumulator::new("first".into());
    let mut second = NativeWorkerResultAccumulator::new("second".into());
    assert!(second.accept(manifest_frame("second")).unwrap().is_none());
    assert!(first.accept(manifest_frame("first")).unwrap().is_none());
    let Err(duplicate) = first.accept(manifest_frame("first")) else {
        panic!("duplicate chunk")
    };
    assert!(duplicate.to_string().contains("sequence"));
    let Err(mismatch) = first.accept(result_frame("first", 2)) else {
        panic!("bad count")
    };
    assert!(mismatch.to_string().contains("count mismatch"));
    for (job, accumulator) in [("first", first), ("second", second)] {
        let manifest = { accumulator }
            .accept(result_frame(job, 1))
            .unwrap()
            .unwrap()
            .manifest
            .unwrap();
        assert!(manifest.complete());
        let row = &manifest.records().unwrap()[0];
        assert_eq!(row.path, format!("{job}-renamed.txt"));
        assert_eq!(&*row.magic, b"abc");
        assert_eq!(row.mtime_ns, Some(123));
    }
}

#[test]
fn malformed_job_body_does_not_break_frame_routing() {
    let malformed = encode_worker_frame(&json!({
        "type": "result", "job_id": "malformed",
        "verified_manifest": {"file_count": 0},
    }))
    .unwrap();
    let event = parse_worker_transport_event(&malformed).unwrap();
    assert_eq!(event.summary["type"], "protocol_error");
    assert_eq!(event.summary["job_id"], "malformed");
    assert!(parse_worker_transport_event(b"broken stream").is_err());
}
