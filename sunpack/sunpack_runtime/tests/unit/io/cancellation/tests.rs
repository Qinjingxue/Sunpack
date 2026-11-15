use super::*;
use crate::io::{iocp, ScanBatch};
use std::sync::mpsc;

#[test]
fn cancellation_marker_preserves_io_errors_and_stops_read_retry_helpers() {
    use std::io::Read;

    // A kind-only test misses both false-positive Interrupted errors and
    // the standard Read helpers silently retrying genuine cancellation.
    let cancel = Cancellation::new();
    cancel.cancel();
    for error in [
        cancel.check().unwrap_err(),
        cancel.check_io().unwrap_err(),
        cancel.run(Cancellation::check_current_io).unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(is_cancellation(&error));
    }
    for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
        assert!(!is_cancellation(&io::Error::new(kind, "native operation cancelled")));
    }
    struct CancelledRead<'a>(&'a Cancellation, usize);
    impl Read for CancelledRead<'_> {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.1 += 1;
            assert_eq!(self.1, 1, "Read retried a cancelled operation");
            self.0.check_io()?;
            Ok(0)
        }
    }
    let error = CancelledRead(&cancel, 0).read_exact(&mut [0; 1]).unwrap_err();
    assert!(is_cancellation(&error));
    let error = CancelledRead(&cancel, 0).read_to_end(&mut Vec::new()).unwrap_err();
    assert!(is_cancellation(&error));
}

#[test]
fn cancellation_drains_live_scan_and_preserves_other_requests() {
    // Password-only cancellation cannot find abandoned OVERLAPPED buffers,
    // lost completion-port wakes, or a flag leaking into the next scan.
    // One bounded IO window plus a complete surviving scan covers all three.
    let path = std::env::temp_dir().join(format!(
        "sunpack_cancel_scan_{}_{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let size = 8 * 1024 * 1024;
    std::fs::write(&path, vec![0x5a; size]).unwrap();
    let state = Arc::new(State::default());
    let signal = Arc::clone(&state);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (released_tx, released_rx) = mpsc::sync_channel(1);
    let released_rx = Mutex::new(released_rx);
    let first = AtomicBool::new(true);
    let canceller = std::thread::spawn(move || {
        entered_rx.recv().unwrap();
        signal.cancel();
        released_tx.send(()).unwrap();
    });
    let mut matched = 0;
    let result = Cancellation(Some(Arc::clone(&state))).run(|| {
        iocp::scan_file(
            &path,
            size as u64,
            64 * 1024,
            2,
            1,
            0,
            |data, _, _| {
                if first.swap(false, Ordering::Relaxed) {
                    entered_tx.send(()).unwrap();
                    released_rx.lock().unwrap().recv().unwrap();
                }
                ScanBatch {
                    results: data.len(),
                    discarded_results: 0,
                }
            },
            |count| {
                matched += count;
                Ok(())
            },
        )
    });
    canceller.join().unwrap();
    assert!(result.is_err());
    assert!(matched < size);
    assert!(state.wakes.lock().unwrap().callbacks.is_empty());
    assert!(!Cancellation::current().cancelled());
    let mut surviving = 0;
    iocp::scan_file(
        &path,
        size as u64,
        64 * 1024,
        2,
        1,
        0,
        |data, _, _| ScanBatch {
            results: data.len(),
            discarded_results: 0,
        },
        |count| {
            surviving += count;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(surviving, size);
    std::fs::remove_file(path).unwrap();
}
