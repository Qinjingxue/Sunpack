use super::*;

#[test]
fn notification_buffers_recover_after_bursts_and_release_the_directory() {
    for capacity in [4096, 64_000] {
        let root = std::env::temp_dir().join(format!(
            "sunpack-notification-buffer-{}-{capacity}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let changes = NativeConfigChanges::observe(root.clone(), true, 0x17f, capacity).unwrap();
        assert_eq!(changes.request.lock().unwrap().as_ref().unwrap().buffer.len() * 4, capacity);
        // An armed request completes first; further events accumulate while
        // its consumer is paused. Exceed both supported buffer capacities.
        for index in 0..1000 {
            std::fs::write(root.join(format!("{index:04}-{}", "x".repeat(100))), []).unwrap();
        }
        let mut overflow = false;
        for index in 0..3 {
            std::fs::write(root.join(format!("wake-{index}")), []).unwrap();
            if changes.read().unwrap().is_none() {
                overflow = true;
                break;
            }
        }
        assert!(overflow, "burst must exercise the recovery notification");
        std::fs::write(root.join("after-overflow"), []).unwrap();
        loop {
            if changes.read().unwrap().is_some_and(|names| names.iter().any(|name| name.name == "after-overflow" && name.action == 1)) {
                break;
            }
        }
        changes.close();
        std::fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn completion_event_is_manual_reset_while_stop_event_is_auto_reset() {
    let completion = event(true).unwrap();
    let stopped = event(false).unwrap();
    let completion_handle = [completion.as_raw_handle()];
    let stopped_handle = [stopped.as_raw_handle()];

    unsafe {
        assert_ne!(SetEvent(completion.as_raw_handle()), 0);
        assert_eq!(
            WaitForMultipleObjects(1, completion_handle.as_ptr(), 0, 0),
            0
        );
        assert_eq!(
            WaitForMultipleObjects(1, completion_handle.as_ptr(), 0, 0),
            0
        );

        assert_ne!(SetEvent(stopped.as_raw_handle()), 0);
        assert_eq!(WaitForMultipleObjects(1, stopped_handle.as_ptr(), 0, 0), 0);
        assert_eq!(
            WaitForMultipleObjects(1, stopped_handle.as_ptr(), 0, 0),
            258
        );
    }
}
