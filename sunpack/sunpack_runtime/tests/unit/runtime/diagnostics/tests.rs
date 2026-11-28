use super::*;
// Exercise the runtime owner's complete lifecycle through the existing
// asynchronous store. Watch-only log tests cannot detect a missing runtime
// owner, dropped events at shutdown, or an accidental live-task projection.
#[test]
fn runtime_events_are_published_and_drained_without_watch_tasks() {
    // The server's logger is process-global. Other Rust tests exercise
    // foreground and Watch events concurrently, so give this owner its
    // own process and keep the exact lifecycle event count assertion.
    const ISOLATED: &str = "SUNPACK_TEST_ISOLATED_RUNTIME_LOG";
    if std::env::var_os(ISOLATED).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::diagnostics::tests::runtime_events_are_published_and_drained_without_watch_tasks"])
            .env(ISOLATED, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(result.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}", String::from_utf8_lossy(&result.stderr));
        return;
    }
    let folder = std::env::temp_dir().join(format!("sunpack-runtime-log-{}-{}", std::process::id(), crate::io::display_store::utc_us()));
    std::fs::create_dir_all(&folder).unwrap();
    let path = folder.join("runtime-test.state.events.json");
    let watch = Arc::new(super::super::watch::Watch::new(Arc::new(|| {})));
    let log = Log::open(path.clone(), 7, &watch).unwrap();
    qos(ProcessMode::High, || 0, &Ok(()), &Ok(false));
    event("watch_control", || json!({"action":"status","result":{"running":false}}));
    // Owner calls, not CLI dispatch: these transitions also cover non-CLI
    // callers and must each produce their own ignored lifecycle event.
    assert_eq!(watch.stop().unwrap()["stopped"], false);
    assert_eq!(crate::pipeline::block_on(watch.reload_async()).unwrap()["running"], false);
    log.finish("idle");
    let manifest: crate::io::display_store::Manifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(manifest.runs.iter().map(|run| run.count).sum::<u64>(), 6);
    assert!(manifest.live.is_none());
    drop(log);
    std::fs::remove_dir_all(folder).unwrap();
}
