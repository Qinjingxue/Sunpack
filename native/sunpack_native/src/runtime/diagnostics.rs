//! Runtime events share the asynchronous event store used by Watch.
use std::{io, path::PathBuf, sync::{Arc, Mutex, Weak}, time::{SystemTime, UNIX_EPOCH}};
use serde_json::{json, Value};
use crate::{core::config::ProcessMode, event_log::NativeEventLog};

static CURRENT: Mutex<Weak<Log>> = Mutex::new(Weak::new());

pub(super) struct Log {
    events: NativeEventLog,
    watch: Weak<super::watch::Watch>,
}
impl Log {
    pub(super) fn open(path: PathBuf, days: u64, watch: &Arc<super::watch::Watch>) -> io::Result<Arc<Self>> {
        let log = Arc::new(Self { events: NativeEventLog::new(path, days.min(u32::MAX as u64) as u32, false)?, watch: Arc::downgrade(watch) });
        *CURRENT.lock().unwrap() = Arc::downgrade(&log);
        log.write("host_started", json!({}));
        Ok(log)
    }
    pub(super) fn finish(&self, reason: &str) {
        self.write("host_stopped", json!({"exit_reason": reason}));
        let _ = self.events.flush();
    }

    fn write(&self, name: &str, mut fields: Value) {
        fields["event"] = json!(name);
        fields["host_pid"] = json!(std::process::id());
        fields["watch_generation"] = json!(self.watch.upgrade().map_or(0, |watch| watch.generation()));
        fields["ts"] = json!(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64());
        let _ = self.events.write(fields);
    }
}
pub(super) fn retention(days: u64) {
    let log = CURRENT.lock().unwrap().upgrade();
    if let Some(log) = log { let _ = log.events.configure_retention(days.min(u32::MAX as u64) as u32); }
}
pub(super) fn event(name: &str, fields: impl FnOnce() -> Value) {
    let Some(log) = CURRENT.lock().unwrap().upgrade() else { return; };
    log.write(name, fields());
}
pub(super) fn qos(mode: ProcessMode, worker_pid: impl FnOnce() -> u32, host: &io::Result<()>, worker: &io::Result<bool>) {
    let mode = match mode { ProcessMode::Background => "background", ProcessMode::Normal => "normal", ProcessMode::High => "high" };
    event("qos_changed", || json!({"mode":mode, "worker_pid":worker_pid(), "host_applied":host.is_ok(), "worker_applied":matches!(worker, Ok(true)),
        "host_error":host.as_ref().err().map(ToString::to_string), "worker_error":worker.as_ref().err().map(ToString::to_string)}));
}

#[cfg(test)]
mod tests {
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
        assert_eq!(watch.reload().unwrap()["running"], false);
        log.finish("idle");
        let manifest: crate::io::display_store::Manifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(manifest.runs.iter().map(|run| run.count).sum::<u64>(), 6);
        assert!(manifest.live.is_none());
        drop(log);
        std::fs::remove_dir_all(folder).unwrap();
    }
}
