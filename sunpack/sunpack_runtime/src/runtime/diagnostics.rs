//! Runtime events share the asynchronous event store used by Watch.
use std::{io, path::PathBuf, sync::{Arc, Mutex, Weak}};
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
        // The event queue assigns time under its lock, in publication order.
        let _ = self.events.write(fields);
    }
}
pub(super) fn retention(days: u64) {
    let log = CURRENT.lock().unwrap().upgrade();
    if let Some(log) = log { log.events.configure_retention(days.min(u32::MAX as u64) as u32); }
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
#[path = "../../tests/unit/runtime/diagnostics/tests.rs"]
mod tests;
