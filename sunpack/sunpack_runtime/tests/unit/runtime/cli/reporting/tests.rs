use super::*;
use crate::pipeline::{Cancellation, Origin, Scheduler};
use std::sync::mpsc;

#[test]
fn replan_discards_pending_old_attempt_but_keeps_registration_and_new_progress() {
    let reports = Reports::default();
    reports.notify(Event::Queued { id: 7, parent: None, path: "old.002".into(), segment: None });
    reports.notify(Event::Working { id: 7 });
    reports.notify(Event::Progress { id: 7, completed_bytes: 9, total_bytes: 10 });
    reports.notify(Event::ResourceWait { id: 7, path: "old.002".into(), state: Default::default() });
    reports.notify(Event::Replanned { id: 7, path: "new.001".into() });
    reports.notify(Event::Working { id: 7 });
    reports.notify(Event::Progress { id: 7, completed_bytes: 1, total_bytes: 10 });
    let events = reports.take_events();
    assert_eq!(events.len(), 4);
    assert!(matches!(&events[0], Event::Queued { .. }));
    assert!(matches!(&events[1], Event::Replanned { path, .. } if path == std::path::Path::new("new.001")));
    assert!(matches!(&events[2], Event::Working { .. }));
    assert!(matches!(&events[3], Event::Progress { completed_bytes: 1, .. }));
}

#[test]
fn shared_progress_service_coalesces_events_and_wakes_without_a_private_thread() {
    let reports = Arc::new(Reports::default());
    reports.notify(Event::Working { id: 7 });
    reports.notify(Event::Working { id: 7 });
    let scheduler = Scheduler::new();
    let cancel = Cancellation::new();
    let (sent, received) = mpsc::channel();
    let service = Arc::clone(&reports);
    let output = scheduler.submit(1, Origin::Foreground, &cancel, move |_| Box::pin(async move {
        service.serve_async(|| { for event in service.take_events() { sent.send(event).unwrap(); } }).await;
    }));
    assert!(matches!(received.recv().unwrap(), Event::Working { id: 7 }));
    reports.close();
    output.join().unwrap();
    assert!(received.try_recv().is_err());
}
