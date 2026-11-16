use super::*;
use std::sync::Mutex;

#[test]
fn invalid_window_reports_filter_and_icon_failures_without_stopping_tray() {
    let errors = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&errors);
    let context = Context {
        enabled: Arc::new(AtomicBool::new(true)),
        cwd: PathBuf::new(), chinese: Arc::new(AtomicBool::new(false)),
        notify: Box::new(|_| {}),
        report_error: Box::new(move |message, _| recorded.lock().unwrap().push(message)),
        taskbar_created: WM_USER + 21, icon_registered: Cell::new(false),
    };
    context.allow_taskbar_message(null_mut());
    assert_eq!(*errors.lock().unwrap(), [None]);
    errors.lock().unwrap().clear();
    // Explorer can accept invalid HWND and even malformed icon data.
    // Inject failure only at the API boundary; exercise the real install
    // fallback/reporting logic deterministically without changing production.
    struct Reset;
    impl Drop for Reset { fn drop(&mut self) { ICON_UPDATE_FAILURE.set(false); } }
    let _reset = Reset;
    ICON_UPDATE_FAILURE.set(true);
    context.install_icon(null_mut(), None);
    assert!(!context.icon_registered.get());
    assert_eq!(*errors.lock().unwrap(), [None]);
    errors.lock().unwrap().clear();
    context.install_icon(null_mut(), Some(context.taskbar_created));
    assert!(!context.icon_registered.get());
    assert_eq!(*errors.lock().unwrap(), [Some(context.taskbar_created); 2]);
    // Display refresh returns its error to the existing window callback.
    assert!(context.update_icon(null_mut(), false).is_err());
}
