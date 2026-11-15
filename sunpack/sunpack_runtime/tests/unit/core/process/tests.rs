use super::*;

#[test]
fn foreground_priority_survives_completion_until_idle_maintenance() {
    // Covers retained CLI QoS, overlapping requests, and config reload with
    // one pure policy scenario; no global priority changes or timed waits.
    let mut policy = PriorityPolicy {
        configured: ProcessMode::Background,
        foreground: 0,
        foreground_override: false,
    };
    assert_eq!(policy.effective(), ProcessMode::Background);
    policy.enter_foreground();
    policy.enter_foreground();
    assert_eq!(policy.effective(), ProcessMode::High);
    policy.leave_foreground();
    policy.expire_foreground_override();
    assert_eq!(policy.effective(), ProcessMode::High);
    policy.configured = ProcessMode::Normal;
    assert_eq!(policy.effective(), ProcessMode::High);
    policy.leave_foreground();
    assert_eq!(policy.foreground, 0);
    assert_eq!(policy.effective(), ProcessMode::High);
    // A request arriving before maintenance must protect the same override.
    policy.enter_foreground();
    policy.expire_foreground_override();
    assert_eq!(policy.effective(), ProcessMode::High);
    policy.leave_foreground();
    policy.expire_foreground_override();
    assert_eq!(policy.effective(), ProcessMode::Normal);
    policy.configured = ProcessMode::Background;
    assert_eq!(policy.effective(), ProcessMode::Background);
    // The no-Watch path can expire immediately after the final release.
    policy.enter_foreground();
    policy.leave_foreground();
    policy.expire_foreground_override();
    policy.expire_foreground_override();
    assert_eq!(policy.effective(), ProcessMode::Background);
}
