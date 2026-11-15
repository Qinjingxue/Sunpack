use super::*;

#[test]
fn history_expiration_trims_overlapping_runs_and_reopens_the_surviving_run() {
    let root = gui_contract::Directory::new("history_overlap");
    let path = root.0.join("events.json");
    let mut store = Store::open(path).unwrap();
    let row = json!({"event":"done","path":"archive.zip"});
    for ts in [1000, 2000, 1500] {
        store.append(&HistoryRecord::new(&row, ts)).unwrap();
    }
    assert_eq!(store.expire(999).unwrap(), Some(1000));
    assert_eq!(store.expire(1500).unwrap(), Some(2000));
    store.publish().unwrap();

    store.append(&HistoryRecord::new(&row, 3000)).unwrap();
    let [run] = store.manifest.runs.as_slice() else {
        panic!("expected one surviving run");
    };
    assert_eq!((run.head, run.first, run.last, run.count), (1, 2000, 3000, 3));
    assert_eq!(store.expire(3000).unwrap(), None);
    store.publish().unwrap();
    store.append(&HistoryRecord::new(&row, 4000)).unwrap();
    assert_eq!(store.expire(3000).unwrap(), Some(4000));
}

#[test]
fn archive_diagnostics_do_not_expand_or_change_shared_recovery_receipts() {
    let input = crate::io::archive_state::ArchiveInput::file("C:/input.zip".into(), "zip".into(), "input.zip".into());
    let checkpoint = json!({"schema_version":1,"carrier":"C:/input.zip","input":input,
        "sources":[],"output":"C:/output","container":"C:/output","files":1,"bytes":1,
        "encrypted":false,"discovery_source":"embedded"});
    let mut expected = None;
    for count in [1, 1024] {
        let failure: crate::pipeline::Failure = serde_json::from_value(json!({
            "kind":"damaged","message":"CRC error","evidence":{"stage":"item_extract"},
            "recovery":{"inputs":vec![checkpoint.clone();count],"output":"C:/output",
                "input_count":count,"had_checkpoints":true,"retry_output":true}
        })).unwrap();
        let project = |budget: &mut usize, truncated: &mut bool|
            diagnostic::value(&DiagnosticFailure(&failure), budget, truncated);
        let output = event_value_with(json!({"event":"archive_failure_evidence","path":"C:/input.zip"}),
            Some(("failure", &project))).unwrap();
        assert_eq!(output["failure"]["kind"], "damaged");
        assert_eq!(output["failure"]["evidence"]["stage"], "item_extract");
        assert!(output["failure"].get("recovery").is_none());
        if let Some(expected) = &expected { assert_eq!(&output, expected); }
        else { expected = Some(output); }
        // Ordinary failure serialization still owns the complete durable
        // contract. Only the per-archive diagnostic view omits the group.
        assert_eq!(serde_json::to_value(&failure).unwrap()["recovery"]["inputs"].as_array().unwrap().len(), count);
    }
}

#[test]
fn diagnostic_budget_keeps_catalog_location_and_failure_classification() {
    let rebuilt = event_value(json!({"event":"catalog_rebuilt", "root":"C:/downloads",
        "reason":"incremental_failed", "errors":vec!["access denied".repeat(300); 64],
        "zzz":"after exhausted diagnostics"})).unwrap();
    assert_eq!(rebuilt["root"], "C:/downloads");
    assert_eq!(rebuilt["reason"], "incremental_failed");
    assert_eq!(rebuilt["truncated"], true);
    assert!(rebuilt.get("").is_none());
    assert!(rebuilt.get("zzz").is_none());
    assert!(serde_json::to_vec(&rebuilt).unwrap().len() < DIAGNOSTIC_TEXT_BYTES + 256);

    let failed = event_value(json!({"event":"failed_terminal", "path":"C:/archive.zip",
        "error_kind":"damaged", "error":"failure details".repeat(1000), "zzz":1})).unwrap();
    assert_eq!(failed["path"], "C:/archive.zip");
    assert_eq!(failed["error_kind"], "damaged");
    assert!(failed["error"].as_str().unwrap().len() < DIAGNOSTIC_TEXT_BYTES);
    assert_eq!(failed["truncated"], true);
    assert!(failed.get("").is_none());
    assert!(failed.get("zzz").is_none());
}

// Hold a writer snapshot across member retirement and completion. Existing
// disk tests cannot force this overlap; this checks snapshot isolation and
// release of both group generations without threads or disk I/O.
#[test]
fn queued_groups_survive_live_mutation_and_release_after_completion() {
    let mut projection = Projection::default();
    let path = "C:/nested.fake";
    let member = "C:/opaque.002";
    projection.apply(
        &mut json!({"event":"pipeline_sources_claimed","owner":"run",
        "groups":[{"path":path,"members":[path,member]}]}),
    );
    projection.apply(&mut json!({"event":"suspended_missing_volume",
        "path":path,"owner":"run","ts":1}));
    let old = projection
        .updates(false)
        .0
        .pop()
        .unwrap()
        .1
        .unwrap()
        .1
        .unwrap();
    let old_lifetime = Arc::downgrade(&old);

    projection.apply(&mut json!({"event":"candidate_departed","path":member}));
    let current = projection
        .updates(false)
        .0
        .pop()
        .unwrap()
        .1
        .unwrap()
        .1
        .unwrap();
    let current_lifetime = Arc::downgrade(&current);
    assert_eq!(old["members"], json!([path, member]));
    assert_eq!(current["members"], json!([path]));

    let mut row = json!({"event":"done","path":path,"owner":"run","ts":2});
    assert!(projection.apply(&mut row));
    assert_eq!(row["group"], *current);
    assert!(projection.tasks.is_empty());
    projection.apply(&mut json!({"event":"pipeline_sources_released",
        "owner":"run","path":path}));
    assert!(projection.aliases.is_empty() && projection.retiring.is_empty());
    drop(old);
    drop(current);
    assert!(old_lifetime.upgrade().is_none());
    assert!(current_lifetime.upgrade().is_none());
}

#[test]
fn completed_families_leave_no_resident_history_or_aliases() {
    // Disk/GUI checks cannot see producer references. Removing this test
    // loses detection of retained completed families; no disk I/O is needed.
    let mut projection = Projection::default();
    for index in 0..2000 {
        let path = format!("C:/carrier-{index}.fake");
        let sibling = format!("C:/opaque-{index}.002");
        let mut claim = json!({"event":"pipeline_sources_claimed","owner":index.to_string(),
            "processing":true,"ts":1,"groups":[{"path":path,"members":[path,sibling]}]});
        projection.apply(&mut claim);
        let mut completion =
            json!({"event":"done","path":sibling,"owner":index.to_string(),"ts":2});
        assert!(projection.apply(&mut completion));
        assert_eq!(completion["group"]["members"].as_array().unwrap().len(), 2);
        assert!(projection.tasks.is_empty());
        assert!(!projection
            .apply(&mut json!({"event":"done","path":path,"owner":index.to_string(),"ts":2})));
        projection.apply(&mut json!({"event":"pipeline_sources_released","owner":index.to_string(),"path":path}));
        assert!(
            projection.aliases.is_empty()
                && projection.retiring.is_empty()
                && projection.owner_tasks.is_empty()
        );
    }
    let mut waiting =
        json!({"event":"suspended_missing_volume","path":"C:/abandoned.002","ts":1});
    projection.apply(&mut waiting);
    let id = projection.tasks.keys().next().unwrap().clone();
    projection.expire_live(vec![id.into()], 2_000_000);
    assert!(projection.tasks.is_empty() && projection.aliases.is_empty());
}
