use super::*;

#[test]
fn history_expiration_trims_overlapping_runs_and_reopens_the_surviving_run() {
    let root = gui_contract::Directory::new("history_overlap");
    let path = root.0.join("events.json");
    let mut store = Store::open(path).unwrap();
    let row = json!({"event":"done","path":"archive.zip"});
    for ts in [1000, 2000, 1500] {
        store.append(&HistoryRecord::new(&row, ts, &row).unwrap()).unwrap();
    }
    assert_eq!(store.expire(999).unwrap(), Some(1000));
    assert_eq!(store.expire(1500).unwrap(), Some(2000));
    store.publish().unwrap();

    store.append(&HistoryRecord::new(&row, 3000, &row).unwrap()).unwrap();
    let [run] = store.manifest.runs.as_slice() else {
        panic!("expected one surviving run");
    };
    assert_eq!((run.head, run.first, run.last, run.count), (1, 2000, 3000, 3));
    assert_eq!(store.expire(3000).unwrap(), None);
    store.publish().unwrap();
    store.append(&HistoryRecord::new(&row, 4000, &row).unwrap()).unwrap();
    assert_eq!(store.expire(3000).unwrap(), Some(4000));
}

#[test]
fn archive_diagnostics_do_not_expand_or_change_shared_recovery_receipts() {
    let input = crate::io::archive_state::ArchiveInput::file("C:/input.zip".into(), "zip".into(), "input.zip".into());
    let checkpoint = json!({"input":input,"sources":[],
        "report":{"input_id":"item","position":1,"input_count":1,"output":"C:/output",
            "files":1,"bytes":1,"recovered_complete_files":0}});
    let evidence = "error details".repeat(1000);
    let mut expected = None;
    for count in [1, 1024] {
        let failure: crate::pipeline::Failure = serde_json::from_value(json!({
            "kind":"damaged","message":"CRC error",
            "evidence":{"classification_evidence":evidence,"stage":"item_extract"},
            "recovery":{"inputs":vec![checkpoint.clone();count],"output":"C:/output",
                "input_count":count,"had_checkpoints":true,"retry_output":true}
        })).unwrap();
        let event = json!({"event":"archive_failure_evidence","path":"C:/input.zip"});
        let payload = EventField {
            fields: event.as_object().unwrap(),
            name: "failure",
            value: DiagnosticFailure(&failure),
        };
        let output: Value = rmp_serde::from_slice(&rmp_serde::to_vec_named(&payload).unwrap()).unwrap();
        assert_eq!(output["failure"]["kind"], "damaged");
        assert_eq!(output["failure"]["evidence"]["stage"], "item_extract");
        assert_eq!(output["failure"]["evidence"]["classification_evidence"], evidence);
        assert!(output["failure"].get("recovery").is_none());
        if let Some(expected) = &expected { assert_eq!(&output, expected); }
        else { expected = Some(output); }
        // Ordinary failure serialization still owns the complete durable
        // contract. Only the per-archive diagnostic view omits the group.
        assert_eq!(serde_json::to_value(&failure).unwrap()["recovery"]["inputs"].as_array().unwrap().len(), count);
    }
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

#[test]
fn deduplicated_proposal_retires_live_owner_and_preserves_named_history() {
    let mut projection = Projection::default();
    let source = "C:/watch/copy.zip";
    projection.apply(&mut json!({"event":"pipeline_sources_claimed","owner":"dedup-run",
        "groups":[{"path":source,"members":[source]}]}));
    projection.apply(&mut json!({"event":"processing_started","owner":"dedup-run","path":source,"ts":1}));
    let mut terminal = json!({"event":"watch_deduplicated","owner":"dedup-run","path":source,
        "ts":2,"retire_group":true,"output_dirs":[]});
    assert!(state_event("watch_deduplicated"));
    assert!(projection.apply(&mut terminal), "deduplicated must enter ordinary history");
    assert!(projection.tasks.is_empty(), "duplicate must not remain processing");
    assert_eq!(terminal["event"], "watch_deduplicated");
    assert!(terminal["task_id"].is_string());
    assert!(terminal.get("succeeded").is_none());
    assert_eq!(terminal["output_dirs"], json!([]));
    projection.apply(&mut json!({"event":"pipeline_sources_released","owner":"dedup-run"}));
    assert!(projection.retiring.is_empty());
}
