use super::*;

#[test]
fn observed_config_candidates_stop_at_selected_priority() {
    let roots = [PathBuf::from(r"C:\application"), PathBuf::from(r"C:\request")];
    let application = roots[0].join(ADVANCED);
    let request = roots[1].join(ADVANCED);
    assert_eq!(source_candidates(&roots, ADVANCED, Some(&application)), [application.clone()]);
    // Missing sources and a lower-priority selection retain the higher
    // candidate so its later creation can take precedence.
    assert_eq!(source_candidates(&roots, ADVANCED, None), [application.clone(), request.clone()]);
    assert_eq!(source_candidates(&roots, ADVANCED, Some(&request)), [application, request]);
}

#[test]
fn filter_validation_errors_match_public_main_messages() {
    let cases = [
        (serde_json::json!({"name":"mtime_range","start_utc":"2026-02-30T00:00Z"}), "Invalid UTC minute"),
        (serde_json::json!({"name":"blacklist","unexpected":true}), "Unsupported blacklist fields: unexpected"),
        (serde_json::json!({"name":"blacklist","paths":[{"value":"a","regex":1}]}), "paths[0] requires a nonempty value string and a regex boolean"),
        (serde_json::json!({"name":"blacklist","paths":[["a",false]]}), "paths[0] requires a nonempty value string and a regex boolean"),
        (serde_json::json!({"name":"whitelist","paths":[{"value":"","regex":false}]}), "paths[0] requires a nonempty value string and a regex boolean"),
        (serde_json::json!({"name":"blacklist","paths":null}), "paths must be a list of rule objects"),
    ];
    for (value, expected) in cases {
        let error = match ScanFilter::parse(0, &value) {
            Ok(_) => panic!("invalid filter accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn saved_output_mapping_participates_in_runtime_configuration() {
    let mut raw = serde_json::json!({"output":{"root":"Recovered","fixed_root":true}});
    let mapped = Config::parse(&raw).unwrap();
    assert_eq!(mapped.output.root.as_deref(), Some(std::path::Path::new("Recovered")));
    assert!(mapped.output.fixed_root);
    raw["output"]["root"] = Value::String(String::new());
    assert!(Config::parse(&raw).unwrap().output.root.is_none());
}

#[test]
fn configured_user_passwords_are_literal_ordered_and_deduplicated() {
    let mut raw = defaults().clone();
    raw["user_passwords"] = serde_json::json!([" first ", "", " first ", "second\0"]);
    let config = Config::parse(&raw).unwrap();
    assert_eq!(config.user_passwords.iter().map(AsRef::as_ref).collect::<Vec<_>>(), [" first ", "", "second\0"]);
    let old = Arc::clone(&config.user_passwords);
    let second_batch = Arc::clone(&config.user_passwords);
    assert!(Arc::ptr_eq(&old, &second_batch));
    let copied_config = config.clone();
    assert!(Arc::ptr_eq(&old, &copied_config.user_passwords));
    raw["user_passwords"] = serde_json::json!(["new", " first "]);
    let updated = Config::parse(&raw).unwrap();
    assert!(!Arc::ptr_eq(&old, &updated.user_passwords));
    assert_eq!(old[0].as_ref(), " first ");
    assert_eq!(updated.user_passwords[0].as_ref(), "new");
}

#[test]
fn normalized_configuration_equality_ignores_syntax_but_not_runtime_changes() {
    let mut raw = serde_json::json!({"runtime":{"process_mode":"normal"}});
    let before = Config::parse(&raw).unwrap();
    raw["runtime"]["process_mode"] = Value::String("NORMAL".into());
    let same = Config::parse(&raw).unwrap();
    assert!(before == same);
    raw["runtime"]["process_mode"] = Value::String("background".into());
    let changed = Config::parse(&raw).unwrap();
    assert!(before != changed);
    let omitted_rules = PathRule::parse(&serde_json::json!({"name":"blacklist","enabled":true})).unwrap();
    let empty_rules = PathRule::parse(&serde_json::json!({"paths":[],"files":[],"extensions":[],"full_names":[]})).unwrap();
    // The compiled matcher is shared, and does not affect settings equality.
    omitted_rules.compile().unwrap();
    let copied = omitted_rules.clone();
    assert!(Arc::ptr_eq(&omitted_rules.inner, &copied.inner));
    assert!(copied.inner.compiled.get().is_some());
    assert!(omitted_rules == empty_rules);
}

#[test]
fn disabled_rules_validate_shape_without_compiling_expressions() {
    let mut raw = defaults().clone();
    raw["filesystem"]["scan_filters"] = serde_json::json!([{
        "name": "blacklist", "enabled": false,
        "full_names": [{"value": "[", "regex": true}]
    }]);
    assert!(Config::parse(&raw).is_ok());
    assert!(!Config::parse(&raw).unwrap().validate_scan_filters().is_empty());
    raw["filesystem"]["scan_filters"][0]["name"] = Value::String(" blacklist ".into());
    assert!(Config::parse(&raw).is_ok());
    assert!(!Config::parse(&raw).unwrap().validate_scan_filters().is_empty());
    raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String(String::new());
    assert!(Config::parse(&raw).is_err());
    raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = Value::String("[".into());
    raw["filesystem"]["scan_filters"][0]["enabled"] = Value::Bool(true);
    let config = Config::parse(&raw).unwrap();
    assert!(crate::pipeline::scan_options(&config).is_err());
    let second = raw["filesystem"]["scan_filters"][0].clone();
    raw["filesystem"]["scan_filters"].as_array_mut().unwrap().push(second);
    assert_eq!(Config::parse(&raw).unwrap().validate_scan_filters().len(), 2);
    raw["filesystem"]["scan_filters_enabled"] = Value::Bool(false);
    assert!(crate::pipeline::scan_options(&Config::parse(&raw).unwrap()).is_ok());
    raw["filesystem"]["scan_filters"][0]["full_names"][0]["regex"] = Value::String("bad".into());
    assert!(Config::parse(&raw).is_err());
    let a = PathRule::parse(&serde_json::json!({"name":"blacklist"})).unwrap();
    let b = PathRule::parse(&serde_json::json!({"name":"whitelist", "paths":[]})).unwrap();
    assert!(a == b);
}

#[test]
fn watch_deduplication_scope_changes_are_normalized_and_validated() {
    let mut raw = serde_json::json!({"watch":{"deduplication_scope":"root"}});
    let root = Config::parse(&raw).unwrap();
    assert_eq!(root.watch.deduplication_scope, WatchDeduplicationScope::Root);
    raw["watch"]["deduplication_scope"] = Value::String("GLOBAL".into());
    let global = Config::parse(&raw).unwrap();
    assert_eq!(global.watch.deduplication_scope, WatchDeduplicationScope::Global);
    assert!(global != root);
    for invalid in [Value::String("volume".into()), Value::from(42)] {
        raw["watch"]["deduplication_scope"] = invalid;
        assert!(Config::parse(&raw).is_err());
    }
}
