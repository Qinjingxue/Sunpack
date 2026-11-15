use super::*;

#[test]
fn explicit_null_analysis_modules_does_not_enable_builtins() {
    let default = Config::parse(&serde_json::json!({"analysis": null})).unwrap();
    let disabled = Config::parse(&serde_json::json!({"analysis": {"modules": null}})).unwrap();
    assert!(!default.analysis.modules.is_empty());
    assert!(disabled.analysis.modules.is_empty());
}

#[test]
fn observed_invalid_edit_is_consumed_while_inspection_stays_strict() {
    let path = crate::test_support::temp_file("observed_config", br#"{"cli":{"language":"en"}}"#);
    let sources = ConfigSources { simple: Some(path.clone()), ..Default::default() };
    let read = |mode| read_generation(Path::new("."), sources.clone(), mode);
    let first = read(ReadMode::Observe).observed.unwrap();
    std::fs::write(&path, br#"{"cli":{"language":"zh"},"recursive_extract":0}"#).unwrap();
    invalidate_sources();
    let failed = read(ReadMode::Observe);
    assert!(failed.language() == Language::Zh);
    let fallback = failed.observed.unwrap();
    assert!(fallback.reload_error.is_some());
    assert!(fallback.snapshot.config == first.snapshot.config);
    let reused = read(ReadMode::Observe).observed.unwrap();
    assert!(Arc::ptr_eq(&fallback, &reused));
    assert!(read(ReadMode::Inspect).into_inspection().is_err());

    std::fs::write(&path, br#"{"cli":{"language":"zh"}}"#).unwrap();
    invalidate_sources();
    let current = read(ReadMode::Observe).normalized(true).unwrap();
    assert!(current.cli.language == Language::Zh);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn one_config_value_preserves_layer_precedence_and_named_filter_order() {
    let advanced = crate::test_support::temp_file("merge_advanced", br#"{"cli":{"language":"en","language":"zh"},"user_passwords":["old"],"filesystem":{"scan_filters":[{"name":"a","z":0,"a":1},{"name":"b","keep":true},{"name":"c","untouched":7}]},"analysis":{"filesystem":{"scan_filters":[{"name":"a","old":true}]}}}"#);
    let simple = crate::test_support::temp_file("merge_simple", br#"{"filesystem":{"scan_filters":[{"name":"b","extra":7},{"name":"a","a":2,"new":3}]},"user_passwords":["second","first"],"analysis":{"filesystem":{"scan_filters":[{"name":"a","new":true}]}}}"#);
    let sources = ConfigSources {
        advanced: Some(advanced.clone()),
        simple: Some(simple.clone()),
        inline_override: Some(r#"{"filesystem":{"scan_filters":[{"name":"a","last":1},{"free":true},{"name":"a","later":2}]},"cli":{"verbose":true}}"#.into()),
        ..ConfigSources::default()
    };
    let value = sources.load(Path::new(".")).unwrap();
    std::fs::remove_file(advanced).unwrap();
    std::fs::remove_file(simple).unwrap();
    let expected = serde_json::json!({
        "cli":{"language":"zh","verbose":true},
        "user_passwords":["second","first"],
        "analysis":{"filesystem":{"scan_filters":[{"name":"a","new":true}]}},
        "filesystem":{"scan_filters":[
            {"name":"a","z":0,"a":2,"new":3,"last":1,"later":2},
            {"name":"a","z":0,"a":2,"new":3,"last":1,"later":2},
            {"name":"b","keep":true,"extra":7},
            {"name":"c","untouched":7},
            {"free":true}
        ]}
    });
    assert_eq!(value, expected);
    // Both show encodings now serialize this same authoritative document,
    // without a parallel shape that can omit keys or truncate arrays.
    let encoded = serde_json::to_string_pretty(&value).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), expected);
}
