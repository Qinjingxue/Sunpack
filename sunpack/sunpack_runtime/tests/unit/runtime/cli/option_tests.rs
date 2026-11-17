use super::*;

#[test]
fn alternating_request_sources_reuse_their_config_subscriptions() {
    let marker = crate::test_support::temp_file("cli_config_subscriptions", b"");
    let directory = marker.with_extension("directory");
    std::fs::create_dir(&directory).unwrap();
    let cwd = directory.as_path();
    let path_a = cwd.join("english.json");
    let path_b = cwd.join("chinese.json");
    std::fs::write(&path_a, br#"{"cli":{"language":"en"}}"#).unwrap();
    std::fs::write(&path_b, br#"{"cli":{"language":"zh"}}"#).unwrap();
    let mut source_a = config::ConfigSources::default();
    source_a.simple = Some(path_a.clone());
    let mut source_b = config::ConfigSources::default();
    source_b.simple = Some(path_b.clone());
    // Seed the shared directory observer from a different thread. Keep
    // its first OS read pending until both requests have subscribed.
    let (ready, armed) = std::sync::mpsc::channel();
    let (leave, exit) = std::sync::mpsc::channel::<()>();
    let (notify, changed) = std::sync::mpsc::channel();
    let path = path_a.clone();
    let issuer = std::thread::spawn(move || {
        let subscriptions = watch::observe_files(
            std::slice::from_ref(&path),
            &path.with_file_name(passwords::FILENAME),
            move |reload, _| {
                if reload {
                    let _ = notify.send(());
                }
            },
        ).unwrap();
        ready.send(subscriptions).ok().unwrap();
        let _ = exit.recv();
    });
    let seed = armed.recv().unwrap();
    let host = Host::new();
    assert_eq!(host.generation(cwd, source_a.clone(), false).language(), Language::En);
    let first = Arc::clone(host.sources.lock().unwrap().front().unwrap());
    assert_eq!(host.generation(cwd, source_b, false).language(), Language::Zh);
    drop(leave);
    issuer.join().unwrap();
    // Joining the issuer cancels its outstanding read. Wait for the
    // shared observer to process that completion before the next request.
    changed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(host.generation(cwd, source_a, false).language(), Language::En);
    let sources = host.sources.lock().unwrap();
    assert_eq!(sources.len(), 2);
    assert!(Arc::ptr_eq(sources.front().unwrap(), &first));
    drop(sources);
    // The same observer must also deliver subsequent file changes.
    std::fs::write(&path_a, br#"{"cli":{"language":"en"}}"#).unwrap();
    changed.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(first);
    drop(host);
    drop(seed);
    std::fs::remove_file(path_a).unwrap();
    std::fs::remove_file(path_b).unwrap();
    std::fs::remove_dir(directory).unwrap();
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn password_display_escapes_controls_without_changing_candidates() {
    assert_eq!(password_repr("a\t\0\n\r\\z"), "'a\\t\\x00\\n\\r\\\\z'");
    assert_eq!(password_repr("can't"), "\"can't\"");
    assert_eq!(password_repr("a'\"b"), "'a\\'\"b'");
    assert_eq!(password_repr("\u{4e2d}\u{6587}\u{2028}"), "'\u{4e2d}\u{6587}\\u2028'");
}

#[test]
fn option_aliases_share_values_without_leaking_action_scope() {
    let parse = |args: &[&str]| Options::parse(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>());
    for args in [
        vec!["e", "-vRd", "-p", "secret", "-Ppasswords.txt", "-r1", "-ck", "-odest", "-fa", "a.zip"],
        vec!["extract", "-v", "-R", "-d", "-p", "secret", "-P=passwords.txt", "-r=1", "-c=k", "-o=dest", "-f", "-a", "a.zip"],
    ] {
        let value = parse(&args).unwrap();
        assert!(value.verbose && value.recursive && value.deep);
        assert!(value.prompt_passwords);
        assert_eq!(value.flatten, Some(true));
        assert_eq!(value.depth, Some((Recursion::Fixed(1), "1".into())));
        assert_eq!(value.cleanup, Some(CleanupMode::Keep));
        assert_eq!(value.output.as_deref(), Some("dest"));
        assert_eq!(value.password_file.as_deref(), Some("passwords.txt"));
        assert_eq!(value.passwords[0].as_ref(), "secret");
        assert_eq!(value.paths, ["a.zip"]);
    }
    let added = parse(&["w", "add", "-Rd", "-odest", "root"]).unwrap();
    assert!(added.recursive && added.deep);
    assert_eq!(added.output.as_deref(), Some("dest"));
    let value = parse(&["e", "-nf", "-pa", "-p", "a", "a.zip"]).unwrap();
    assert_eq!(value.flatten, Some(false));
    assert!(value.pause && !value.no_pause);
    assert_eq!(value.passwords[0].as_ref(), "a");
    assert!(parse(&["e", "-npa", "a.zip"]).unwrap().no_pause);
    for flag in ["--help", "--json", "--verbose", "--no-pause", "--pause", "--recursive",
        "--deep-detect", "--password=x", "--pw-file=x", "--ask-pw", "--no-builtin-pw",
        "--no-bpw", "--recur=1", "--cleanup=k", "--out-dir=x", "--flatten", "--no-flatten", "-F",
        "-psecret", "-p=secret", "-vpsecret", "-vp"] {
        assert!(parse(&["extract", flag, "a.zip"]).is_err(), "{flag}");
    }
    for args in [
        vec!["scan", "-o", "dest", "a.zip"],
        vec!["passwords", "-R"],
        vec!["watch", "--start", "add", "root"],
        vec!["daemon", "start", "--start"],
        vec!["watch", "remove", "-R", "root"],
        vec!["config", "show", "-srs"],
        vec!["doctor", "-v"],
        vec!["version", "-j"],
        vec!["passwords", "-pa"],
        vec!["daemon", "start", "--no-tray"],
        vec!["config", "validate", "--scan-rule-stdin"],
    ] { assert!(parse(&args).is_err(), "{args:?}"); }
}

// One parser-level regression covers resolution, value consumption and
// subparser boundaries; no worker/filesystem is needed for these failures.
#[test]
fn argparse_option_resolution_and_boundaries() {
    let parse = |args: &[&str]| Options::parse(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>());
    let value = parse(&["extract", "-p", "-secret", "-o=dest", "file.zip"]).unwrap();
    assert_eq!(value.passwords[0].as_ref(), "-secret");
    assert_eq!(value.output.as_deref(), Some("dest"));
    assert_eq!(value.paths, ["file.zip"]);
    assert!(parse(&["extract", "--direct", "file.zip"]).is_err());
    assert!(parse(&["extract", "--direct-file", "file.zip"]).is_err());
    for args in [
        vec!["extract", "a.zip", "--cle", "d"],
        vec!["scan", "a.zip", "--recurs"],
        vec!["--hel"],
    ] { assert!(parse(&args).is_err(), "{args:?}"); }
    assert!(parse(&["watch", "-j", "status"]).unwrap().json);
    assert!(parse(&["watch", "-v", "status"]).unwrap().verbose);
    assert!(parse(&["config", "-j", "show"]).unwrap().json);
    let value = parse(&["extract", "--", "-j", "-v", "-pa"]).unwrap();
    assert!(!value.json && !value.verbose && !value.pause);
    assert_eq!(value.paths, ["-j", "-v", "-pa"]);
    // The token after standalone -p is always a literal password.
    for password in ["-j", "-v", "-pa", "-npa", "--", "-p", "", "=x"] {
        let value = parse(&["extract", "-p", password, "a.zip"]).unwrap();
        assert_eq!(value.passwords[0].as_ref(), password);
        assert!(!value.json && !value.verbose && !value.pause);
    }
    let value = parse(&["watch", "-jv", "status"]).unwrap();
    assert!(!value.json && !value.verbose);
    let value = parse(&["watch", "-j", "-v", "status"]).unwrap();
    assert!(value.json && value.verbose);
    let value = parse(&["watch", "-jv", "status", "-j"]).unwrap();
    assert!(value.json && !value.verbose);
    let value = parse(&["watch", "-pa", "enable", "-npa"]).unwrap();
    assert!(!value.pause && value.no_pause);
    let value = parse(&["extract", "-P=", "-o=", "a.zip"]).unwrap();
    assert!(value.password_file.is_none());
    assert!(value.output.is_none());
    // Watch checks whether -o was supplied, including an empty
    // value, before accepting multiple roots. Do not apply extract's
    // empty-output normalization to this command.
    for args in [
        vec!["watch", "add", "A", "B", "-o="],
        vec!["watch", "add", "A", "B", "-o", ""],
    ] {
        let value = parse(&args).unwrap();
        assert_eq!(value.output.as_deref(), Some(""));
        assert_eq!(value.paths, ["A", "B"]);
    }
    assert!(parse(&["watch", "add", "A", "B"]).unwrap().output.is_none());

    for args in [
        vec!["extract", "--dire", "file.zip"], // prefixes are not declared options
        vec!["extract", "--recu", "file.zip"],
        vec!["extract", "--no-b", "file.zip"],
        vec!["watch", "--on", "start"], // action-only flag at parent scope
        vec!["extract", "-j=true", "file.zip"],
        vec!["extract", "--pass", "-j", "file.zip"],
        vec!["extract", "a.zip", "-v", "b.zip"],
        vec!["extract", "a.zip", "-v", "--", "b.zip"],
    ] { assert!(parse(&args).is_err(), "{args:?}"); }
    let value = parse(&["extract", "-v", "-p", "secret", "-p", "-.5", "-p", "-with space", "--", "--no-b"]).unwrap();
    assert!(value.verbose);
    assert_eq!(value.passwords.iter().map(|s| s.as_ref()).collect::<Vec<_>>(), ["secret", "-.5", "-with space"]);
    assert_eq!(value.paths, ["--no-b"]);
    for password in ["-１２３", "-١٢٣", "-१२३", "-.１２", "-١.٢", "-1\n", "-.1\n", "-１２\n", "-²", "-\n", "-1\n\n", "-1\r\n"] {
        let value = parse(&["passwords", "-p", password, "-j"]).unwrap();
        assert_eq!(value.passwords[0].as_ref(), password);
    }
    assert_eq!(parse(&["extract", "a.zip", "--", "-b.zip"]).unwrap().paths, ["a.zip", "-b.zip"]);
    let value = parse(&["daemon", "-j", "start", "-nt"]).unwrap();
    assert!(value.no_tray);
    assert!(value.json); // main restores explicitly supplied parent flags
    assert!(parse(&["daemon", "start", "-j"]).unwrap().json);
    assert!(parse(&["config", "validate", "-srs"]).unwrap().rule_stdin);
    assert!(parse(&["--", "extract", "file.zip"]).is_err());
    assert!(parse(&["watch", "-j", "--", "start", "-nt"]).is_err());
    assert_eq!(parse(&["daemon", "startup", "--", "status"]).unwrap().paths, ["status"]);
    assert_eq!(parse(&["daemon", "startup", "status", "--"]).unwrap().paths, ["status"]);
    assert_eq!(parse(&["pw", "-j", "-p", "=x"]).unwrap().passwords[0].as_ref(), "=x");
    assert!(parse(&["--he"]).is_err());
    assert!(parse(&["extract", "--he"]).is_err());
    for args in [
        vec!["extract", "a.zip", "-v", "b.zip", "-h"],
        vec!["extract", "--unknown", "-h"],
        vec!["extract", "--dire", "-h"],
        vec!["--unknown", "-h"],
        vec!["extract", "-hP", "passwords.txt"],
        vec!["extract", "-hvPpasswords.txt"],
        vec!["extract", "-hfa"],
        vec!["--unknown", "extract", "-h"],
        vec!["daemon", "-nt", "start", "-h"],
        vec!["daemon", "start", "--unknown", "-h"],
        vec!["watch", "-h", "invalid"],
        vec!["--unknown", "extract"],
        vec!["watch", "--unknown", "add"],
        vec!["--unknown", "watch"],
    ] { assert!(parse(&args).unwrap().help, "{args:?}"); }
    for args in [
        vec!["-hx"],
        vec!["extract", "-hx"],
        vec!["extract", "-p", "-h"],
        vec!["extract", "-hp", "-h"],
        vec!["extract", "-hvp", "-h"],
        vec!["extract", "-hj=true"],
        vec!["-h=foo"],
        vec!["extract", "-j=true", "-h"],
        vec!["extract", "-pa", "-npa", "-h"],
        vec!["extract", "-f", "-nf", "-h"],
        vec!["watch", "invalid", "-h"],
        vec!["config", "invalid", "-h"],
    ] { assert!(parse(&args).is_err(), "{args:?}"); }
}

#[test]
fn daemon_and_watch_control_have_distinct_scopes() {
    let parse = |args: &[&str]| Options::parse(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>());
    assert_eq!(parse(&["d", "start", "-nt"]).unwrap().command, "daemon");
    assert_eq!(parse(&["doc"]).unwrap().command, "doctor");
    for (action, canonical) in [("enable", "enable"), ("disable", "disable"),
        ("ea", "enable"), ("da", "disable"), ("rl", "reload"), ("relog", "relog"), ("rlg", "relog")] {
        assert_eq!(parse(&["w", action]).unwrap().action, canonical);
    }
    assert_eq!(parse(&["daemon", "startup", "status"]).unwrap().paths, ["status"]);
    for args in [
        vec!["watch", "start"], vec!["watch", "stop"],
        vec!["watch", "rebuild-log"],
        vec!["watch", "startup", "status"], vec!["watch", "add", "root", "--start"],
        vec!["watch", "add", "-s", "root"], vec!["watch", "enable", "-nt"],
        vec!["daemon", "enable"], vec!["daemon", "stop", "-pa"],
        vec!["daemon", "-v", "stop"], vec!["daemon", "stop", "-npa"],
    ] { assert!(parse(&args).is_err(), "{args:?}"); }
}
