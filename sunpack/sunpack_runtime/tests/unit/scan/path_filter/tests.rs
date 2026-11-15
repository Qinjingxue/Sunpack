use super::*;

#[test]
fn regex_cache_pressure_keeps_concurrent_batch_results() {
    let rule = PathRule::compile(
        vec![],
        vec![],
        vec![],
        vec![RuleEntry {
            value: r"\A[01]*1[01]{18}\z".into(),
            regex: true,
        }],
    )
    .unwrap();
    let names: Vec<_> = (0..1024u64)
        .map(|index| format!("{:064b}", index.wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect();
    std::thread::scope(|workers| {
        for _ in 0..4 {
            workers.spawn(|| {
                let mut scratch = PathRuleScratch::default();
                for name in &names {
                    let path = Path::new("C:/input").join(name);
                    let candidate = FilterPath::new(&path, Path::new("C:/input"));
                    assert_eq!(
                        !rule.rejects(&candidate, false, true, &mut scratch),
                        name.as_bytes()[45] == b'1'
                    );
                }
            });
        }
    });
}

#[test]
fn reused_path_scratch_follows_ancestors_in_arbitrary_order() {
    let root = Path::new("C:/input");
    let relatives = [
        "a/keep/deep",
        "ab/keep",
        "a/keeper",
        "中文/keep",
        "",
        "a/other",
        "a/keep",
        "中文/keeper",
        "ab",
        "a",
        "別/keep",
    ];
    for (value, regex) in [
        ("keep", false),
        ("a/keep", false),
        ("a/k??p", false),
        (r"\Aa/keep\z|\A中文/keep\z", true),
        (r"(?:\A|/)keep\z", true),
        (r"\A\z", true),
    ] {
        let rule = PathRule::compile(
            vec![RuleEntry {
                value: value.into(),
                regex,
            }],
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        for whitelist in [false, true] {
            let mut scratch = PathRuleScratch::default();
            for relative in relatives.iter().chain(relatives.iter().rev()) {
                let directory = root.join(relative);
                for (path, is_dir) in
                    [(&directory, true), (&directory.join("payload.001"), false)]
                {
                    for base in [root, path.parent().unwrap()] {
                        let candidate = FilterPath::new(path, base);
                        let mut single = PathRuleScratch::default();
                        single.paths.one_shot = true;
                        assert_eq!(
                            rule.rejects(&candidate, is_dir, whitelist, &mut scratch),
                            rule.rejects(&candidate, is_dir, whitelist, &mut single),
                            "{value:?} {path:?} under {base:?}"
                        );
                    }
                }
            }
        }
    }
}
