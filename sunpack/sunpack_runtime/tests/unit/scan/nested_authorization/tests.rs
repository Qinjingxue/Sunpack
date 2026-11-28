use super::*;

#[test]
fn nested_authorization_requires_both_root_and_local_scope() {
    use crate::scan::directory::DirectoryEntryRecord;

    let allowed = r"C:\out\allowed\first.zip";
    let sibling = r"C:\out\allowed\wrapper\second.bin";
    let denied = r"C:\out\denied\wrapper\small.7z";
    let direct = r"C:\out\root.rar";
    let records = [
        (allowed, 1000),
        (sibling, 1000),
        (denied, 1),
        (r"C:\out\denied\large.dat", 10),
        (direct, 1000),
    ].map(|(path, size)| DirectoryEntryRecord {
        path: path.into(),
        size: Some(size),
        ..Default::default()
    });
    let (_, snapshot) = NativeDirectorySnapshot::from_views(
        Vec::new(), records, Default::default(), Vec::new(),
    );
    let candidates = [allowed, denied, direct, sibling, r"C:\other\outside.rar"];
    let scope = Path::new(r"C:\out");
    let decisions = |minimum_authorization_score| authorize_nested_candidates(
        &snapshot,
        scope,
        candidates.iter().copied().map(|path| (path, std::iter::empty())),
        AuthorizationConfig {
            enabled: true,
            byte_ratio_exponent: 1.0,
            project_ratio_exponent: 1.0,
            minimum_authorization_score,
        },
    );
    assert_eq!(decisions(0.85), [true, false, true, true, false]);
    assert_eq!(decisions(1.0), [false; 5]);
}

#[test]
fn project_ratio_uses_candidate_share_of_all_projects() {
    assert_eq!(project_ratio(0, 0), 0.0);
    assert_eq!(project_ratio(1, 0), 1.0);
    assert_eq!(project_ratio(1, 19), 0.05);
    assert_eq!(project_ratio(2, 3), 0.4);
}

#[test]
fn odds_fusion_accelerates_at_extreme_ratios() {
    let score = |bytes, projects| odds_fusion_score(bytes, projects, 1.0, 1.0);
    assert!(score(0.99, 1.0 / 6.0) > 0.95);
    assert!((score(0.99, 0.05) - 0.839).abs() < 0.002);
    assert!(score(0.99, 1.0 / 31.0) < 0.77);
    assert!(score(0.999, 0.05) > score(0.99, 0.05));
}
