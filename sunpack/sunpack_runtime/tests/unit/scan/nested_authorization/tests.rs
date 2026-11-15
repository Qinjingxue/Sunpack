use super::*;

#[test]
fn semantic_scope_uses_first_directory_below_root() {
    let root = Path::new("C:\\out");
    assert_eq!(
        semantic_scope(Path::new("C:\\out\\wrapper\\inner.zip"), root),
        Some(PathBuf::from("C:\\out\\wrapper"))
    );
    assert_eq!(
        semantic_scope(Path::new("C:\\out\\root.rar"), root),
        Some(PathBuf::from("C:\\out"))
    );
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

#[test]
fn immediate_branch_finds_first_directory_for_nested_files() {
    let root = Path::new("C:\\out");
    assert_eq!(immediate_branch(Path::new("C:\\out\\a.zip"), root), None);
    assert_eq!(
        immediate_branch(Path::new("C:\\out\\wrapper\\a.zip"), root),
        Some(PathBuf::from("C:\\out\\wrapper"))
    );
}
