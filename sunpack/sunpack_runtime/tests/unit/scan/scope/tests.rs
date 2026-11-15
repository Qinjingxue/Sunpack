use super::*;

#[test]
fn output_publication_failure_rolls_back_only_new_empty_root() {
    let marker = crate::test_support::temp_file("output_publication_failure", b"");
    let root = marker.with_extension("output");
    let publish = |exclusive, arrival| -> std::io::Result<()> {
        let _creation = OutputRootCreation::create(&root, exclusive)?;
        if arrival { std::fs::write(root.join("external.txt"), b"keep")?; }
        // Identity/alias publication fails after mkdir, before the caller
        // can add this directory to its extraction rollback receipts.
        Err(std::io::ErrorKind::PermissionDenied.into())
    };
    assert!(publish(true, false).is_err());
    assert!(!root.exists());
    std::fs::create_dir(&root).unwrap();
    assert!(publish(false, false).is_err());
    assert!(root.is_dir());
    assert!(publish(true, false).is_err()); // existing directory is not ours
    assert!(root.is_dir());
    std::fs::remove_dir(&root).unwrap();
    assert!(publish(true, true).is_err());
    assert_eq!(std::fs::read(root.join("external.txt")).unwrap(), b"keep");
    std::fs::remove_file(root.join("external.txt")).unwrap();
    std::fs::remove_dir(&root).unwrap();
    OutputRootCreation::create(&root, true).unwrap().commit();
    assert!(root.is_dir());
    std::fs::remove_dir(&root).unwrap();
    std::fs::remove_file(marker).unwrap();
}
