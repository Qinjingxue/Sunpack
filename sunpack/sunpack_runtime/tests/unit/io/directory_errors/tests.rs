use super::*;

#[test]
fn merged_report_preserves_every_distinct_scan_error() {
    let mut report = DirectoryReadErrors::report();
    for index in 0..128 {
        let mut directory = DirectoryReadErrors::default();
        // More than the previous per-directory cap in the first batch.
        let entries = if index == 0 { 24 } else { 1 };
        for child in 0..entries {
            let path = format!("C:/input/{index}/{child}");
            directory.push(Path::new(&path), "metadata", io::ErrorKind::PermissionDenied.into());
        }
        // This spelling refers to the first observation and adds no evidence.
        directory.push(Path::new("c:\\input\\0\\0"), "metadata", io::ErrorKind::PermissionDenied.into());
        report.merge_report(directory);
    }
    let errors = report.into_messages();
    assert_eq!(errors.len(), 151);
    assert_eq!(errors[23].1, "C:/input/0/23");
    assert_eq!(errors.last().unwrap().1, "C:/input/127/0");
}
