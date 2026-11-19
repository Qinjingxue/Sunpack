use super::*;

#[test]
fn saved_catalog_rows_keep_the_legacy_messagepack_format() {
    #[derive(Serialize)]
    struct LegacyRow {
        #[serde(flatten)]
        record: DirectoryEntryRecord,
        #[serde(skip_serializing_if = "Option::is_none")]
        observed: Option<(u64, f64, String, i64)>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generated: Option<GeneratedBaseline>,
    }

    let rows = [
        LegacyRow {
            record: DirectoryEntryRecord {
                path: r"C:\Catalog\Output".into(),
                is_dir: true,
                ..DirectoryEntryRecord::default()
            },
            observed: None,
            generated: None,
        },
        LegacyRow {
            record: DirectoryEntryRecord {
                path: r"C:\Catalog\Output\Archive.Bin".into(),
                size: Some(42),
                mtime_ns: Some(10_000_000_000),
                ..DirectoryEntryRecord::default()
            },
            observed: Some((42, 10.0, "file-id".into(), 7)),
            generated: Some(GeneratedBaseline::new(42, 10.0, "file-id", 6)),
        },
    ];
    let mut catalog = ScopeCatalog::default();
    for row in rows {
        let payload = rmp_serde::to_vec(&row).unwrap();
        let decoded: StoredRow = wal::decode(&payload).unwrap();
        let key = path_key(&row.record.path);
        decoded.insert(&mut catalog);
        let encoded = rmp_serde::to_vec(&catalog.row_view(&key).unwrap()).unwrap();
        assert_eq!(encoded, payload);
    }
}
