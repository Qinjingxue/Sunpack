use super::*;

#[test]
fn saved_catalog_rows_keep_the_legacy_messagepack_format() {
    #[derive(Serialize)]
    struct LegacyRow {
        path: &'static str,
        is_dir: bool,
        size: Option<u64>,
        mtime_ns: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        observed: Option<(u64, f64, String, i64)>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generated: Option<(u64, f64, String, i64)>,
    }

    let rows = [
        LegacyRow {
            path: r"C:\Catalog\Output",
            is_dir: true,
            size: None,
            mtime_ns: None,
            observed: None,
            generated: None,
        },
        LegacyRow {
            path: r"C:\Catalog\Output\Archive.Bin",
            is_dir: false,
            size: Some(42),
            mtime_ns: Some(10_000_000_000),
            observed: Some((42, 10.0, "file-id".into(), 7)),
            generated: Some((42, 10.0, "file-id".into(), 6)),
        },
    ];
    let mut catalog = ScopeCatalog::default();
    for row in rows {
        let payload = rmp_serde::to_vec_named(&row).unwrap();
        let decoded: StoredRow = wal::decode(&payload).unwrap();
        let key = path_key(row.path);
        decoded.insert(&mut catalog);
        let encoded = rmp_serde::to_vec(&catalog.row_view(&key).unwrap()).unwrap();
        assert_eq!(encoded, payload);
    }
}
