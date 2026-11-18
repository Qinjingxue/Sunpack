use super::*;
use crate::test_support::temp_file;

#[test]
fn virtual_ranges_read_and_seek_across_files() {
    let first = temp_file("password_range_first", b"012345");
    let second = temp_file("password_range_second", b"abcdef");
    let ranges = [
        RangeSpec {
            reader: ManagedReader::open(&first).unwrap(),
            start: 2,
            len: 3,
            virtual_start: 0,
        },
        RangeSpec {
            reader: ManagedReader::open(&second).unwrap(),
            start: 1,
            len: 4,
            virtual_start: 3,
        },
    ];
    let mut reader = VirtualRangeReader::new(&ranges);
    let mut all = [0u8; 7];
    reader.read_exact(&mut all).unwrap();
    assert_eq!(&all, b"234bcde");
    reader.seek(SeekFrom::Start(2)).unwrap();
    let mut middle = [0u8; 3];
    reader.read_exact(&mut middle).unwrap();
    assert_eq!(&middle, b"4bc");
    let _ = std::fs::remove_file(first);
    let _ = std::fs::remove_file(second);
}

#[test]
fn tail_total_table_prefers_source_then_falls_back_to_global_trim() {
    use super::attempts::{prepare_attempt_evidence, AttemptGeometry};
    use crate::io::archive_state::{
        InputExtent, TailTotal, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot,
    };
    use std::sync::Arc;
    let paths = [
        temp_file("trim_head", b"abcd"),
        temp_file("trim_tail_x", b"X"),
        temp_file("trim_tail_y", b"Y"),
    ];
    let sources: Vec<_> = paths
        .iter()
        .map(|path| InputExtent {
            path: path.to_string_lossy().into_owned(),
            start: 0,
            end: Some(std::fs::metadata(path).unwrap().len()),
        })
        .collect();
    let plan = VolumeAttemptPlan {
        sources: sources.clone().into_boxed_slice(),
        domains: vec![
            VolumeDomain {
                choices: Arc::new(vec![0]),
            },
            VolumeDomain {
                choices: Arc::new(vec![1, 2]),
            },
        ]
        .into_boxed_slice(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: (0..2)
                .map(|index| VolumeSlot {
                    number: index as u32 + 1,
                    canonical_name: format!("x.{index}"),
                    domain: index,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }]
        .into_boxed_slice(),
        head_size_from_total: Some(3),
        minimum_size: None,
        tail_totals: vec![TailTotal {
            source: 1,
            total: 2,
        }]
        .into_boxed_slice(),
    };
    let values = prepare_attempt_evidence(
        &sources[0],
        &plan,
        &[],
        AttemptGeometry::TailTotals,
        |reader| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).map_err(|error| {
                crate::password::context::PreparedStatus::new(
                    "unknown_needs_final_verifier",
                    error.to_string(),
                )
            })?;
            Ok(Some(bytes))
        },
    )
    .unwrap_or_else(|_| panic!("tail-specific geometry"));
    assert_eq!(values.len(), 2);
    assert!(values.contains(&b"aX".to_vec()));
    assert!(values.contains(&b"abY".to_vec()));
    let disks = prepare_attempt_evidence(
        &sources[0],
        &plan,
        &[],
        AttemptGeometry::TailTotals,
        |reader| {
            let read = (|| -> std::io::Result<_> {
                assert_eq!(reader.last_disk()?, Some(1));
                let head_len = reader.volume_len(0)?.unwrap();
                assert_eq!(reader.volume_len(2)?, None);
                let whole = reader.read_disk_spanning(0, 0, 8)?;
                let tail = reader.read_disk_spanning(1, 0, 1)?;
                assert_eq!(reader.advance_disk_offset(0, head_len, 1)?, Some((1, 1)));
                Ok((head_len, whole, tail))
            })();
            read.map(Some).map_err(|error| {
                crate::password::context::PreparedStatus::new(
                    "unknown_needs_final_verifier",
                    error.to_string(),
                )
            })
        },
    )
    .unwrap_or_else(|_| panic!("disk-relative projected geometry"));
    assert_eq!(disks.len(), 2);
    assert!(disks.contains(&(1, b"aX".to_vec(), b"X".to_vec())));
    assert!(disks.contains(&(2, b"abY".to_vec(), b"Y".to_vec())));
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}
