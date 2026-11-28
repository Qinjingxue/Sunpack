use super::*;
use crate::test_support::temp_file;

#[test]
fn available_prefix_visits_each_range_once_before_a_gap() {
    let file = temp_file("password_available_prefix", b"volume");
    let path = file.to_string_lossy().into_owned();
    let ranges: Vec<_> = (0..256).map(|i| InputExtent {
        view: None,
        path: path.clone(), start: if i == 128 { 10 } else { 0 }, end: Some(6),
    }).collect();
    RANGE_PROJECTIONS.set(Some(0));
    let prefix = available_range_prefix(ranges.iter(), &[]);
    assert_eq!(RANGE_PROJECTIONS.replace(None), Some(129));
    assert_eq!(prefix.len(), 128);
    assert_eq!(VirtualRangeReader::streaming(&prefix).len(), 128 * 6);
    drop(prefix);
    let _ = std::fs::remove_file(file);
}

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
fn disk_relative_reads_visit_only_the_requested_volume_edges() {
    use super::attempts::{count_disk_edges, prepare_attempt_evidence, AttemptGeometry};
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    let bytes: Vec<u8> = (0..128).collect();
    let file = temp_file("native_disk_edges", &bytes);
    let path = file.to_string_lossy().into_owned();
    let plan = VolumeAttemptPlan {
        sources: (0..128).map(|start| InputExtent {
            view: None,
            path: path.clone(), start, end: Some(start + 1),
        }).collect(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: (0..128).map(|domain| VolumeSlot {
                number: domain as u32 + 1, canonical_name: domain.to_string(), domain,
            }).collect(),
        }].into(),
        domains: (0..128).map(|source| VolumeDomain { choices: Arc::new(vec![source]) }).collect(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::default(),
    };
    let mut prepared = prepare_attempt_evidence(&plan.sources[0], &plan, &[], AttemptGeometry::DiskRelative,
        |reader| Ok(Some(reader.deferred_reads(true)))).unwrap_or_else(|_| panic!("disk-relative topology"));
    let readers = prepared.pop().unwrap();
    let (observations, visits) = count_disk_edges(|| readers.evaluate(|reader| reader.read_disk_offset(100, 0, 0, 4)));
    let observations = observations.unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].1.as_deref().unwrap(), &bytes[100..104]);
    assert_eq!(visits, 4);
    drop(readers);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn logical_crc_reuses_geometry_between_volume_boundaries() {
    use super::attempts::{count_logical_edges, prepare_attempt_evidence, AttemptGeometry};
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    const VOLUMES: usize = 128;
    const CHUNK: usize = 64 * 1024;
    let mut bytes = vec![b'A'; 8 * CHUNK];
    bytes[4 * CHUNK..].fill(b'B');
    bytes.extend([b'C'; VOLUMES - 2]);
    let file = temp_file("logical_crc_geometry", &bytes);
    let path = file.to_string_lossy();
    let mut start = 0;
    let sources = (0..VOLUMES).map(|i| {
        let end = start + if i < 2 { 4 * CHUNK as u64 } else { 1 };
        let extent = InputExtent { view: None, path: path.to_string(), start, end: Some(end) };
        start = end;
        extent
    }).collect();
    let plan = VolumeAttemptPlan {
        sources,
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: (0..VOLUMES).map(|domain| VolumeSlot {
                number: domain as u32 + 1, canonical_name: domain.to_string(), domain,
            }).collect(),
        }].into(),
        domains: (0..VOLUMES).map(|source| VolumeDomain { choices: Arc::new(vec![source]) }).collect(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::default(),
    };
    let mut prepared = prepare_attempt_evidence(&plan.sources[0], &plan, &[],
        AttemptGeometry::Forward { logical_limit: None },
        |reader| Ok(Some(reader.deferred_reads(false))),
    ).unwrap_or_else(|_| panic!("logical geometry"));
    let readers = prepared.pop().unwrap();
    let (observations, visits) = count_logical_edges(|| readers.evaluate(|reader| {
        assert!(readers.shares_projection(reader));
        let mut head = crc32fast::Hasher::new();
        for offset in (0..8 * CHUNK).step_by(CHUNK) {
            head.update(&reader.read(offset as u64, CHUNK).unwrap());
        }
        // A backward seek must resolve the earlier volume again.
        let restart = reader.read(0, 1).unwrap();
        (head.finalize(), restart)
    }));
    let observations = observations.unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].1, (crc32fast::hash(&bytes[..8 * CHUNK]), vec![b'A']));
    assert_eq!(visits, 3 * VOLUMES);
    drop(readers);
    std::fs::remove_file(file).unwrap();
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
            view: None,
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
    assert_eq!(values, [b"aX".to_vec(), b"abY".to_vec()]);
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

#[test]
fn delayed_read_keeps_unavailable_choices_separate_from_readable_bytes() {
    use super::attempts::{prepare_attempt_evidence, AttemptGeometry, DeferredReadError};
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    let paths = [
        temp_file("deferred_head", b"H"),
        temp_file("deferred_match", b"A"),
        temp_file("deferred_reject", b"B"),
        temp_file("deferred_unavailable", b""),
        temp_file("deferred_truncated", b""),
    ];
    std::fs::remove_file(&paths[3]).unwrap();
    let plan = VolumeAttemptPlan {
        sources: paths.iter().map(|path| InputExtent {
            view: None,
            path: path.to_string_lossy().into_owned(), start: 0, end: Some(1),
        }).collect(),
        domains: [vec![0], vec![1, 2, 3, 4]].map(|choices| VolumeDomain { choices: Arc::new(choices) }).into(),
        layouts: vec![VolumeLayout {
            slots: (0..2).map(|domain| VolumeSlot {
                number: domain as u32 + 1, canonical_name: domain.to_string(), domain,
            }).collect(),
            minimum_slots: 0,
        }].into(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::default(),
    };
    let values = prepare_attempt_evidence(&plan.sources[0], &plan, &[],
        AttemptGeometry::Forward { logical_limit: None },
        |reader| Ok(Some(reader.deferred_reads(false))),
    ).unwrap_or_else(|_| panic!("shared prefix geometry"));
    assert!(!values[0].disk_range_is_ambiguous(0, 0, 1));
    assert!(values[0].disk_range_is_ambiguous(0, 1, 1));
    let observations = values[0].evaluate(|reader| {
        assert_eq!(reader.read(0, 1).unwrap(), b"H");
        reader.read(1, 1)
    }).unwrap();
    let mut count = 0;
    for (projection, read) in observations {
        let source = projection.edges.iter().find(|edge| edge[2] != 0).unwrap()[2];
        count += 1;
        match (source, read) {
            (1, Ok(bytes)) if bytes == b"A" => {}
            (2, Ok(bytes)) if bytes == b"B" => {}
            (3, Err(DeferredReadError::Io(_))) => {}
            (4, Err(DeferredReadError::Truncated)) => {}
            (source, read) => panic!("unexpected deferred read for {source}: {read:?}"),
        }
    }
    assert_eq!(count, 4);
    drop(values);
    for (index, path) in paths.into_iter().enumerate() {
        if index != 3 { std::fs::remove_file(path).unwrap(); }
    }
}

#[test]
fn equal_volume_evidence_reuses_its_comparison_bytes() {
    use super::attempts::{count_edge_reads, prepare_attempt_evidence, AttemptGeometry};
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    const COPIES: usize = 8;
    let mut carrier = b"XA".to_vec();
    for _ in 1..=8 {
        let first = std::mem::replace(&mut carrier[0], b'M');
        carrier.push(first);
        carrier.extend_from_slice(&1u32.to_le_bytes());
    }
    let mut paths = vec![temp_file("shared_evidence_head", b"H--"), temp_file("distinct_tail", &carrier)];
    paths.extend((0..COPIES).map(|_| temp_file("repeated_tail", b"B")));
    let mut sources: Vec<_> = paths.iter().map(|path| InputExtent {
        view: None,
        path: path.to_string_lossy().into_owned(), start: 0, end: Some(1),
    }).collect();
    // Distinct view candidates aliasing exactly the bytes already requested
    // must stay in the proof without issuing more reads, including on replay.
    sources[1].start = 1;
    sources[1].end = Some(2);
    let file = ManagedReader::open(&paths[1]).unwrap();
    let views = crate::io::view::ConfiguredViews::from_methods(false, (1..=8).map(|n| (crate::io::view::ViewMethod::Apate, n)).collect())
        .derive_views(&file, &mut Default::default()).unwrap();
    assert_eq!(views.len(), 8);
    drop(file);
    for view in views {
        sources.push(InputExtent { view: Some(view), ..sources[1].clone() });
    }
    let plan = VolumeAttemptPlan {
        domains: [vec![0], (1..sources.len()).collect()].map(|choices|
            VolumeDomain { choices: Arc::new(choices) }).into(),
        sources: sources.into(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: (0..2).map(|domain| VolumeSlot {
                number: domain as u32 + 1, canonical_name: domain.to_string(), domain,
            }).collect(),
        }].into(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::default(),
    };
    // Relations kept the plain representative of this exact mapped head.
    let head = InputExtent { start: 1, end: Some(2), view: Some(Arc::new(crate::io::view::ReadView {
        method: crate::io::view::ViewMethod::Apate, depth: 1, physical_size: 3,
        spans: vec![crate::io::view::Span { start: 2, end: 3, reverse: false },
                    crate::io::view::Span { start: 0, end: 1, reverse: false }],
    })), ..plan.sources[0].clone() };
    let values = prepare_attempt_evidence(&head, &plan, &[],
        AttemptGeometry::Forward { logical_limit: None },
        |reader| Ok(Some(reader.deferred_reads(false))),
    ).unwrap_or_else(|_| panic!("volume alternatives"));
    let (observations, reads) = count_edge_reads(|| values[0].evaluate(|reader| reader.read(1, 1)));
    let bytes: Vec<_> = observations.unwrap().into_iter().map(|(_, read)| read.unwrap()[0]).collect();
    assert_eq!(bytes, [b'A', b'B']);
    // One read per source in discovery and replay, plus one comparison
    // read for the representatives not kept in the caller's buffer.
    assert_eq!(reads, (COPIES + 1) * 2 + 1);
    drop(values);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn length_partitions_preserve_all_offsets_and_prune_impossible_prefixes() {
    use super::attempts::{prepare_attempt_evidence, AttemptGeometry, PackedCrcs};
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::sync::Arc;

    let file = temp_file("volume_length_frontier", &[b'x'; 512]);
    let path = file.to_string_lossy().into_owned();
    for (slots, only_longest) in [(8, false), (32, true)] {
        let mut sources = vec![InputExtent {
            path: path.clone(),
            start: 0,
            end: Some(1),
            view: None,
        }];
        let mut domains = vec![VolumeDomain {
            choices: Arc::new(vec![0]),
        }];
        for index in 0..slots {
            let first = sources.len();
            for length in [1, 1 + (1u64 << index)] {
                sources.push(InputExtent {
                    path: path.clone(),
                    start: index + 1,
                    end: Some(index + 1 + length),
                    view: None,
                });
            }
            domains.push(VolumeDomain {
                choices: Arc::new(vec![first, first + 1]),
            });
        }
        let base = 1 + slots as u64;
        let last = base + (1u64 << slots) - 1;
        let layout = VolumeLayout {
            minimum_slots: 0,
            slots: (0..domains.len())
                .map(|domain| VolumeSlot {
                    number: domain as u32 + 1,
                    canonical_name: String::new(),
                    domain,
                })
                .collect(),
        };
        let mut plan = VolumeAttemptPlan {
            sources: sources.into(),
            domains: domains.into(),
            layouts: Box::new([layout]),
            minimum_size: only_longest.then_some(last),
            head_size_from_total: None,
            tail_totals: Box::default(),
        };
        let crc = PackedCrcs::default();
        let wrong_crc = !crc32fast::hash(b"x");
        let mut lengths = prepare_attempt_evidence(
            &plan.sources[0],
            &plan,
            &[],
            AttemptGeometry::Forward {
                logical_limit: None,
            },
            |reader| {
                let len = reader.len();
                if !only_longest {
                    assert!(!reader.packed_matches(len - 1, 1, wrong_crc, &crc).unwrap());
                }
                Ok(Some(len))
            },
        )
        .unwrap_or_else(|_| panic!("valid volume geometry"));
        lengths.sort_unstable();
        assert_eq!(
            lengths,
            ((if only_longest { last } else { base })..=last).collect::<Vec<_>>()
        );

        if !only_longest {
            plan.sources[0].end = Some(last);
            let mut heads = prepare_attempt_evidence(
                &plan.sources[0],
                &plan,
                &[],
                AttemptGeometry::TrimmedHead { total: last },
                |reader| Ok(reader.volume_len(0).ok().flatten()),
            )
            .unwrap_or_else(|_| panic!("valid carrier head lengths"));
            heads.sort_unstable();
            assert_eq!(heads, (1..=1u64 << slots).collect::<Vec<_>>());
        }
    }
    std::fs::remove_file(file).unwrap();
}
