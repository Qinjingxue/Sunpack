use super::*;

fn assert_view(view: HitView<'_>, expected: &[RawHit]) {
    assert_eq!(view.len(), expected.len());
    assert_eq!(view.iter().collect::<Vec<_>>(), expected);
    let mut parallel = view.par_iter_mask(TAGS).collect::<Vec<_>>();
    parallel.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
    assert_eq!(parallel, expected);
    assert_eq!(view.get(expected.len()), None);
    let mut cursor = view.iter();
    for group in expected.chunk_by(|a, b| a.offset() == b.offset()) {
        assert_eq!(
            cursor.equal_offset(group[0].offset()).collect::<Vec<_>>(),
            group
        );
    }
    for (i, hit) in expected.iter().enumerate() {
        assert_eq!(view.get(i).as_ref(), Some(hit));
    }
    for offset in expected
        .iter()
        .step_by(19)
        .flat_map(|h| {
            [
                h.offset().saturating_sub(1),
                h.offset(),
                h.offset().saturating_add(1),
            ]
        })
        .chain([0, u64::MAX])
    {
        let rank = expected.partition_point(|h| h.offset() < offset);
        assert_eq!(view.lower_bound(offset), rank, "lower_bound {offset}");
        let mut cursor = view.iter();
        cursor.seek_ge(offset);
        assert_eq!(cursor.next().as_ref(), expected.get(rank));
    }
    for tags in [1, 1 << 1, 1 << 12, (1 << 5) | (1 << 13), TAGS] {
        let subset = expected
            .iter()
            .filter(|h| tags & (1 << h.pattern) != 0)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(view.iter_mask(tags).collect::<Vec<_>>(), subset);
        // A filtered equal-offset query must not consume a later matching
        // offset when this group contains only excluded types.
        let mut grouped = view.iter_mask(tags);
        for group in expected.chunk_by(|a, b| a.offset() == b.offset()) {
            let selected = group
                .iter()
                .filter(|h| tags & (1 << h.pattern) != 0)
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                grouped.equal_offset(group[0].offset()).collect::<Vec<_>>(),
                selected
            );
        }
        let mut parallel = view.par_iter_mask(tags).collect::<Vec<_>>();
        parallel.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        assert_eq!(parallel, subset);
    }
}

// Archive fixtures cannot distinguish codec/query corruption at duplicate
// offsets, 64-bit boundaries, partial leaves, or an EF bucket with no hits.
// One differential lifecycle covers all codecs and both query mechanisms.
#[test]
fn codecs_and_index_queries_preserve_the_sorted_multiset() {
    let mut used = [false; 8];
    let mut random = 0x1234_5678u32;
    for mode in 0..12 {
        for count in [0, 1, 2, 7, 127, 128, 129, 257, 4099] {
            let base = u64::MAX - (1 << 28);
            let mut offset = 0;
            let mut hits = Vec::new();
            for i in 0..count {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                offset += match mode {
                    0 => 12,
                    1 => 0,
                    2 | 3 => random % 25,
                    4 => (random % 10000) + 100,
                    // Exercise both subtraction directions at an early
                    // cut and a leaf-tail cut, including partial leaves.
                    5 => {
                        u32::from(i % 128 == if count % 2 == 0 { 127 } else { 8 }) * 50000
                            + random % 2
                    }
                    6 => random % 4,
                    8 => 1 + random % 3,
                    9 => {
                        if i % 128 < 120 {
                            1
                        } else {
                            4096
                        }
                    }
                    10 => u32::from(i % 14 == 0) * 1000,
                    11 => 1 << (random % 16),
                    _ => random % 2,
                };
                hits.push(RawHit::new(
                    base + offset as u64,
                    match mode {
                        0 | 2 | 4 | 5 | 8 | 9 | 11 => 13,
                        3 => (i % 3 * 5) as u8,
                        _ => (i % 14) as u8,
                    },
                ));
            }
            hits.sort_unstable_by_key(|h| (h.offset(), h.hit_name()));
            let store = HitStorage::from_hits(&hits);
            let view = store.view(0);
            for si in 0..view.segments() {
                let segment = view.segment(si);
                let codec = segment.control as u32 & 7;
                used[codec as usize] = true;
                if codec == LEAVES {
                    for li in 0..view.leaf_count(segment) {
                        let (leaf, _, _) = view.leaf(segment, li);
                        used[(leaf.control & 7) as usize] = true;
                    }
                }
            }
            assert_view(view, &hits);
            let mut source_hits = hits.clone();
            source_hits.sort_unstable_by_key(|h| {
                (
                    h.offset()
                        .saturating_add(if h.pattern == 9 { 257 } else { 0 }),
                    h.hit_name(),
                )
            });
            let end = hits.last().map_or(base, |h| h.offset().saturating_add(269));
            let mut batch = HitBuffer::new(base, base, end, 11);
            for hit in source_hits {
                batch.push(hit);
            }
            let streamed = HitStorage::single(prepare(batch, true));
            for stream in 0..2 {
                let expected = hits
                    .iter()
                    .filter(|h| usize::from(h.pattern == 13) == stream)
                    .cloned()
                    .collect::<Vec<_>>();
                assert_view(streamed.view(stream), &expected);
            }
        }
    }
    assert!(
        used.into_iter().all(|yes| yes),
        "representations exercised: {used:?}"
    );
    let mut maximum = (0..14)
        .map(|pattern| RawHit::new(u64::MAX, pattern))
        .collect::<Vec<_>>();
    maximum.sort_unstable_by_key(RawHit::hit_name);
    let store = HitStorage::from_hits(&maximum);
    assert_view(store.view(0), &maximum);
}

// Single-window tests cannot expose completion reordering or TAR/XZ facts
// returning into the previous read's tail. Spill also verifies that all
// views borrow the same owner after the mutable slot table is released.
#[test]
fn reordered_read_windows_reconcile_boundaries_and_spill() {
    let chunk = 64 * 1024;
    let chunks = 160;
    let mut builder = Builder::new(chunks as u64 * chunk as u64, chunk, 6).unwrap();
    let mut expected = [Vec::new(), Vec::new()];
    let mut random = 123456789u32;
    for ordinal in (0..chunks).rev() {
        let start = ordinal as u64 * chunk as u64;
        let base = start.saturating_sub(HIT_LOOKBEHIND + 11);
        let mut batch = HitBuffer::new(base, start, start + chunk as u64, 11);
        let mut source_hits = Vec::new();
        for i in 0..10000 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let offset = start + (random as u64 % chunk as u64);
            let pattern = (i % 14) as u8;
            source_hits.push(RawHit::new(offset, pattern));
            expected[usize::from(pattern == 13)].push(RawHit::new(offset, pattern));
        }
        if ordinal != 0 {
            for (distance, pattern) in [(1, 9), (11, 13), (257, 9), (268, 9)] {
                let hit = RawHit::new(start - distance, pattern);
                source_hits.push(hit.clone());
                expected[usize::from(pattern == 13)].push(hit);
            }
        }
        source_hits.sort_unstable_by_key(|h| {
            (
                h.offset() + if h.pattern == 9 { 257 } else { 0 },
                h.hit_name(),
            )
        });
        for hit in source_hits {
            batch.push(hit);
        }
        builder.push(prepare(batch, ordinal + 1 == chunks)).unwrap();
    }
    builder.arena.spill().unwrap();
    let store = builder.finish().unwrap();
    assert!(matches!(store.data, Blob::Mapped(_)));
    for (stream, hits) in expected.iter_mut().enumerate() {
        hits.sort_unstable_by_key(|h| (h.offset(), h.hit_name()));
        // Exhaustive random access is covered above; sample the large spill
        // and compare its complete sequential and masked parallel views.
        let view = store.view(stream);
        assert_eq!(view.iter().collect::<Vec<_>>(), *hits);
        for i in (0..hits.len()).step_by(997) {
            assert_eq!(view.get(i).as_ref(), hits.get(i));
            let offset = hits[i].offset();
            assert_eq!(
                view.lower_bound(offset),
                hits.partition_point(|h| h.offset() < offset)
            );
        }
        let mut parallel = view.par_iter_mask(TAGS).collect::<Vec<_>>();
        parallel.sort_unstable_by_key(|h| (h.offset(), h.hit_name()));
        assert_eq!(parallel, *hits);
    }
}

// Dense blocks exercise data spill but have tiny top-level directories.
// A sparse logical file needs its directory to spill independently while
// the unused footer stream must remain a valid empty borrowed view.
#[test]
fn sparse_directory_spill_preserves_an_empty_secondary_stream() {
    let chunk = 65536;
    let chunks = 45000;
    let mut builder = Builder::new(chunks as u64 * chunk, chunk as usize, 6).unwrap();
    for ordinal in (0..chunks).rev() {
        let start = ordinal as u64 * chunk;
        let mut batch = HitBuffer::new(start, start, start + chunk, 11);
        batch.push(RawHit::new(start + 1000, 8));
        batch.push(RawHit::new(start + chunk - 1, 5));
        builder.push(prepare(batch, ordinal + 1 == chunks)).unwrap();
    }
    let store = builder.finish().unwrap();
    assert!(matches!(store.dirs[0], Blob::Mapped(_)));
    assert!(matches!(store.dirs[1], Blob::Memory(_)));
    assert_eq!(store.view(1).iter().count(), 0);
    let view = store.view(0);
    assert_eq!(view.len(), chunks * 2);
    for ordinal in (0..chunks).step_by(997) {
        let offset = ordinal as u64 * chunk + 1000;
        assert_eq!(view.lower_bound(offset), ordinal * 2);
        assert_eq!(view.get(ordinal * 2), Some(RawHit::new(offset, 8)));
        assert_eq!(
            view.get(ordinal * 2 + 1),
            Some(RawHit::new((ordinal as u64 + 1) * chunk - 1, 5))
        );
    }
}
