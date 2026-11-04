// Appended ONLY to a copied production hit_storage.rs by profile_hooks.py.
impl HitStorage {
    pub(super) fn benchmark_storage_profile(&self, universe: u64) -> io::Result<serde_json::Value> {
        use std::collections::BTreeMap;
        let mut codecs = [0usize; 8];
        let mut codec_hits = [0usize; 8];
        let mut counts = [0usize; 14];
        let mut gaps = BTreeMap::<u64, usize>::new();
        let (mut segments, mut leaves, mut leaf_dirs, mut positions, mut types, mut mixed) = (0,0,0,0,0,0);
        let (mut sparse_leaves, mut sparse_exceptions) = (0,0);
        let mut hits = 0usize;
        for stream in 0..2 {
            let view = self.view(stream);
            segments += view.segments();
            let mut previous = 0;
            for hit in view.iter() {
                hits += 1;
                counts[hit.pattern as usize] += 1;
                *gaps.entry(hit.offset() - previous).or_default() += 1;
                previous = hit.offset();
            }
            for si in 0..view.segments() {
                let segment = view.segment(si);
                let is_directory = segment.control as u32 & 7 == LEAVES;
                let nleaf = if is_directory { view.leaf_count(segment) } else { 1 };
                if is_directory { leaf_dirs += 16 + nleaf * descriptor_size(segment.control as u32); }
                for li in 0..nleaf {
                    let (leaf, n, body) = view.leaf(segment, li);
                    let ctl = leaf.control;
                    let codec = (ctl & 7) as usize;
                    let width = (ctl >> 3) & 31;
                    leaves += 1;
                    codecs[codec] += 1;
                    codec_hits[codec] += n;
                    if codec == RAW as usize { mixed += n * 4; continue; }
                    if codec == GROUP as usize { mixed += group_masks(body, width) + group_count(body) * 3; continue; }
                    let pos = match ctl & 7 {
                        AR => 8,
                        FOR => 8 + bit_bytes(n, width),
                        EF => 48 + bit_bytes(n, width),
                        PATCH => patch_types(body, n, width),
                        BITMAP if ctl & RUNS != 0 => 8 + small(body, 4) as usize * 8,
                        BITMAP => bitmap_start(body) + bitmap_words(body) * 8,
                        _ => unreachable!(),
                    };
                    positions += pos;
                    types += if ctl & SPARSE_TYPES != 0 {
                        let exceptions = small(body, pos + 4) as usize;
                        sparse_leaves += 1;
                        sparse_exceptions += exceptions;
                        8 + exceptions * position_width(n) + bit_bytes(exceptions, 4)
                    } else { bit_bytes(n, (ctl >> TYPE_SHIFT) & 7) };
                }
            }
        }
        let dirs = self.dirs.iter().map(|x| x.len()).sum::<usize>();
        let data = self.data.len();
        let accounted = leaf_dirs + positions + types + mixed;
        if accounted > data { return Err(io::Error::other("storage accounting exceeds actual bytes")); }
        let [segment_padding, staging_descriptors, staging_boundaries] = super::benchmark_profile::space_snapshot();
        let staging = staging_descriptors + staging_boundaries;
        if accounted + staging + segment_padding > data {
            return Err(io::Error::other("storage staging accounting exceeds actual bytes"));
        }
        // Includes alignment between leaves; the single-batch fast path can
        // also align its two streams without passing Builder::write_segment.
        let padding = data - accounted - staging;
        let blobs = [&self.data, &self.dirs[0], &self.dirs[1]];
        let heap = blobs.iter().map(|b| match b { Blob::Memory(v) => v.capacity(), _ => 0 }).sum::<usize>();
        let mapped = blobs.iter().map(|b| match b { Blob::Mapped(_) => b.len(), _ => 0 }).sum::<usize>();
        // Constructive lossless size witness; not a random-access replacement.
        // Include 3 lengths so the compressed stream is independently decodable.
        let mut serialized = Vec::with_capacity(data + dirs + 24);
        for blob in blobs { serialized.extend_from_slice(&(blob.len() as u64).to_le_bytes()); }
        for blob in blobs { serialized.extend_from_slice(blob); }
        let compressed = zstd::stream::encode_all(serialized.as_slice(), 3)?;
        if zstd::stream::decode_all(compressed.as_slice())? != serialized {
            return Err(io::Error::other("compressed storage witness failed round trip"));
        }
        fn h0(values: impl Iterator<Item=usize>, total: usize) -> f64 {
            values.filter(|&n| n != 0).map(|n| n as f64 * (total as f64 / n as f64).log2()).sum()
        }
        fn multiset_bits(u: u64, n: usize) -> f64 {
            if n == 0 || u <= 1 { return 0.0; }
            // log2 binomial(u+n-1,n), avoiding cancellation in log-factorials.
            (1..=n).map(|i| ((u - 1) as f64 / i as f64).ln_1p() / std::f64::consts::LN_2).sum()
        }
        Ok(serde_json::json!({"hits": hits, "bytes": data + dirs, "data_bytes": data,
            "top_directory_bytes": dirs, "leaf_directory_bytes": leaf_dirs,
            "position_bytes": positions, "type_bytes": types, "mixed_tuple_bytes": mixed,
            "alignment_bytes": padding, "segment_alignment_bytes": segment_padding,
            "staging_descriptor_bytes": staging_descriptors, "staging_boundary_bytes": staging_boundaries,
            "heap_capacity_bytes": heap, "mapped_bytes": mapped,
            "object_inline_bytes": std::mem::size_of::<Self>(), "cursor_bytes": std::mem::size_of::<Cursor<'_>>(),
            "segments": segments, "leaves": leaves, "codec_leaves": codecs, "codec_hits": codec_hits,
            "sparse_type_leaves": sparse_leaves, "sparse_exceptions": sparse_exceptions,
            "type_counts": counts, "gap_h0_bits": h0(gaps.values().copied(), hits),
            "type_h0_bits": h0(counts.into_iter(), hits),
            "uniform_multiset_class_bits": counts.into_iter().map(|n| multiset_bits(universe,n)).sum::<f64>(),
            "zstd3_with_lengths_bytes": compressed.len(), "zstd_roundtrip": true}))
    }
}
