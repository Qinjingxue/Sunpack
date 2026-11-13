//! Private, immutable signature facts. Matching jobs encode their own physical
//! interval; only the bounded lookbehind at a read boundary needs reconciliation.
//! Offsets remain u64. All spill files belong to one scan and use scratch.rs.
//!
//! Each physical segment has one representation or a rank/last-offset leaf
//! directory. A fixed directory permits rank/128; adaptive leaves retain their
//! cumulative ranks. Leaf offsets use u32 only when both body and ranks fit,
//! otherwise the directory widens to u64. This is scan-local private storage.
//! The cost selector includes position checkpoints, type evidence and padding;
//! GROUP is permitted only when its type masks preserve every original tuple.
use super::{PackedHit, RawHit, HIT_LOOKBEHIND, HIT_OFFSET_MASK, PATTERNS};
use crate::io::scratch::{Blob, Slots, Spool, MEMORY_BYTES};
use rayon::prelude::*;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::ManuallyDrop;

const LEAF: usize = 128;
const RAW: u32 = 0;
const AR: u32 = 1;
const FOR: u32 = 2;
const EF: u32 = 3;
const LEAVES: u32 = 4;
const DESC_BYTES: usize = 16;
const PATCH: u32 = 5;
const BITMAP: u32 = 6;
const GROUP: u32 = 7;
const SPARSE_TYPES: u32 = 1 << 25;
const RUNS: u32 = 1 << 30;
const WIDE: u32 = 1 << 31;
const CHECKPOINT: usize = 8;
const FIXED: u32 = 1 << 29;
const SEG_BYTES: usize = 48;
const TAG_SHIFT: u32 = 11;
const TYPE_SHIFT: u32 = 8;
const TAGS: u16 = ((1u32 << (PATTERNS.len() + 1)) - 1) as u16;

#[inline(always)]
fn word(data: &[u8], pos: usize) -> u64 {
    u64::from_ne_bytes(data[pos..pos + 8].try_into().unwrap())
}
#[inline(always)]
fn small(data: &[u8], pos: usize) -> u32 {
    u32::from_ne_bytes(data[pos..pos + 4].try_into().unwrap())
}
fn relative(hit: PackedHit) -> u32 {
    u32::from_ne_bytes(hit.0) >> 4
}
fn tag(hit: PackedHit) -> u8 {
    (u32::from_ne_bytes(hit.0) & 15) as u8
}
fn bits(value: u32) -> u32 {
    32 - value.leading_zeros()
}
fn bit_bytes(count: usize, width: u32) -> usize {
    (count * width as usize).div_ceil(64) * 8
}
fn mask(control: u32) -> u16 {
    ((control >> TAG_SHIFT) as u16) & TAGS
}
fn type_width(tags: u16) -> u32 {
    bits(tags.count_ones() - 1)
}
fn control(codec: u32, width: u32, tags: u16) -> u32 {
    codec | (width << 3) | (type_width(tags) << TYPE_SHIFT) | ((tags as u32) << TAG_SHIFT)
}
fn get_bits(data: &[u8], index: usize, width: u32) -> u32 {
    if width == 0 {
        return 0;
    }
    let bit = index * width as usize;
    let shift = bit % 64;
    let pos = bit / 64 * 8;
    let mut value = word(data, pos) >> shift;
    if shift + width as usize > 64 {
        value |= word(data, pos + 8) << (64 - shift);
    }
    (value & ((1u64 << width) - 1)) as u32
}
fn palette(tags: u16) -> [u8; 16] {
    let mut out = [0; 16];
    let mut tags = tags;
    let mut i = 0;
    while tags != 0 {
        out[i] = tags.trailing_zeros() as u8;
        tags &= tags - 1;
        i += 1;
    }
    out
}
fn pack_stream(data: &mut [u8], n: usize, width: u32, mut value: impl FnMut(usize) -> u32) {
    if width == 0 {
        return;
    }
    let (mut accumulator, mut used, mut at) = (0u64, 0u32, 0usize);
    for i in 0..n {
        let v = value(i) as u64;
        accumulator |= v << used;
        let total = used + width;
        if total >= 64 {
            data[at..at + 8].copy_from_slice(&accumulator.to_ne_bytes());
            at += 8;
            accumulator = if total == 64 { 0 } else { v >> (64 - used) };
        }
        used = total % 64;
    }
    if used != 0 {
        data[at..at + 8].copy_from_slice(&accumulator.to_ne_bytes());
    }
}
fn position_width(n: usize) -> usize {
    if n <= 256 {
        1
    } else if n <= 65536 {
        2
    } else {
        4
    }
}
fn read_position(data: &[u8], i: usize, width: usize) -> usize {
    match width {
        1 => data[i] as usize,
        2 => u16::from_ne_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()) as usize,
        _ => small(data, i * 4) as usize,
    }
}
#[derive(Clone, Copy)]
struct TypePlan {
    tags: u16,
    dominant: u8,
    exceptions: usize,
    bytes: usize,
    sparse: bool,
}
impl TypePlan {
    fn new<T: Copy + Into<usize>>(n: usize, counts: &[T; 16]) -> Self {
        let mut tags = 0;
        let mut dominant = 0;
        for i in 0..14 {
            if counts[i].into() != 0 {
                tags |= 1 << i;
            }
            if counts[i].into() > counts[dominant].into() {
                dominant = i;
            }
        }
        let exceptions = n - counts[dominant].into();
        let dense = bit_bytes(n, type_width(tags));
        let sparse = 8 + exceptions * position_width(n) + bit_bytes(exceptions, 4);
        let use_sparse = n <= u32::MAX as usize && sparse < dense;
        Self {
            tags,
            dominant: dominant as u8,
            exceptions,
            bytes: if use_sparse { sparse } else { dense },
            sparse: use_sparse,
        }
    }
    fn ctl(self, codec: u32, width: u32) -> u32 {
        control(codec, width, self.tags) | if self.sparse { SPARSE_TYPES } else { 0 }
    }
}
fn encode_types(data: &mut [u8], hits: &[PackedHit], plan: TypePlan) {
    if plan.sparse {
        data[0] = plan.dominant;
        data[4..8].copy_from_slice(&(plan.exceptions as u32).to_ne_bytes());
        let w = position_width(hits.len());
        let tag_pos = 8 + plan.exceptions * w;
        let mut rank = 0;
        for (i, &hit) in hits.iter().enumerate() {
            if tag(hit) != plan.dominant {
                let bytes = (i as u32).to_ne_bytes();
                data[8 + rank * w..8 + (rank + 1) * w].copy_from_slice(&bytes[..w]);
                data[tag_pos + rank / 2] |= tag(hit) << ((rank & 1) * 4);
                rank += 1;
            }
        }
    } else {
        let width = type_width(plan.tags);
        if width == 4 {
            pack_stream(data, hits.len(), 4, |i| tag(hits[i]) as u32);
        } else if width != 0 {
            pack_stream(data, hits.len(), width, |i| {
                (plan.tags & ((1 << tag(hits[i])) - 1)).count_ones()
            });
        }
    }
}
fn decode_type(data: &[u8], n: usize, i: usize, control: u32) -> u8 {
    if control & SPARSE_TYPES != 0 {
        let count = small(data, 4) as usize;
        let w = position_width(n);
        let positions = &data[8..];
        let mut lo = 0;
        let mut hi = count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if read_position(positions, mid, w) < i {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return if lo < count && read_position(positions, lo, w) == i {
            get_bits(&data[8 + count * w..], lo, 4) as u8
        } else {
            data[0]
        };
    }
    let width = (control >> TYPE_SHIFT) & 7;
    if width == 0 {
        mask(control).trailing_zeros() as u8
    } else if width == 4 {
        get_bits(data, i, width) as u8
    } else {
        select_type(mask(control), get_bits(data, i, width) as usize)
    }
}
fn select_type(tags: u16, rank: usize) -> u8 {
    let low = tags as u8;
    let count = low.count_ones() as usize;
    if rank < count {
        BYTE_SELECT[low as usize][rank]
    } else {
        8 + BYTE_SELECT[(tags >> 8) as usize][rank - count]
    }
}
fn decode_types(data: &[u8], n: usize, begin: usize, out: &mut [u8], ctl: u32) {
    if ctl & SPARSE_TYPES != 0 {
        out.fill(data[0]);
        let count = small(data, 4) as usize;
        let w = position_width(n);
        let positions = &data[8..];
        let mut lo = 0;
        let mut hi = count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if read_position(positions, mid, w) < begin {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        while lo < count {
            let rank = read_position(positions, lo, w);
            if rank >= begin + out.len() {
                break;
            }
            out[rank - begin] = get_bits(&data[8 + count * w..], lo, 4) as u8;
            lo += 1;
        }
        return;
    }
    let width = (ctl >> TYPE_SHIFT) & 7;
    if width == 0 {
        out.fill(mask(ctl).trailing_zeros() as u8);
    } else if width == 4 {
        for (i, value) in out.iter_mut().enumerate() {
            let rank = begin + i;
            *value = (data[rank / 2] >> ((rank & 1) * 4)) & 15;
        }
    } else {
        let table = palette(mask(ctl));
        for (i, value) in out.iter_mut().enumerate() {
            *value = table[get_bits(data, begin + i, width) as usize];
        }
    }
}

const BYTE_SELECT: [[u8; 8]; 256] = {
    let mut table = [[0; 8]; 256];
    let mut byte = 0usize;
    while byte < 256 {
        let mut rank = 0;
        let mut bit = 0;
        while bit < 8 {
            if byte & (1 << bit) != 0 {
                table[byte][rank] = bit as u8;
                rank += 1;
            }
            bit += 1;
        }
        byte += 1;
    }
    table
};
// Portable broadword byte prefixes plus a 2 KiB byte-select table. Avoid six
// dependent popcounts/branches and CPU-specific assumptions about PDEP speed.
fn select_word(value: u64, rank: u32) -> u32 {
    let pairs = value - ((value >> 1) & 0x5555_5555_5555_5555);
    let nibbles = (pairs & 0x3333_3333_3333_3333) + ((pairs >> 2) & 0x3333_3333_3333_3333);
    let bytes = (nibbles + (nibbles >> 4)) & 0x0f0f_0f0f_0f0f_0f0f;
    let prefix = bytes.wrapping_mul(0x0101_0101_0101_0101);
    let target = (rank as u64 + 1) * 0x0101_0101_0101_0101;
    // The high guard bits prevent subtraction borrowing across byte lanes.
    let lanes = ((prefix | 0x8080_8080_8080_8080) - target) & 0x8080_8080_8080_8080;
    let byte = lanes.trailing_zeros() / 8;
    let before = if byte == 0 {
        0
    } else {
        (prefix >> ((byte - 1) * 8)) & 255
    };
    byte * 8
        + BYTE_SELECT[((value >> (byte * 8)) & 255) as usize][rank as usize - before as usize]
            as u32
}
fn select(data: &[u8], mut rank: u32, one: bool) -> u32 {
    let len = small(data, 4);
    let prefix = word(data, 8);
    for i in 0..4 {
        let valid = len.saturating_sub(i * 64).min(64);
        if valid == 0 {
            break;
        }
        let ones_before = ((prefix >> (i * 8)) & 255) as u32;
        let before = if one {
            ones_before
        } else {
            i * 64 - ones_before
        };
        let ones_after = ((prefix >> ((i + 1) * 8)) & 255) as u32;
        let after = if one {
            ones_after
        } else {
            i * 64 + valid - ones_after
        };
        if rank >= before && rank < after {
            let mut value = word(data, 16 + i as usize * 8);
            if !one {
                value = !value;
            }
            if valid < 64 {
                value &= (1u64 << valid) - 1;
            }
            rank -= before;
            return i * 64 + select_word(value, rank);
        }
    }
    unreachable!("rank outside the private EF bitvector")
}

#[derive(Clone, Copy)]
struct Leaf {
    offset: u64,
    end: u64,
    last: u32,
    control: u32,
}
impl Leaf {
    #[inline(always)]
    fn read(data: &[u8], wide: bool) -> Self {
        if wide {
            Self {
                offset: word(data, 0),
                end: word(data, 8),
                last: small(data, 16),
                control: small(data, 20),
            }
        } else {
            Self {
                offset: small(data, 0) as u64,
                end: small(data, 4) as u64,
                last: small(data, 8),
                control: small(data, 12),
            }
        }
    }
    fn write(self, out: &mut Vec<u8>, wide: bool) {
        if wide {
            out.extend_from_slice(&self.offset.to_ne_bytes());
            out.extend_from_slice(&self.end.to_ne_bytes());
        } else {
            out.extend_from_slice(&(self.offset as u32).to_ne_bytes());
            out.extend_from_slice(&(self.end as u32).to_ne_bytes());
        }
        out.extend_from_slice(&self.last.to_ne_bytes());
        out.extend_from_slice(&self.control.to_ne_bytes());
    }
}
fn descriptor_size(control: u32) -> usize {
    if control & WIDE != 0 {
        24
    } else {
        DESC_BYTES
    }
}
#[derive(Clone, Copy, Default)]
struct Segment {
    base: u64,
    end: u64,
    count: u64,
    payload: u64,
    last: u64,
    control: u64,
}
impl Segment {
    #[inline(always)]
    fn read(data: &[u8]) -> Self {
        Self {
            base: word(data, 0),
            end: word(data, 8),
            count: word(data, 16),
            payload: word(data, 24),
            last: word(data, 32),
            control: word(data, 40),
        }
    }
    fn bytes(self) -> [u8; SEG_BYTES] {
        let mut out = [0; SEG_BYTES];
        for (bytes, value) in out.chunks_exact_mut(8).zip([
            self.base,
            self.end,
            self.count,
            self.payload,
            self.last,
            self.control,
        ]) {
            bytes.copy_from_slice(&value.to_ne_bytes());
        }
        out
    }
}

struct Encoded {
    data: Vec<u8>,
    control: u32,
    count: usize,
    last: u32,
}
fn into_bytes(hits: Vec<PackedHit>) -> Vec<u8> {
    let mut hits = ManuallyDrop::new(hits);
    // PackedHit is four bytes, align 1, with no padding or invalid bit patterns.
    // Allocation size/alignment are unchanged; ownership transfers exactly once.
    unsafe {
        Vec::from_raw_parts(
            hits.as_mut_ptr().cast(),
            hits.len() * 4,
            hits.capacity() * 4,
        )
    }
}
fn release_slack(mut data: Vec<u8>) -> Vec<u8> {
    // Completed jobs can wait behind other completions. Do not retain their
    // uncompressed allocation merely because encoding happened in place.
    // Keep normal Vec growth slack; shrink only substantial compression.
    let slack = data.capacity() - data.len();
    if slack >= 1024 && slack > data.len() / 8 {
        data.shrink_to_fit();
    }
    data
}

struct Stats {
    tags: u16,
    counts: [u8; 16],
    histogram: [u8; 33],
    patch: bool,
    step: Option<u32>,
    unique: usize,
    repeated_tuples: usize,
    runs: usize,
    max_gap: u32,
    gap_index: usize,
}
impl Stats {
    fn strict_uniform(hits: &[PackedHit]) -> Option<Self> {
        let n = hits.len();
        debug_assert!(n <= LEAF);
        if n < 3 {
            return None;
        }
        let t = tag(hits[0]);
        let mut gaps = [0u32; LEAF];
        let mut at = 1;
        let mut runs = 1;
        #[cfg(target_arch = "x86_64")]
        let mut max_gap;
        #[cfg(not(target_arch = "x86_64"))]
        let mut max_gap = 0;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use std::arch::x86_64::*;
            let tags = _mm_set1_epi32(15);
            let expected = _mm_set1_epi32(t as i32);
            let zero = _mm_setzero_si128();
            let one = _mm_set1_epi32(1);
            let mut maximum = zero;
            let mut run_counts = zero;
            while at + 4 <= n {
                let packed = _mm_loadu_si128(hits.as_ptr().add(at).cast());
                let prior = _mm_srli_epi32::<4>(_mm_loadu_si128(hits.as_ptr().add(at - 1).cast()));
                let delta = _mm_sub_epi32(_mm_srli_epi32::<4>(packed), prior);
                if _mm_movemask_epi8(_mm_cmpeq_epi32(_mm_and_si128(packed, tags), expected))
                    != 65535
                    || _mm_movemask_epi8(_mm_cmpeq_epi32(delta, zero)) != 0
                {
                    return None;
                }
                _mm_storeu_si128(gaps.as_mut_ptr().add(at).cast(), delta);
                run_counts = _mm_sub_epi32(run_counts, _mm_cmpgt_epi32(delta, one));
                let greater = _mm_cmpgt_epi32(delta, maximum);
                maximum = _mm_or_si128(
                    _mm_and_si128(greater, delta),
                    _mm_andnot_si128(greater, maximum),
                );
                at += 4;
            }
            let mut lanes = [0u32; 4];
            _mm_storeu_si128(lanes.as_mut_ptr().cast(), maximum);
            max_gap = lanes.into_iter().max().unwrap();
            _mm_storeu_si128(lanes.as_mut_ptr().cast(), run_counts);
            runs += lanes.into_iter().sum::<u32>() as usize;
        }
        while at < n {
            let gap = relative(hits[at]) - relative(hits[at - 1]);
            if tag(hits[at]) != t || gap == 0 {
                return None;
            }
            gaps[at] = gap;
            runs += usize::from(gap > 1);
            max_gap = max_gap.max(gap);
            at += 1;
        }
        let mut counts = [0; 16];
        counts[t as usize] = n as u8;
        let mut s = Self {
            tags: 1 << t,
            counts,
            histogram: [0; 33],
            patch: true,
            step: None,
            unique: n,
            repeated_tuples: 0,
            runs,
            max_gap,
            gap_index: 0,
        };
        let span = relative(hits[n - 1]) - relative(hits[0]);
        let words = (span as usize + 1).div_ceil(64);
        let bitmap_bytes = (8 + (words + 1) * 2).next_multiple_of(8) + words * 8;
        let patch_min = 8 + bit_bytes(n, 1) + bit_bytes(n.div_ceil(CHECKPOINT), bits(span));
        // Strict gaps need at least one bit. Width zero would need n-1
        // five-byte exceptions and cannot beat this bound for n >= 3.
        // Equality retains PATCH's existing tie-break. Split sides with an
        // omitted histogram are recomputed by without(), never subtracted.
        s.patch = bitmap_bytes >= patch_min;
        if !s.patch {
            if max_gap as u64 * 4 > span as u64 {
                s.gap_index = gaps[..n].iter().position(|&gap| gap == max_gap).unwrap();
            }
            return Some(s);
        }
        s.histogram[0] = 1;
        let mut histograms = [[0u8; 33]; 4];
        // Independent counters avoid a read-modify-write chain when most gaps
        // fall in the same bucket. Each lane receives at most LEAF/4 values.
        let mut i = 1;
        while i + 4 <= n {
            for lane in 0..4 {
                histograms[lane][bits(gaps[i + lane]) as usize] += 1;
            }
            i += 4;
        }
        for gap in &gaps[i..n] {
            s.histogram[bits(*gap) as usize] += 1;
        }
        for histogram in histograms {
            for (total, count) in s.histogram.iter_mut().zip(histogram) {
                *total += count;
            }
        }
        if max_gap as u64 * 4 > span as u64 {
            s.gap_index = gaps[..n].iter().position(|&gap| gap == max_gap).unwrap();
        }
        Some(s)
    }
    fn new(hits: &[PackedHit]) -> Self {
        if let Some((_, step, t)) = uniform_arithmetic(hits) {
            let n = hits.len();
            let mut counts = [0; 16];
            counts[t as usize] = n as u8;
            let mut histogram = [0; 33];
            histogram[0] = 1;
            histogram[bits(step) as usize] += (n - 1) as u8;
            return Self {
                tags: 1 << t,
                counts,
                histogram,
                patch: true,
                step: Some(step),
                unique: if step == 0 { 1 } else { n },
                repeated_tuples: if step == 0 { n - 1 } else { 0 },
                runs: if step <= 1 { 1 } else { n },
                max_gap: step,
                gap_index: usize::from(step != 0),
            };
        }
        if let Some(stats) = Self::strict_uniform(hits) {
            return stats;
        }
        let step = (hits.len() > 1).then(|| relative(hits[1]) - relative(hits[0]));
        let mut s = Self {
            tags: 0,
            counts: [0; 16],
            histogram: [0; 33],
            patch: true,
            step,
            unique: 0,
            repeated_tuples: 0,
            runs: 0,
            max_gap: 0,
            gap_index: 0,
        };
        let (mut previous, mut group_tags, mut run_step, mut run_len) =
            (relative(hits[0]), 0u16, None, 0usize);
        for (i, &hit) in hits.iter().enumerate() {
            let value = relative(hit);
            let t = tag(hit);
            let gap = value - previous;
            s.tags |= 1 << t;
            s.counts[t as usize] += 1;
            s.histogram[bits(gap) as usize] += 1;
            if i != 0 && Some(gap) != step {
                s.step = None;
            }
            if i == 0 || gap != 0 {
                s.unique += 1;
                group_tags = 0;
            } else if group_tags & (1 << t) != 0 {
                s.repeated_tuples += 1;
            }
            group_tags |= 1 << t;
            if i == 0 || gap > 1 || (run_len > 1 && run_step != Some(gap)) {
                s.runs += 1;
                run_len = 1;
                run_step = None;
            } else {
                run_step = Some(gap);
                run_len += 1;
            }
            if gap > s.max_gap {
                s.max_gap = gap;
                s.gap_index = i;
            }
            previous = value;
        }
        s
    }
    fn without(&self, known: &Self, removed_gap: u32, hits: &[PackedHit]) -> Self {
        if !self.patch || !known.patch {
            return Self::new(hits);
        }
        // A gap > 1 starts a new position group and run. Counts, duplicate
        // occurrences and run counts are therefore additive across this cut.
        // Each standalone side replaces the boundary gap by a first zero gap.
        debug_assert!(removed_gap > 1 && !hits.is_empty());
        let mut counts = [0; 16];
        let mut tags = 0;
        for i in 0..16 {
            counts[i] = self.counts[i] - known.counts[i];
            if counts[i] != 0 {
                tags |= 1 << i;
            }
        }
        let mut histogram = self.histogram;
        histogram[0] += 1;
        for (value, count) in histogram.iter_mut().zip(known.histogram) {
            *value -= count;
        }
        histogram[bits(removed_gap) as usize] -= 1;
        let width = histogram.iter().rposition(|&n| n != 0).unwrap();
        Self {
            tags,
            counts,
            histogram,
            patch: true,
            step: if hits.len() > 1 {
                arithmetic_offsets(hits)
            } else {
                None
            },
            unique: self.unique - known.unique,
            repeated_tuples: self.repeated_tuples - known.repeated_tuples,
            runs: self.runs - known.runs,
            // Only choose() consumes these cost statistics. No recursive cut
            // is offered; the histogram supplies a sufficient gap-width bound.
            max_gap: ((1u64 << width) - 1) as u32,
            gap_index: 0,
        }
    }
}
#[derive(Clone, Copy)]
struct Plan {
    leaf: Leaf,
    n: usize,
    bytes: usize,
    types: TypePlan,
}
fn choose(hits: &[PackedHit], s: &Stats) -> Plan {
    let n = hits.len();
    let first = relative(hits[0]);
    let last = relative(hits[n - 1]);
    let span = last - first;
    let types = TypePlan::new(n, &s.counts);
    let mut ctl = control(RAW, 0, s.tags);
    let mut bytes = n * 4;
    let mut consider = |candidate: u32, size: usize| {
        if size < bytes {
            ctl = candidate;
            bytes = size;
        }
    };
    if s.step.is_some() {
        consider(types.ctl(AR, 0), 8 + types.bytes);
    }
    consider(
        types.ctl(FOR, bits(span)),
        8 + bit_bytes(n, bits(span)) + types.bytes,
    );
    let low = bits(span / n as u32);
    consider(types.ctl(EF, low), 48 + bit_bytes(n, low) + types.bytes);
    let mut covered = 0;
    let mut best_gap = (0, usize::MAX);
    for width in 0..if s.patch {
        bits(s.max_gap) as usize + 1
    } else {
        0
    } {
        covered += s.histogram[width] as usize;
        if width != 0 && s.histogram[width] == 0 {
            continue;
        }
        let size = 8
            + bit_bytes(n, width as u32)
            + (n - covered) * 5
            + bit_bytes(n.div_ceil(CHECKPOINT), bits(span));
        if size < best_gap.1 {
            best_gap = (width as u32, size);
        }
    }
    if s.patch {
        consider(types.ctl(PATCH, best_gap.0), best_gap.1 + types.bytes);
    }
    consider(types.ctl(BITMAP, 0) | RUNS, 8 + s.runs * 8 + types.bytes);
    if s.unique == n {
        let words = (span as usize + 1).div_ceil(64);
        // Prefix counts fit u16 for every leaf. Bitmap selection never scans
        // a physical address universe whose cost exceeds the other codecs.
        let size = (8 + (words + 1) * 2).next_multiple_of(8) + words * 8;
        consider(types.ctl(BITMAP, 0), size + types.bytes);
    }
    if s.repeated_tuples == 0 && s.unique < n {
        let width = bits(span);
        let size = 8 + bit_bytes(s.unique, width) + s.unique * 3;
        consider(control(GROUP, width, s.tags), size);
    }
    Plan {
        leaf: Leaf {
            offset: 0,
            end: 0,
            last,
            control: ctl,
        },
        n,
        bytes,
        types,
    }
}
fn uniform_arithmetic(hits: &[PackedHit]) -> Option<(u32, u32, u8)> {
    if hits.len() < 3 || tag(hits[0]) != tag(hits[1]) {
        return None;
    }
    let first = small(&hits[0].0, 0);
    let delta = small(&hits[1].0, 0) - first;
    let mut at = 0;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use std::arch::x86_64::*;
        let mut expected = _mm_setr_epi32(
            first as i32,
            first.wrapping_add(delta) as i32,
            first.wrapping_add(delta.wrapping_mul(2)) as i32,
            first.wrapping_add(delta.wrapping_mul(3)) as i32,
        );
        let advance = _mm_set1_epi32(delta.wrapping_mul(4) as i32);
        while at + 4 <= hits.len() {
            let actual = _mm_loadu_si128(hits.as_ptr().add(at).cast());
            if _mm_movemask_epi8(_mm_cmpeq_epi32(actual, expected)) != 65535 {
                return None;
            }
            expected = _mm_add_epi32(expected, advance);
            at += 4;
        }
    }
    while at < hits.len() {
        if small(&hits[at].0, 0) != first.wrapping_add(delta.wrapping_mul(at as u32)) {
            return None;
        }
        at += 1;
    }
    Some((first >> 4, delta >> 4, tag(hits[0])))
}
fn arithmetic_offsets(hits: &[PackedHit]) -> Option<u32> {
    let first = relative(hits[0]);
    let step = relative(hits[1]) - first;
    let mut at = 0;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use std::arch::x86_64::*;
        let mut expected = _mm_setr_epi32(
            first as i32,
            (first + step) as i32,
            first.wrapping_add(step.wrapping_mul(2)) as i32,
            first.wrapping_add(step.wrapping_mul(3)) as i32,
        );
        let advance = _mm_set1_epi32(step.wrapping_mul(4) as i32);
        while at + 4 <= hits.len() {
            let actual = _mm_srli_epi32::<4>(_mm_loadu_si128(hits.as_ptr().add(at).cast()));
            if _mm_movemask_epi8(_mm_cmpeq_epi32(actual, expected)) != 65535 {
                return None;
            }
            expected = _mm_add_epi32(expected, advance);
            at += 4;
        }
    }
    while at < hits.len() {
        if relative(hits[at]) != first.wrapping_add(step.wrapping_mul(at as u32)) {
            return None;
        }
        at += 1;
    }
    Some(step)
}
fn gap_at(data: &[u8], n: usize, width: u32, i: usize) -> u32 {
    if width == 0 {
        return 0;
    }
    if n != 128 {
        return get_bits(data, i, width);
    }
    let bit = (i / 4) as u32 * width;
    let at = (bit / 32) as usize * 16 + (i % 4) * 4;
    let shift = bit % 32;
    let mut v = small(data, at) >> shift;
    if shift + width > 32 {
        v |= small(data, at + 16) << (32 - shift);
    }
    v & ((1 << width) - 1)
}
fn pack_gaps(data: &mut [u8], gaps: &[u32; LEAF], n: usize, width: u32) {
    if width == 0 {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if n == 128 {
        unsafe {
            use std::arch::x86_64::*;
            let (mut accumulator, mut used, mut at) = (_mm_setzero_si128(), 0u32, 0usize);
            for i in 0..32 {
                let v = _mm_loadu_si128(gaps.as_ptr().add(i * 4).cast());
                accumulator = _mm_or_si128(
                    accumulator,
                    _mm_sll_epi32(v, _mm_cvtsi32_si128(used as i32)),
                );
                let total = used + width;
                if total >= 32 {
                    _mm_storeu_si128(data.as_mut_ptr().add(at).cast(), accumulator);
                    at += 16;
                    accumulator = if total == 32 {
                        _mm_setzero_si128()
                    } else {
                        _mm_srl_epi32(v, _mm_cvtsi32_si128((32 - used) as i32))
                    };
                }
                used = total % 32;
            }
            debug_assert_eq!(at, width as usize * 16);
        }
        return;
    }
    if n == 128 {
        for i in 0..n {
            let bit = (i / 4) as u32 * width;
            let at = (bit / 32) as usize * 16 + (i % 4) * 4;
            let shift = bit % 32;
            let v = small(data, at) | (gaps[i] << shift);
            data[at..at + 4].copy_from_slice(&v.to_ne_bytes());
            if shift + width > 32 {
                let v = small(data, at + 16) | (gaps[i] >> (32 - shift));
                data[at + 16..at + 20].copy_from_slice(&v.to_ne_bytes());
            }
        }
    } else {
        pack_stream(data, n, width, |i| gaps[i]);
    }
}
fn decode_gaps(data: &[u8], n: usize, width: u32, out: &mut [u32; LEAF]) {
    if width == 0 {
        out[..n].fill(0);
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if n == 128 {
        unsafe {
            use std::arch::x86_64::*;
            let mask = _mm_set1_epi32(((1 << width) - 1) as i32);
            for i in 0..32 {
                let bit = i as u32 * width;
                let at = (bit / 32) as usize * 16;
                let shift = bit % 32;
                let mut v = _mm_srl_epi32(
                    _mm_loadu_si128(data.as_ptr().add(at).cast()),
                    _mm_cvtsi32_si128(shift as i32),
                );
                if shift + width > 32 {
                    v = _mm_or_si128(
                        v,
                        _mm_sll_epi32(
                            _mm_loadu_si128(data.as_ptr().add(at + 16).cast()),
                            _mm_cvtsi32_si128((32 - shift) as i32),
                        ),
                    );
                }
                _mm_storeu_si128(out.as_mut_ptr().add(i * 4).cast(), _mm_and_si128(v, mask));
            }
        }
        return;
    }
    for (i, v) in out[..n].iter_mut().enumerate() {
        *v = gap_at(data, n, width, i);
    }
}
fn prefix_offsets(out: &mut [u32; LEAF], n: usize, first: u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use std::arch::x86_64::*;
        let mut prior = _mm_set1_epi32(first as i32);
        let full = n / 4;
        for i in 0..full {
            let mut v = _mm_loadu_si128(out.as_ptr().add(i * 4).cast());
            v = _mm_add_epi32(v, _mm_slli_si128::<4>(v));
            v = _mm_add_epi32(v, _mm_slli_si128::<8>(v));
            v = _mm_add_epi32(v, prior);
            _mm_storeu_si128(out.as_mut_ptr().add(i * 4).cast(), v);
            prior = _mm_shuffle_epi32::<255>(v);
        }
        let mut previous = if full == 0 { first } else { out[full * 4 - 1] };
        for v in &mut out[full * 4..n] {
            previous += *v;
            *v = previous;
        }
        return;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut previous = first;
        for v in &mut out[..n] {
            previous += *v;
            *v = previous;
        }
    }
}
fn patch_count(data: &[u8]) -> usize {
    (small(data, 4) & 255) as usize
}
fn checkpoint_width(data: &[u8]) -> u32 {
    (small(data, 4) >> 8) & 31
}
fn patch_types(data: &[u8], n: usize, width: u32) -> usize {
    8 + bit_bytes(n, width)
        + patch_count(data) * 5
        + bit_bytes(n.div_ceil(CHECKPOINT), checkpoint_width(data))
}
fn decode_patch(data: &[u8], n: usize, width: u32, out: &mut [u32; LEAF]) -> usize {
    decode_gaps(&data[8..], n, width, out);
    let mut at = 8 + bit_bytes(n, width);
    for _ in 0..patch_count(data) {
        out[data[at] as usize] = small(data, at + 1);
        at += 5;
    }
    prefix_offsets(out, n, small(data, 0));
    at + bit_bytes(n.div_ceil(CHECKPOINT), checkpoint_width(data))
}
fn patch_range(
    data: &[u8],
    n: usize,
    width: u32,
    begin: usize,
    end: usize,
    out: &mut [u32; CHECKPOINT],
) {
    let count = patch_count(data);
    let patches = 8 + bit_bytes(n, width);
    let checkpoints = patches + count * 5;
    for i in begin..end {
        out[i - begin] = gap_at(&data[8..], n, width, i);
    }
    for k in 0..count {
        let at = patches + k * 5;
        let i = data[at] as usize;
        if i >= end {
            break;
        }
        if i >= begin {
            out[i - begin] = small(data, at + 1);
        }
    }
    let mut previous = if begin == 0 {
        small(data, 0)
    } else {
        small(data, 0)
            + get_bits(
                &data[checkpoints..],
                begin / CHECKPOINT - 1,
                checkpoint_width(data),
            )
    };
    for v in &mut out[..end - begin] {
        previous += *v;
        *v = previous;
    }
}
fn bitmap_words(data: &[u8]) -> usize {
    (small(data, 4) as usize).div_ceil(64)
}
fn bitmap_start(data: &[u8]) -> usize {
    (8 + (bitmap_words(data) + 1) * 2).next_multiple_of(8)
}
fn bitmap_prefix(data: &[u8], i: usize) -> usize {
    u16::from_ne_bytes(data[8 + i * 2..10 + i * 2].try_into().unwrap()) as usize
}
fn bitmap_select(data: &[u8], rank: usize) -> u32 {
    let words = bitmap_words(data);
    let (mut lo, mut hi) = (0, words);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if bitmap_prefix(data, mid + 1) <= rank {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    small(data, 0)
        + lo as u32 * 64
        + select_word(
            word(data, bitmap_start(data) + lo * 8),
            (rank - bitmap_prefix(data, lo)) as u32,
        )
}
fn run_value(data: &[u8], run: usize, rank: usize) -> u32 {
    let value = small(data, 8 + run * 8);
    let begin = if run == 0 {
        0
    } else {
        small(data, 4 + run * 8) as usize
    };
    (value & 0x7fff_ffff)
        + if value >> 31 != 0 {
            0
        } else {
            (rank - begin) as u32
        }
}
fn group_count(data: &[u8]) -> usize {
    small(data, 4) as usize
}
fn group_masks(data: &[u8], width: u32) -> usize {
    8 + bit_bytes(group_count(data), width)
}
fn group_end(data: &[u8], width: u32, i: usize) -> usize {
    data[group_masks(data, width) + i * 3 + 2] as usize
}
const fn type_name(t: usize) -> &'static [u8] {
    if t < PATTERNS.len() {
        PATTERNS[t].1.as_bytes()
    } else {
        b"xz_footer"
    }
}
const fn lexical_order() -> [u8; PATTERNS.len() + 1] {
    let mut order = [0; PATTERNS.len() + 1];
    let mut i = 0;
    while i < order.len() {
        order[i] = i as u8;
        let mut j = i;
        while j > 0 {
            let a = type_name(order[j] as usize);
            let b = type_name(order[j - 1] as usize);
            let mut k = 0;
            while k < a.len() && k < b.len() && a[k] == b[k] {
                k += 1;
            }
            let less = if k == a.len() {
                k < b.len()
            } else {
                k < b.len() && a[k] < b[k]
            };
            if !less {
                break;
            }
            let prior = order[j - 1];
            order[j - 1] = order[j];
            order[j] = prior;
            j -= 1;
        }
        i += 1;
    }
    order
}
const TYPE_ORDER: [u8; PATTERNS.len() + 1] = lexical_order();
fn lexical_type(tags: u16, mut rank: usize) -> u8 {
    for t in TYPE_ORDER {
        if tags & (1 << t) != 0 {
            if rank == 0 {
                return t;
            }
            rank -= 1;
        }
    }
    unreachable!()
}
fn encode_leaf(data: &mut [u8], hits: &[PackedHit], plan: Plan) {
    let ctl = plan.leaf.control;
    let codec = ctl & 7;
    let n = hits.len();
    if codec == RAW {
        for (out, hit) in data.chunks_exact_mut(4).zip(hits) {
            out.copy_from_slice(&hit.0);
        }
        return;
    }
    data.fill(0);
    let first = relative(hits[0]);
    let width = (ctl >> 3) & 31;
    data[..4].copy_from_slice(&first.to_ne_bytes());
    let type_pos = match codec {
        AR => {
            data[4..8].copy_from_slice(&(relative(hits[1]) - first).to_ne_bytes());
            8
        }
        FOR => {
            let end = 8 + bit_bytes(n, width);
            pack_stream(&mut data[8..end], n, width, |i| relative(hits[i]) - first);
            end
        }
        EF => {
            let end = 48 + bit_bytes(n, width);
            let len = n as u32 + ((relative(hits[n - 1]) - first) >> width) + 1;
            data[4..8].copy_from_slice(&len.to_ne_bytes());
            let mut high = [0u64; 4];
            for (i, &hit) in hits.iter().enumerate() {
                let value = relative(hit) - first;
                let bit = (value >> width) as usize + i;
                high[bit / 64] |= 1 << (bit % 64);
            }
            pack_stream(&mut data[48..end], n, width, |i| {
                (relative(hits[i]) - first) & ((1 << width) - 1)
            });
            let mut count = 0u8;
            for (i, v) in high.into_iter().enumerate() {
                data[8 + i] = count;
                data[16 + i * 8..24 + i * 8].copy_from_slice(&v.to_ne_bytes());
                count += v.count_ones() as u8;
            }
            data[12] = count;
            end
        }
        PATCH => {
            let mut gaps = [0u32; LEAF];
            let mut previous = first;
            let mut at = 8 + bit_bytes(n, width);
            let mut exceptions = 0u32;
            for (i, &hit) in hits.iter().enumerate() {
                let value = relative(hit);
                let gap = value - previous;
                previous = value;
                gaps[i] = gap & ((1 << width) - 1);
                if bits(gap) > width {
                    data[at] = i as u8;
                    data[at + 1..at + 5].copy_from_slice(&gap.to_ne_bytes());
                    at += 5;
                    exceptions += 1;
                }
            }
            let cw = bits(relative(hits[n - 1]) - first);
            data[4..8].copy_from_slice(&(exceptions | (cw << 8)).to_ne_bytes());
            pack_gaps(&mut data[8..], &gaps, n, width);
            let groups = n.div_ceil(CHECKPOINT);
            pack_stream(&mut data[at..], groups, cw, |i| {
                relative(hits[((i + 1) * CHECKPOINT).min(n) - 1]) - first
            });
            at + bit_bytes(groups, cw)
        }
        BITMAP if ctl & RUNS != 0 => {
            let mut begin = 0;
            let mut count = 0;
            while begin < n {
                let value = relative(hits[begin]);
                let mut end = begin + 1;
                let step = if end < n {
                    relative(hits[end]) - value
                } else {
                    2
                };
                if step <= 1 {
                    while end < n && relative(hits[end]) - relative(hits[end - 1]) == step {
                        end += 1;
                    }
                }
                let start = value | if step == 0 { 1 << 31 } else { 0 };
                let at = 8 + count * 8;
                data[at..at + 4].copy_from_slice(&start.to_ne_bytes());
                data[at + 4..at + 8].copy_from_slice(&(end as u32).to_ne_bytes());
                count += 1;
                begin = end;
            }
            data[4..8].copy_from_slice(&(count as u32).to_ne_bytes());
            8 + count * 8
        }
        BITMAP => {
            let len = relative(hits[n - 1]) - first + 1;
            data[4..8].copy_from_slice(&len.to_ne_bytes());
            let start = bitmap_start(data);
            let words = bitmap_words(data);
            for &hit in hits {
                let v = (relative(hit) - first) as usize;
                let at = start + v / 64 * 8;
                let x = word(data, at) | (1 << (v % 64));
                data[at..at + 8].copy_from_slice(&x.to_ne_bytes());
            }
            let mut count = 0u16;
            for i in 0..words {
                data[8 + i * 2..10 + i * 2].copy_from_slice(&count.to_ne_bytes());
                count += word(data, start + i * 8).count_ones() as u16;
            }
            data[8 + words * 2..10 + words * 2].copy_from_slice(&count.to_ne_bytes());
            start + words * 8
        }
        GROUP => {
            let mut offsets = [0u32; LEAF];
            let mut masks = [0u16; LEAF];
            let mut ends = [0u8; LEAF];
            let mut count = 0;
            for (i, &hit) in hits.iter().enumerate() {
                let value = relative(hit);
                if count == 0 || offsets[count - 1] != value {
                    offsets[count] = value;
                    count += 1;
                }
                masks[count - 1] |= 1 << tag(hit);
                ends[count - 1] = (i + 1) as u8;
            }
            data[4..8].copy_from_slice(&(count as u32).to_ne_bytes());
            let end = 8 + bit_bytes(count, width);
            pack_stream(&mut data[8..end], count, width, |i| offsets[i] - first);
            for i in 0..count {
                data[end + i * 3..end + i * 3 + 2].copy_from_slice(&masks[i].to_ne_bytes());
                data[end + i * 3 + 2] = ends[i];
            }
            return;
        }
        _ => unreachable!(),
    };
    encode_types(&mut data[type_pos..], hits, plan.types);
}

fn partition(hits: &[PackedHit]) -> Plan {
    let stats = Stats::new(hits);
    let plan = choose(hits, &stats);
    let split = stats.gap_index;
    if split >= 8
        && split < hits.len()
        && stats.max_gap > 1
        && stats.max_gap as u64 * 4 > (relative(hits[hits.len() - 1]) - relative(hits[0])) as u64
    {
        let (left, right) = if split <= hits.len() - split {
            let left = Stats::new(&hits[..split]);
            let right = stats.without(&left, stats.max_gap, &hits[split..]);
            (left, right)
        } else {
            let right = Stats::new(&hits[split..]);
            let left = stats.without(&right, stats.max_gap, &hits[..split]);
            (left, right)
        };
        let a = choose(&hits[..split], &left);
        let b = choose(&hits[split..], &right);
        if a.bytes.next_multiple_of(8) + b.bytes + DESC_BYTES < plan.bytes {
            return a;
        }
    }
    plan
}
fn encode(hits: Vec<PackedHit>) -> Option<Encoded> {
    if hits.is_empty() {
        return None;
    }
    let count = hits.len();
    let last = relative(hits[count - 1]);
    // No indexed representation can beat four/eight bytes, and ownership of
    // these tiny arrays can transfer directly without statistics or planning.
    if count <= 2 {
        let tags = hits.iter().fold(0, |tags, &hit| tags | (1 << tag(hit)));
        return Some(Encoded {
            data: into_bytes(hits),
            control: control(RAW, 0, tags),
            count,
            last,
        });
    }
    if let Some((first, step, t)) = uniform_arithmetic(&hits) {
        let mut data = vec![0; 8];
        data[..4].copy_from_slice(&first.to_ne_bytes());
        data[4..8].copy_from_slice(&step.to_ne_bytes());
        return Some(Encoded {
            data,
            control: control(AR, 0, 1 << t),
            count,
            last,
        });
    }
    // Constant offsets with changing types are common in retained evidence.
    // Check that global form before building leaf statistics and directories.
    if let Some(step) = arithmetic_offsets(&hits) {
        let mut counts = [0usize; 16];
        for &hit in &hits {
            counts[tag(hit) as usize] += 1;
        }
        let types = TypePlan::new(count, &counts);
        let size = 8 + types.bytes;
        if size < count * 4 {
            let ctl = types.ctl(AR, 0);
            let mut data = vec![0; size];
            data[..4].copy_from_slice(&relative(hits[0]).to_ne_bytes());
            data[4..8].copy_from_slice(&step.to_ne_bytes());
            encode_types(&mut data[8..], &hits, types);
            return Some(Encoded {
                data,
                control: ctl,
                count,
                last,
            });
        }
    }
    let mut plans = Vec::with_capacity(count.div_ceil(LEAF));
    let mut at = 0;
    let mut body = 16usize;
    let mut tags = 0;
    while at < count {
        let end = (at + LEAF).min(count);
        let mut plan = partition(&hits[at..end]);
        let n = plan.n;
        tags |= mask(plan.leaf.control);
        plan.leaf.offset = body.next_multiple_of(8) as u64;
        plan.leaf.end = (at + n) as u64;
        body = plan.leaf.offset as usize + plan.bytes;
        plans.push(plan);
        at += n;
    }
    if plans.len() == 1 {
        let mut plan = plans[0];
        if plan.leaf.control & 7 != RAW {
            plan.leaf.offset = 0;
            let mut data = vec![0; plan.bytes];
            encode_leaf(&mut data, &hits, plan);
            return Some(Encoded {
                data,
                control: plan.leaf.control,
                count,
                last,
            });
        }
    }
    let fixed = plans
        .iter()
        .take(plans.len().saturating_sub(1))
        .all(|p| p.n == LEAF);
    let wide = body > u32::MAX as usize || count > u32::MAX as usize;
    let desc = if wide { 24 } else { DESC_BYTES };
    // One leaf of read-ahead protects the original prefix during in-place
    // writes. Larger prefix expansion simply selects the lossless RAW form.
    let safe = plans
        .iter()
        .all(|p| p.leaf.offset as usize + p.bytes <= p.leaf.end as usize * 4 + LEAF * 4);
    if !safe || body + plans.len() * desc >= count * 4 {
        return Some(Encoded {
            data: release_slack(into_bytes(hits)),
            control: control(RAW, 0, tags),
            count,
            last,
        });
    }
    let mut data = into_bytes(hits);
    let mut pending = [PackedHit([0; 4]); LEAF * 2];
    let mut scratch = [PackedHit([0; 4]); LEAF];
    let mut read = 0;
    let mut rank = 0;
    let mut previous = 16;
    for plan in &plans {
        let limit = (rank + plan.n + LEAF).min(count);
        while read < limit {
            let begin = read % pending.len();
            let n = (limit - read).min(pending.len() - begin);
            // PackedHit has alignment 1 and every four-byte pattern is valid.
            let source =
                unsafe { std::slice::from_raw_parts(data.as_ptr().add(read * 4).cast(), n) };
            pending[begin..begin + n].copy_from_slice(source);
            read += n;
        }
        let begin = rank % pending.len();
        let source = if begin + plan.n <= pending.len() {
            &pending[begin..begin + plan.n]
        } else {
            let first = pending.len() - begin;
            scratch[..first].copy_from_slice(&pending[begin..]);
            scratch[first..plan.n].copy_from_slice(&pending[..plan.n - first]);
            &scratch[..plan.n]
        };
        let start = plan.leaf.offset as usize;
        data[previous..start].fill(0);
        encode_leaf(&mut data[start..start + plan.bytes], source, *plan);
        previous = start + plan.bytes;
        rank += plan.n;
    }
    data.truncate(body);
    data[..8].copy_from_slice(&(body as u64).to_ne_bytes());
    data[8..16].copy_from_slice(&(plans.len() as u64).to_ne_bytes());
    for p in plans {
        p.leaf.write(&mut data, wide);
    }
    Some(Encoded {
        data: release_slack(data),
        control: control(LEAVES, 0, tags)
            | if wide { WIDE } else { 0 }
            | if fixed { FIXED } else { 0 },
        count,
        last,
    })
}

struct Part {
    interior: Option<Encoded>,
    head: Vec<PackedHit>,
    tail: Vec<PackedHit>,
}
pub(super) struct Prepared {
    start: u64,
    base: u64,
    parts: [Part; 2],
    #[cfg(test)]
    pub(super) raw_count: usize,
    working_bytes: usize,
}
fn ordered(hits: &[PackedHit]) -> bool {
    hits.windows(2).all(|pair| pair[0].key() <= pair[1].key())
}

// The matcher emits monotonically advancing anchors. TAR normalization can
// move a root back by HIT_LOOKBEHIND and suffix recovery by at most overlap.
// Separate footer/header buffers therefore need only this physical horizon;
// completed prefixes can never be changed by a later matching anchor.
const fn type_ranks() -> [u8; PATTERNS.len() + 1] {
    let mut ranks = [0; PATTERNS.len() + 1];
    let mut i = 0;
    while i < TYPE_ORDER.len() {
        ranks[TYPE_ORDER[i] as usize] = i as u8;
        i += 1;
    }
    ranks
}
const TYPE_RANK: [u8; PATTERNS.len() + 1] = type_ranks();
fn ordered_key(hit: PackedHit) -> u32 {
    (relative(hit) << 4) | TYPE_RANK[tag(hit) as usize] as u32
}
fn from_ordered_key(key: u32) -> PackedHit {
    PackedHit::new(key >> 4, TYPE_ORDER[(key & 15) as usize])
}

struct LeafWriter {
    data: Vec<u8>,
    leaves: Vec<Leaf>,
    pending: Vec<PackedHit>,
    encoded: usize,
    seen: usize,
    first: u32,
    last: u32,
    step: Option<u32>,
    arithmetic: bool,
    tags: u16,
    counts: [usize; 16],
    prefix: bool,
    prefix_tag: u8,
}
impl Default for LeafWriter {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            leaves: Vec::new(),
            pending: Vec::new(),
            encoded: 0,
            seen: 0,
            first: 0,
            last: 0,
            step: None,
            arithmetic: true,
            tags: 0,
            counts: [0; 16],
            prefix: true,
            prefix_tag: 0,
        }
    }
}
impl LeafWriter {
    fn observe(&mut self, hit: PackedHit) {
        let value = relative(hit);
        let t = tag(hit);
        if self.arithmetic {
            if self.seen == 0 {
                self.first = value;
                self.prefix_tag = t;
            } else if self.seen == 1 {
                self.step = Some(value - self.last);
            } else if self.step != Some(value - self.last) {
                self.arithmetic = false;
            }
        }
        self.last = value;
        self.seen += 1;
        self.tags |= 1 << t;
        if self.arithmetic {
            self.counts[t as usize] += 1;
        }
    }
    fn materialize_prefix(&mut self) {
        self.prefix = false;
        self.data.resize(16, 0);
        if self.seen >= 3 {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&self.first.to_ne_bytes());
            bytes[4..].copy_from_slice(&self.step.unwrap().to_ne_bytes());
            self.data.extend_from_slice(&bytes);
            self.leaves.push(Leaf {
                offset: 16,
                end: self.seen as u64,
                last: self.last,
                control: control(AR, 0, 1 << self.prefix_tag),
            });
            self.encoded = self.seen;
        } else {
            for i in 0..self.seen {
                self.pending.push(PackedHit::new(
                    self.first + i as u32 * self.step.unwrap_or(0),
                    self.prefix_tag,
                ));
            }
        }
    }
    fn push(&mut self, hit: PackedHit) {
        if self.prefix {
            if self.seen == 0
                || (tag(hit) == self.prefix_tag
                    && (self.seen == 1 || Some(relative(hit) - self.last) == self.step))
            {
                self.observe(hit);
                return;
            }
            self.materialize_prefix();
        }
        self.observe(hit);
        self.pending.push(hit);
        if self.pending.len() == LEAF {
            self.flush_leaf();
        }
    }
    fn flush_leaf(&mut self) {
        let mut plan = partition(&self.pending);
        let n = plan.n;
        let start = self.data.len().next_multiple_of(8);
        self.data.resize(start + plan.bytes, 0);
        encode_leaf(&mut self.data[start..], &self.pending[..n], plan);
        self.encoded += n;
        plan.leaf.offset = start as u64;
        plan.leaf.end = self.encoded as u64;
        self.leaves.push(plan.leaf);
        self.pending.drain(..n);
    }
    #[cfg(test)]
    fn visit(&self, mut emit: impl FnMut(PackedHit)) {
        if self.prefix {
            for i in 0..self.seen {
                emit(PackedHit::new(
                    self.first + i as u32 * self.step.unwrap_or(0),
                    self.prefix_tag,
                ));
            }
            return;
        }
        let mut begin = 0;
        for &leaf in &self.leaves {
            let n = leaf.end as usize - begin;
            let data = &self.data[leaf.offset as usize..];
            if leaf.control & 7 == AR {
                for i in 0..n {
                    let (offset, pattern) = decode_one(data, leaf.control, n, i);
                    emit(PackedHit::new(offset, pattern));
                }
            } else {
                let mut offsets = [0; LEAF];
                let mut patterns = [0; LEAF];
                decode_cache(data, leaf.control, n, 0, &mut offsets, &mut patterns, n);
                for i in 0..n {
                    emit(PackedHit::new(offsets[i], patterns[i]));
                }
            }
            begin = leaf.end as usize;
        }
        for &hit in &self.pending {
            emit(hit);
        }
    }
    fn finish(mut self) -> Option<Encoded> {
        if self.seen == 0 {
            return None;
        }
        if self.prefix {
            if self.seen < 3 {
                let hits = (0..self.seen)
                    .map(|i| {
                        PackedHit::new(
                            self.first + i as u32 * self.step.unwrap_or(0),
                            self.prefix_tag,
                        )
                    })
                    .collect();
                return encode(hits);
            }
            let mut data = vec![0; 8];
            data[..4].copy_from_slice(&self.first.to_ne_bytes());
            data[4..8].copy_from_slice(&self.step.unwrap().to_ne_bytes());
            return Some(Encoded {
                data,
                control: control(AR, 0, self.tags),
                count: self.seen,
                last: self.last,
            });
        }
        while !self.pending.is_empty() {
            self.flush_leaf();
        }
        if self.arithmetic {
            let types = TypePlan::new(self.seen, &self.counts);
            let size = 8 + types.bytes;
            if size < self.data.len() + self.leaves.len() * DESC_BYTES {
                let mut data = vec![0; size];
                data[..4].copy_from_slice(&self.first.to_ne_bytes());
                data[4..8].copy_from_slice(&self.step.unwrap().to_ne_bytes());
                // Re-encode only type evidence. Long constant prefixes need no
                // raw position array and no per-hit expansion for sparse types.
                let mut rank = 0;
                let mut exception = 0;
                let w = position_width(self.seen);
                let tag_pos = 8 + types.exceptions * w;
                if types.sparse {
                    data[8] = types.dominant;
                    data[12..16].copy_from_slice(&(types.exceptions as u32).to_ne_bytes());
                }
                let tw = type_width(types.tags);
                for &leaf in &self.leaves {
                    let n = leaf.end as usize - rank;
                    let body = &self.data[leaf.offset as usize..];
                    if types.sparse && mask(leaf.control) == 1 << types.dominant {
                        rank += n;
                        continue;
                    }
                    let mut local = 0;
                    while local < n {
                        let m = (n - local).min(LEAF);
                        let mut patterns = [0; LEAF];
                        if leaf.control & 7 == RAW {
                            for i in 0..m {
                                patterns[i] = (small(body, (local + i) * 4) & 15) as u8;
                            }
                        } else if leaf.control & 7 == AR {
                            decode_types(&body[8..], n, local, &mut patterns[..m], leaf.control);
                        } else {
                            let mut offsets = [0; LEAF];
                            decode_cache(
                                body,
                                leaf.control,
                                n,
                                local,
                                &mut offsets,
                                &mut patterns,
                                m,
                            );
                        }
                        for &pattern in &patterns[..m] {
                            if types.sparse {
                                if pattern != types.dominant {
                                    let at = 16 + exception * w;
                                    data[at..at + w]
                                        .copy_from_slice(&(rank as u32).to_ne_bytes()[..w]);
                                    data[8 + tag_pos + exception / 2] |=
                                        pattern << ((exception & 1) * 4);
                                    exception += 1;
                                }
                            } else if tw != 0 {
                                let code = if tw == 4 {
                                    pattern as u32
                                } else {
                                    (types.tags & ((1 << pattern) - 1)).count_ones()
                                };
                                set_type_bits(&mut data[8..], rank, tw, code);
                            }
                            rank += 1;
                        }
                        local += m;
                    }
                }
                return Some(Encoded {
                    data,
                    control: types.ctl(AR, 0),
                    count: self.seen,
                    last: self.last,
                });
            }
        }
        if self.leaves.len() == 1 {
            let leaf = self.leaves[0];
            let start = leaf.offset as usize;
            let len = self.data.len() - start;
            self.data.copy_within(start.., 0);
            self.data.truncate(len);
            return Some(Encoded {
                data: release_slack(self.data),
                control: leaf.control,
                count: self.seen,
                last: self.last,
            });
        }
        let body = self.data.len();
        let wide = body > u32::MAX as usize || self.seen > u32::MAX as usize;
        let desc = if wide { 24 } else { DESC_BYTES };
        let mut prior = 0;
        let fixed = self.leaves.iter().take(self.leaves.len() - 1).all(|leaf| {
            let n = leaf.end as usize - prior;
            prior = leaf.end as usize;
            n == LEAF
        });
        self.data[..8].copy_from_slice(&(body as u64).to_ne_bytes());
        self.data[8..16].copy_from_slice(&(self.leaves.len() as u64).to_ne_bytes());
        self.data.reserve_exact(self.leaves.len() * desc);
        for leaf in self.leaves {
            leaf.write(&mut self.data, wide);
        }
        Some(Encoded {
            data: release_slack(self.data),
            control: control(LEAVES, 0, self.tags)
                | if wide { WIDE } else { 0 }
                | if fixed { FIXED } else { 0 },
            count: self.seen,
            last: self.last,
        })
    }
}
// Only the final mixed-type AR reduction uses point writes. Regular leaf
// encoding uses pack_stream and performs one store per completed word.
fn set_type_bits(data: &mut [u8], i: usize, width: u32, value: u32) {
    let bit = i * width as usize;
    let at = bit / 64 * 8;
    let shift = bit % 64;
    let v = word(data, at) | ((value as u64) << shift);
    data[at..at + 8].copy_from_slice(&v.to_ne_bytes());
    if shift + width as usize > 64 {
        let v = word(data, at + 8) | ((value as u64) >> (64 - shift));
        data[at + 8..at + 16].copy_from_slice(&v.to_ne_bytes());
    }
}
#[derive(Default)]
struct MatchPart {
    writer: LeafWriter,
    pending: Vec<u32>,
    head: Vec<PackedHit>,
    tail: Vec<PackedHit>,
    maximum: u32,
    flushed_at: u32,
    minimum: Option<u32>,
}
impl MatchPart {
    fn interior(&mut self, hit: PackedHit, horizon: u32) {
        let value = relative(hit);
        self.maximum = self.maximum.max(value);
        self.minimum = Some(self.minimum.map_or(value, |prior| prior.min(value)));
        self.pending.push(ordered_key(hit));
        let frontier = self.maximum.saturating_sub(horizon);
        // Batch the bounded normalization window. Primitive-word sorting is
        // adaptive for already ordered signatures, without a heap operation
        // for every emitted fact or any idle polling/concurrency reduction.
        if self.minimum.is_some_and(|v| v < frontier)
            && (self.maximum - self.flushed_at >= horizon.saturating_mul(2)
                || self.pending.len() >= LEAF * 4)
        {
            self.pending.sort_unstable();
            let end = self.pending.partition_point(|key| key >> 4 < frontier);
            for key in self.pending.drain(..end) {
                self.writer.push(from_ordered_key(key));
            }
            self.minimum = self.pending.first().map(|key| key >> 4);
            self.flushed_at = self.maximum;
        }
    }
    fn finish(mut self, last: bool) -> Part {
        self.pending.sort_unstable();
        for key in self.pending.drain(..) {
            self.writer.push(from_ordered_key(key));
        }
        if last {
            self.tail.sort_unstable_by_key(|&h| ordered_key(h));
            for hit in self.tail.drain(..) {
                self.writer.push(hit);
            }
        }
        Part {
            interior: self.writer.finish(),
            head: self.head,
            tail: self.tail,
        }
    }
}

// Matching jobs keep only a bounded normalization horizon and encoded leaves.
pub(super) struct HitBuffer {
    pub(super) saw_zip_eocd: bool,
    parts: [MatchPart; 2],
    base: u64,
    start: u64,
    tail: u64,
    horizon: u32,
    count: usize,
    #[cfg(test)]
    raw_count: usize,
}
impl HitBuffer {
    pub(super) fn new(base: u64, start: u64, end: u64, overlap: usize) -> Self {
        Self {
            saw_zip_eocd: false,
            parts: std::array::from_fn(|_| MatchPart::default()),
            base,
            start,
            tail: end
                .saturating_sub(HIT_LOOKBEHIND + overlap as u64)
                .max(start),
            horizon: (HIT_LOOKBEHIND + overlap as u64) as u32,
            count: 0,
            #[cfg(test)]
            raw_count: 0,
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub(super) fn push(&mut self, hit: RawHit) {
        let relative_offset = hit.offset() - self.base;
        debug_assert!(relative_offset <= HIT_OFFSET_MASK);
        let hit = PackedHit::new(relative_offset as u32, hit.pattern);
        let t = tag(hit);
        self.count += 1;
        #[cfg(test)]
        {
            self.raw_count += usize::from((t as usize) < 12);
        }
        let part = &mut self.parts[usize::from(t as usize == PATTERNS.len())];
        let offset = self.base + relative(hit) as u64;
        if offset < self.start {
            part.head.push(hit);
        } else if offset >= self.tail {
            part.tail.push(hit);
        } else {
            part.interior(hit, self.horizon);
        }
    }
    #[cfg(test)]
    fn visit(&self, mut emit: impl FnMut(RawHit)) {
        for part in &self.parts {
            part.writer.visit(|hit| emit(hit.unpack(self.base)));
            for key in &part.pending {
                emit(from_ordered_key(*key).unpack(self.base));
            }
            for &hit in part.head.iter().chain(&part.tail) {
                emit(hit.unpack(self.base));
            }
        }
    }
    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = RawHit> {
        let mut hits = Vec::new();
        self.visit(|hit| hits.push(hit));
        hits.sort_unstable_by_key(|h| (h.offset(), h.hit_name()));
        hits.into_iter()
    }
}
pub(super) fn prepare(batch: HitBuffer, last: bool) -> Prepared {
    let HitBuffer {
        base,
        start,
        #[cfg(test)]
        raw_count,
        parts,
        ..
    } = batch;
    let parts = parts.map(|p| p.finish(last));
    let working_bytes = parts
        .iter()
        .map(|p| {
            p.head.capacity() * 4
                + p.tail.capacity() * 4
                + p.interior.as_ref().map_or(0, |e| e.data.capacity())
        })
        .sum();
    Prepared {
        start,
        base,
        parts,
        #[cfg(test)]
        raw_count,
        working_bytes,
    }
}

pub(super) struct Builder {
    arena: Spool,
    slots: Option<Slots>,
    chunks: usize,
    chunk: u64,
    window: usize,
    single: Option<Prepared>,
}
impl Builder {
    pub(super) fn new(size: u64, chunk: usize, window: usize) -> io::Result<Self> {
        let chunks = usize::try_from(size.div_ceil(chunk as u64)).map_err(io::Error::other)?;
        Ok(Self {
            arena: Spool::default(),
            slots: None,
            chunks,
            chunk: chunk as u64,
            window,
            single: None,
        })
    }
    fn write_segment(&mut self, base: u64, encoded: Encoded) -> io::Result<Segment> {
        // All codecs use safe byte loads. Eight-byte alignment is sufficient
        // for packed streams; EF does not require cache-line padding.
        let end = self.arena.seek(SeekFrom::End(0))?;
        let start = end.next_multiple_of(8);
        self.arena.write_all(&[0; 8][..(start - end) as usize])?;
        self.arena.write_all(&encoded.data)?;
        Ok(Segment {
            base,
            end: 0,
            count: encoded.count as u64,
            payload: start,
            last: base + encoded.last as u64,
            control: encoded.control as u64,
        })
    }
    fn write_part(&mut self, base: u64, hits: &[PackedHit]) -> io::Result<u64> {
        if hits.is_empty() {
            return Ok(0);
        }
        let pos = self.arena.seek(SeekFrom::End(0))?;
        self.arena.write_all(&base.to_ne_bytes())?;
        self.arena.write_all(&(hits.len() as u64).to_ne_bytes())?;
        // Same byte-aligned representation as into_bytes, borrowed only here.
        let bytes = unsafe { std::slice::from_raw_parts(hits.as_ptr().cast(), hits.len() * 4) };
        self.arena.write_all(bytes)?;
        Ok(pos + 1)
    }
    pub(super) fn push(&mut self, batch: Prepared) -> io::Result<()> {
        if self.chunks == 1
            && batch
                .parts
                .iter()
                .all(|part| part.head.is_empty() && part.tail.is_empty())
            && batch
                .parts
                .iter()
                .filter_map(|part| part.interior.as_ref())
                .map(|part| part.count)
                .sum::<usize>()
                <= LEAF
        {
            // A small EOF batch is already final: no mutable directory,
            // staging descriptor, boundary record or spool copy is needed.
            self.single = Some(batch);
            return Ok(());
        }
        // Charge the bounded matching window before retaining an arena copy.
        // Compression shrinks completed jobs, but concurrent encoders still
        // need the original allocation. Spill storage, never throttle workers.
        let working = batch.working_bytes.saturating_mul(self.window);
        let slots = match &self.slots {
            Some(Slots::Memory(values)) => values.len() * 8,
            _ => 0,
        };
        if !self.arena.is_spilled()
            && self
                .arena
                .memory_bytes()
                .saturating_add(working)
                .saturating_add(slots)
                > MEMORY_BYTES
        {
            self.arena.spill()?;
        }
        let ordinal = (batch.start / self.chunk) as usize;
        for (stream, part) in batch.parts.into_iter().enumerate() {
            if part.interior.is_none() && part.head.is_empty() && part.tail.is_empty() {
                continue;
            }
            if self.slots.is_none() {
                self.slots =
                    Some(Slots::new(self.chunks.checked_mul(6).ok_or_else(
                        || io::Error::other("hit directory overflow"),
                    )?)?);
            }
            let row = ordinal * 6 + stream * 3;
            if let Some(encoded) = part.interior {
                let segment = self.write_segment(batch.base, encoded)?;
                let pos = self.arena.seek(SeekFrom::End(0))?;
                self.arena.write_all(&segment.bytes())?;
                self.slots.as_mut().unwrap().set(row, pos + 1);
            }
            let tail = self.write_part(batch.base, &part.tail)?;
            self.slots.as_mut().unwrap().set(row + 1, tail);
            if !part.head.is_empty() {
                debug_assert!(ordinal != 0);
                let head = self.write_part(batch.base, &part.head)?;
                self.slots.as_mut().unwrap().set(row - 6 + 2, head);
            }
        }
        Ok(())
    }
    fn read_part(&mut self, pointer: u64, base: u64, out: &mut Vec<PackedHit>) -> io::Result<()> {
        if pointer == 0 {
            return Ok(());
        }
        self.arena.seek(SeekFrom::Start(pointer - 1))?;
        let mut header = [0; 16];
        self.arena.read_exact(&mut header)?;
        let old_base = word(&header, 0);
        let n = word(&header, 8) as usize;
        let first = out.len();
        out.resize(first + n, PackedHit([0; 4]));
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(out[first..].as_mut_ptr().cast(), n * 4) };
        self.arena.read_exact(bytes)?;
        for hit in &mut out[first..] {
            *hit = PackedHit::new((old_base + relative(*hit) as u64 - base) as u32, tag(*hit));
        }
        Ok(())
    }
    pub(super) fn finish(mut self) -> io::Result<HitStorage> {
        if let Some(single) = self.single.take() {
            return Ok(HitStorage::single(single));
        }
        let mut dirs = [Spool::default(), Spool::default()];
        let mut counts = [0; 2];
        let mut boundary = Vec::new();
        if let Some(slots) = self.slots.take() {
            let slot_bytes = match &slots {
                Slots::Memory(values) => values.len() * 8,
                Slots::Disk(_) => 0,
            };
            for ordinal in 0..self.chunks {
                for stream in 0..2 {
                    let row = ordinal * 6 + stream * 3;
                    let pointer = slots.get(row);
                    if pointer != 0 {
                        self.arena.seek(SeekFrom::Start(pointer - 1))?;
                        let mut bytes = [0; SEG_BYTES];
                        self.arena.read_exact(&mut bytes)?;
                        let mut segment = Segment::read(&bytes);
                        counts[stream] += segment.count;
                        segment.end = counts[stream];
                        dirs[stream].write_all(&segment.bytes())?;
                    }
                    boundary.clear();
                    let base = ordinal as u64 * self.chunk;
                    self.read_part(slots.get(row + 1), base, &mut boundary)?;
                    self.read_part(slots.get(row + 2), base, &mut boundary)?;
                    if !boundary.is_empty() {
                        if !ordered(&boundary) {
                            boundary.sort_unstable_by_key(|hit| hit.key());
                        }
                        if let Some(encoded) = encode(std::mem::take(&mut boundary)) {
                            let mut segment = self.write_segment(base, encoded)?;
                            counts[stream] += segment.count;
                            segment.end = counts[stream];
                            dirs[stream].write_all(&segment.bytes())?;
                        }
                    }
                }
                let directory_bytes = dirs[0].memory_bytes() + dirs[1].memory_bytes();
                if !self.arena.is_spilled()
                    && self.arena.memory_bytes() + directory_bytes + slot_bytes > MEMORY_BYTES
                {
                    self.arena.spill()?;
                }
                if directory_bytes + slot_bytes + self.arena.memory_bytes() > MEMORY_BYTES {
                    for dir in &mut dirs {
                        // A never-used stream stays empty and has no mapping.
                        if dir.len()? != 0 {
                            dir.spill()?;
                        }
                    }
                }
            }
        }
        let [a, b] = dirs;
        Ok(HitStorage {
            data: compact_blob(self.arena.finish()?),
            dirs: [compact_blob(a.finish()?), compact_blob(b.finish()?)],
        })
    }
}

fn compact_blob(blob: Blob) -> Blob {
    match blob {
        Blob::Memory(data) => Blob::Memory(release_slack(data)),
        other => other,
    }
}
pub(super) struct HitStorage {
    data: Blob,
    dirs: [Blob; 2],
}
impl HitStorage {
    fn single(batch: Prepared) -> Self {
        let mut data = Vec::new();
        let mut dirs = [Blob::Memory(Vec::new()), Blob::Memory(Vec::new())];
        for (stream, part) in batch.parts.into_iter().enumerate() {
            if let Some(encoded) = part.interior {
                let payload = if data.is_empty() {
                    data = encoded.data;
                    0
                } else {
                    let offset = data.len().next_multiple_of(8);
                    data.resize(offset, 0);
                    data.extend_from_slice(&encoded.data);
                    offset as u64
                };
                let segment = Segment {
                    base: batch.base,
                    end: encoded.count as u64,
                    count: encoded.count as u64,
                    payload,
                    last: batch.base + encoded.last as u64,
                    control: encoded.control as u64,
                };
                dirs[stream] = Blob::Memory(segment.bytes().to_vec());
            }
        }
        Self {
            data: Blob::Memory(data),
            dirs,
        }
    }
    pub(super) fn view(&self, stream: usize) -> HitView<'_> {
        HitView {
            data: &self.data,
            directory: &self.dirs[stream],
        }
    }
    #[cfg(test)]
    pub(super) fn from_hits(hits: &[RawHit]) -> Self {
        let base = hits.iter().map(RawHit::offset).min().unwrap_or(0);
        let mut packed = hits
            .iter()
            .map(|h| PackedHit::new((h.offset() - base) as u32, h.pattern))
            .collect::<Vec<_>>();
        packed.sort_unstable_by_key(|h| h.key());
        let mut builder = Builder::new(1, 65536, 1).unwrap();
        let mut dir = Spool::default();
        if let Some(encoded) = encode(packed) {
            let mut segment = builder.write_segment(base, encoded).unwrap();
            segment.end = segment.count;
            dir.write_all(&segment.bytes()).unwrap();
        }
        Self {
            data: builder.arena.finish().unwrap(),
            dirs: [dir.finish().unwrap(), Blob::Memory(Vec::new())],
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct HitView<'a> {
    data: &'a [u8],
    directory: &'a [u8],
}
impl<'a> HitView<'a> {
    fn segments(self) -> usize {
        self.directory.len() / SEG_BYTES
    }
    fn segment(self, i: usize) -> Segment {
        Segment::read(&self.directory[i * SEG_BYTES..])
    }
    pub(super) fn len(self) -> usize {
        if self.directory.is_empty() {
            0
        } else {
            self.segment(self.segments() - 1).end as usize
        }
    }
    fn find_segment(self, rank: usize) -> usize {
        let (mut lo, mut hi) = (0, self.segments());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.segment(mid).end as usize <= rank {
                lo = mid + 1
            } else {
                hi = mid
            }
        }
        lo
    }

    fn leaf_count(self, segment: Segment) -> usize {
        word(&self.data[segment.payload as usize..], 8) as usize
    }
    fn leaf(self, segment: Segment, index: usize) -> (Leaf, usize, &'a [u8]) {
        let payload = &self.data[segment.payload as usize..];
        if segment.control as u32 & 7 != LEAVES {
            return (
                Leaf {
                    offset: 0,
                    end: segment.count,
                    last: (segment.last - segment.base) as u32,
                    control: segment.control as u32,
                },
                segment.count as usize,
                payload,
            );
        }
        let size = descriptor_size(segment.control as u32);
        let directory = word(payload, 0) as usize;
        let wide = segment.control as u32 & WIDE != 0;
        let leaf = Leaf::read(&payload[directory + index * size..], wide);
        let begin = if segment.control as u32 & FIXED != 0 {
            (index * LEAF) as u64
        } else if index == 0 {
            0
        } else {
            Leaf::read(&payload[directory + (index - 1) * size..], wide).end
        };
        (
            leaf,
            (leaf.end - begin) as usize,
            &payload[leaf.offset as usize..],
        )
    }
    fn find_leaf(self, segment: Segment, rank: usize) -> usize {
        if segment.control as u32 & FIXED != 0 {
            return rank / LEAF;
        }
        let payload = &self.data[segment.payload as usize..];
        let directory = word(payload, 0) as usize;
        let size = descriptor_size(segment.control as u32);
        let wide = segment.control as u32 & WIDE != 0;
        let (mut lo, mut hi) = (0, self.leaf_count(segment));
        while lo < hi {
            let mid = (lo + hi) / 2;
            if (if wide {
                word(payload, directory + mid * size + 8)
            } else {
                small(payload, directory + mid * size + 4) as u64
            }) as usize
                <= rank
            {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
    pub(super) fn get(self, rank: usize) -> Option<RawHit> {
        let si = self.find_segment(rank);
        if si == self.segments() {
            return None;
        }
        let segment = self.segment(si);
        let local = rank - (segment.end - segment.count) as usize;
        let li = if segment.control as u32 & 7 == LEAVES {
            self.find_leaf(segment, local)
        } else {
            0
        };
        let (leaf, n, data) = self.leaf(segment, li);
        let i = local - (leaf.end as usize - n);
        let (offset, pattern) = decode_one(data, leaf.control, n, i);
        Some(RawHit::new(segment.base + offset as u64, pattern))
    }
    pub(super) fn lower_bound(self, offset: u64) -> usize {
        self.lower_bound_from(offset, 0)
    }
    fn lower_bound_from(self, offset: u64, begin: usize) -> usize {
        let (mut lo, mut hi) = (begin, self.segments());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.segment(mid).last < offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == self.segments() {
            return self.len();
        }
        let segment = self.segment(lo);
        let rank = (segment.end - segment.count) as usize;
        if offset <= segment.base {
            return rank;
        }
        let relative = (offset - segment.base) as u32;
        let mut index = 0;
        if segment.control as u32 & 7 == LEAVES {
            let payload = &self.data[segment.payload as usize..];
            let directory = word(payload, 0) as usize;
            let size = descriptor_size(segment.control as u32);
            let wide = segment.control as u32 & WIDE != 0;
            let (mut a, mut b) = (0, self.leaf_count(segment));
            while a < b {
                let mid = (a + b) / 2;
                if small(payload, directory + mid * size + if wide { 16 } else { 8 }) < relative {
                    a = mid + 1;
                } else {
                    b = mid;
                }
            }
            index = a;
        }
        let (leaf, n, data) = self.leaf(segment, index);
        rank + leaf.end as usize - n + leaf_lower_bound(data, leaf.control, n, relative)
    }
    #[cfg(test)]
    pub(super) fn iter(self) -> Cursor<'a> {
        self.range(0, self.len(), TAGS)
    }
    pub(super) fn iter_mask(self, tags: u16) -> Cursor<'a> {
        self.range(0, self.len(), tags)
    }
    fn range(self, start: usize, end: usize, tags: u16) -> Cursor<'a> {
        Cursor {
            view: self,
            next: start,
            end,
            tags,
            cache_start: 0,
            cache_len: 0,
            base: 0,
            offsets: [0; LEAF],
            patterns: [0; LEAF],
            arithmetic: false,
            first: 0,
            step: 0,
            constant_type: None,
            segment_index: self.find_segment(start),
        }
    }
    pub(super) fn par_iter_mask(self, tags: u16) -> impl ParallelIterator<Item = RawHit> + 'a {
        (0..self.segments())
            .into_par_iter()
            .filter(move |&si| mask(self.segment(si).control as u32) & tags != 0)
            .flat_map(move |si| {
                let segment = self.segment(si);
                let start = (segment.end - segment.count) as usize;
                (0..(segment.count as usize).div_ceil(4096))
                    .into_par_iter()
                    .flat_map_iter(move |i| {
                        self.range(
                            start + i * 4096,
                            (start + (i + 1) * 4096).min(segment.end as usize),
                            tags,
                        )
                    })
            })
    }
}

fn run_rank(data: &[u8], target: u32) -> usize {
    let count = small(data, 4) as usize;
    let (mut lo, mut hi) = (0, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let end = small(data, 12 + mid * 8) as usize;
        if run_value(data, mid, end - 1) < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == count {
        return small(data, 4 + count * 8) as usize;
    }
    let begin = if lo == 0 {
        0
    } else {
        small(data, 4 + lo * 8) as usize
    };
    let first = small(data, 8 + lo * 8) & 0x7fff_ffff;
    begin + target.saturating_sub(first) as usize
}
fn group_for_rank(data: &[u8], width: u32, rank: usize) -> usize {
    let (mut lo, mut hi) = (0, group_count(data));
    while lo < hi {
        let mid = (lo + hi) / 2;
        if group_end(data, width, mid) <= rank {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}
fn decode_one(data: &[u8], ctl: u32, n: usize, i: usize) -> (u32, u8) {
    let codec = ctl & 7;
    if codec == RAW {
        let v = small(data, i * 4);
        return (v >> 4, (v & 15) as u8);
    }
    let width = (ctl >> 3) & 31;
    let first = small(data, 0);
    if codec == GROUP {
        let group = group_for_rank(data, width, i);
        let begin = if group == 0 {
            0
        } else {
            group_end(data, width, group - 1)
        };
        let at = group_masks(data, width) + group * 3;
        let tags = u16::from_ne_bytes(data[at..at + 2].try_into().unwrap());
        return (
            first + get_bits(&data[8..], group, width),
            lexical_type(tags, i - begin),
        );
    }
    let (offset, type_pos) = match codec {
        AR => (first + i as u32 * small(data, 4), 8),
        FOR => (
            first + get_bits(&data[8..], i, width),
            8 + bit_bytes(n, width),
        ),
        EF => (
            first
                + ((select(data, i as u32, true) - i as u32) << width)
                + get_bits(&data[48..], i, width),
            48 + bit_bytes(n, width),
        ),
        PATCH => {
            let begin = i / CHECKPOINT * CHECKPOINT;
            let mut values = [0; CHECKPOINT];
            patch_range(data, n, width, begin, i + 1, &mut values);
            (values[i - begin], patch_types(data, n, width))
        }
        BITMAP if ctl & RUNS != 0 => {
            let (mut lo, mut hi) = (0, small(data, 4) as usize);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if small(data, 12 + mid * 8) as usize <= i {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            (run_value(data, lo, i), 8 + small(data, 4) as usize * 8)
        }
        BITMAP => (
            bitmap_select(data, i),
            bitmap_start(data) + bitmap_words(data) * 8,
        ),
        _ => unreachable!(),
    };
    (offset, decode_type(&data[type_pos..], n, i, ctl))
}
fn leaf_lower_bound(data: &[u8], ctl: u32, n: usize, target: u32) -> usize {
    let codec = ctl & 7;
    let first = if codec == RAW {
        small(data, 0) >> 4
    } else {
        small(data, 0)
    };
    if target <= first {
        return 0;
    }
    if codec == AR {
        let step = small(data, 4);
        return if step == 0 {
            n
        } else {
            ((target - first) as usize).div_ceil(step as usize).min(n)
        };
    }
    let width = (ctl >> 3) & 31;
    if codec == PATCH {
        let checkpoints = 8 + bit_bytes(n, width) + patch_count(data) * 5;
        let groups = n.div_ceil(CHECKPOINT);
        let (mut a, mut b) = (0, groups);
        while a < b {
            let mid = (a + b) / 2;
            if first + get_bits(&data[checkpoints..], mid, checkpoint_width(data)) < target {
                a = mid + 1;
            } else {
                b = mid;
            }
        }
        if a == groups {
            return n;
        }
        let begin = a * CHECKPOINT;
        let end = (begin + CHECKPOINT).min(n);
        let mut values = [0; CHECKPOINT];
        patch_range(data, n, width, begin, end, &mut values);
        return begin + values[..end - begin].partition_point(|&v| v < target);
    }
    if codec == BITMAP {
        if ctl & RUNS != 0 {
            return run_rank(data, target);
        }
        let rel = (target - first) as usize;
        if rel >= small(data, 4) as usize {
            return n;
        }
        return bitmap_prefix(data, rel / 64)
            + (word(data, bitmap_start(data) + rel / 64 * 8) & ((1u64 << (rel % 64)) - 1))
                .count_ones() as usize;
    }
    if codec == GROUP {
        let count = group_count(data);
        let (mut a, mut b) = (0, count);
        while a < b {
            let mid = (a + b) / 2;
            if first + get_bits(&data[8..], mid, width) < target {
                a = mid + 1;
            } else {
                b = mid;
            }
        }
        return if a == 0 {
            0
        } else {
            group_end(data, width, a - 1)
        };
    }
    let (mut lo, mut hi) = (0, n);
    if codec == EF {
        let value = target - first;
        let q = value >> width;
        let max_q = small(data, 4) - n as u32 - 1;
        if q > max_q {
            return n;
        }
        lo = if q == 0 {
            0
        } else {
            (select(data, q - 1, false) - q + 1) as usize
        };
        hi = (select(data, q, false) - q) as usize;
        let low = value & ((1 << width) - 1);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if get_bits(&data[48..], mid, width) < low {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }
    while lo < hi {
        let mid = (lo + hi) / 2;
        let value = if codec == RAW {
            small(data, mid * 4) >> 4
        } else {
            first + get_bits(&data[8..], mid, width)
        };
        if value < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}
fn decode_cache(
    data: &[u8],
    ctl: u32,
    n: usize,
    begin: usize,
    offsets: &mut [u32; LEAF],
    patterns: &mut [u8; LEAF],
    len: usize,
) {
    let codec = ctl & 7;
    let width = (ctl >> 3) & 31;
    let first = small(data, 0);
    let type_pos = match codec {
        RAW => {
            for i in 0..len {
                let v = small(data, (begin + i) * 4);
                offsets[i] = v >> 4;
                patterns[i] = (v & 15) as u8;
            }
            return;
        }
        FOR => {
            for (i, v) in offsets[..len].iter_mut().enumerate() {
                *v = first + get_bits(&data[8..], begin + i, width);
            }
            8 + bit_bytes(n, width)
        }
        EF => {
            let mut rank = 0;
            for wi in 0..4 {
                let mut high = word(data, 16 + wi * 8);
                while high != 0 {
                    let bit = wi * 64 + high.trailing_zeros() as usize;
                    offsets[rank] = first
                        + (((bit - rank) as u32) << width)
                        + get_bits(&data[48..], rank, width);
                    rank += 1;
                    high &= high - 1;
                }
            }
            debug_assert_eq!(rank, n);
            48 + bit_bytes(n, width)
        }
        PATCH => decode_patch(data, n, width, offsets),
        BITMAP if ctl & RUNS != 0 => {
            let mut rank = 0;
            for run in 0..small(data, 4) as usize {
                let end = small(data, 12 + run * 8) as usize;
                while rank < end {
                    offsets[rank] = run_value(data, run, rank);
                    rank += 1;
                }
            }
            8 + small(data, 4) as usize * 8
        }
        BITMAP => {
            let start = bitmap_start(data);
            let mut rank = 0;
            for wi in 0..bitmap_words(data) {
                let mut v = word(data, start + wi * 8);
                while v != 0 {
                    offsets[rank] = first + wi as u32 * 64 + v.trailing_zeros();
                    rank += 1;
                    v &= v - 1;
                }
            }
            debug_assert_eq!(rank, n);
            start + bitmap_words(data) * 8
        }
        GROUP => {
            let mut rank = 0;
            let masks = group_masks(data, width);
            for group in 0..group_count(data) {
                let value = first + get_bits(&data[8..], group, width);
                let at = masks + group * 3;
                let tags = u16::from_ne_bytes(data[at..at + 2].try_into().unwrap());
                for j in 0..tags.count_ones() as usize {
                    offsets[rank] = value;
                    patterns[rank] = lexical_type(tags, j);
                    rank += 1;
                }
            }
            debug_assert_eq!(rank, n);
            return;
        }
        _ => unreachable!(),
    };
    decode_types(&data[type_pos..], n, begin, &mut patterns[..len], ctl);
}

pub(super) struct Cursor<'a> {
    view: HitView<'a>,
    next: usize,
    end: usize,
    tags: u16,
    cache_start: usize,
    cache_len: usize,
    base: u64,
    offsets: [u32; LEAF],
    patterns: [u8; LEAF],
    arithmetic: bool,
    first: u32,
    step: u32,
    constant_type: Option<u8>,
    segment_index: usize,
}
impl<'a> Cursor<'a> {
    fn lower_bound_cached(&self, offset: u64) -> usize {
        if self.arithmetic && self.cache_len != 0 {
            let first = self.base + self.first as u64;
            if offset <= first {
                return self.cache_start;
            }
            let last = first + self.step as u64 * (self.cache_len - 1) as u64;
            if offset <= last {
                return self.cache_start + ((offset - first).div_ceil(self.step as u64)) as usize;
            }
            return self.view.lower_bound_from(offset, self.segment_index);
        }
        if self.cache_len != 0 && offset <= self.base + self.offsets[self.cache_len - 1] as u64 {
            let rank = self.offsets[..self.cache_len]
                .partition_point(|&value| self.base + (value as u64) < offset);
            self.cache_start + rank
        } else {
            self.view.lower_bound_from(offset, self.segment_index)
        }
    }
    pub(super) fn seek_ge(&mut self, offset: u64) {
        if self.next >= self.end {
            return;
        }
        self.next = self.next.max(self.lower_bound_cached(offset));
    }
    #[cfg(test)]
    pub(super) fn equal_offset<'b>(
        &'b mut self,
        offset: u64,
    ) -> impl Iterator<Item = RawHit> + use<'a, 'b> {
        self.seek_ge(offset);
        let end = offset
            .checked_add(1)
            .map_or(self.end, |end| self.lower_bound_cached(end));
        std::iter::from_fn(move || self.next_before(end))
    }

    fn load(&mut self) {
        let mut si = self.segment_index;
        if si >= self.view.segments()
            || self.next < (self.view.segment(si).end - self.view.segment(si).count) as usize
        {
            si = self.view.find_segment(self.next);
        } else {
            while self.view.segment(si).end as usize <= self.next {
                si += 1;
            }
        }
        self.segment_index = si;
        let segment = self.view.segment(si);
        let start = (segment.end - segment.count) as usize;
        if mask(segment.control as u32) & self.tags == 0 {
            self.next = segment.end as usize;
            return;
        }
        let local = self.next - start;
        let leaves = segment.control as u32 & 7 == LEAVES;
        let li = if leaves {
            self.view.find_leaf(segment, local)
        } else {
            0
        };
        let (leaf, n, data) = self.view.leaf(segment, li);
        let leaf_start = leaf.end as usize - n;
        let begin = if leaves && n <= LEAF {
            0
        } else {
            (local - leaf_start) / LEAF * LEAF
        };
        if mask(leaf.control) & self.tags == 0 {
            self.next = start + leaf.end as usize;
            return;
        }
        self.cache_start = start + leaf_start + begin;
        self.cache_len = LEAF.min(n - begin);
        self.base = segment.base;
        self.arithmetic = leaf.control & 7 == AR;
        self.constant_type = (mask(leaf.control).count_ones() == 1)
            .then(|| mask(leaf.control).trailing_zeros() as u8);
        if self.arithmetic {
            self.step = small(data, 4);
            self.first = small(data, 0) + begin as u32 * self.step;
            if self.constant_type.is_some() {
                self.cache_len = n - begin;
            } else {
                decode_types(
                    &data[8..],
                    n,
                    begin,
                    &mut self.patterns[..self.cache_len],
                    leaf.control,
                );
            }
        } else {
            decode_cache(
                data,
                leaf.control,
                n,
                begin,
                &mut self.offsets,
                &mut self.patterns,
                self.cache_len,
            );
        }
    }
}
impl Cursor<'_> {
    #[inline(always)]
    fn next_before(&mut self, end: usize) -> Option<RawHit> {
        while self.next < self.end.min(end) {
            if self.next < self.cache_start || self.next >= self.cache_start + self.cache_len {
                self.load();
                if self.next < self.cache_start || self.next >= self.cache_start + self.cache_len {
                    continue;
                }
            }
            let i = self.next - self.cache_start;
            self.next += 1;
            let pattern = self.constant_type.unwrap_or_else(|| self.patterns[i]);
            if (1 << pattern) & self.tags != 0 {
                return Some(RawHit::new(
                    self.base
                        + if self.arithmetic {
                            (self.first + i as u32 * self.step) as u64
                        } else {
                            self.offsets[i] as u64
                        },
                    pattern,
                ));
            }
        }
        None
    }
}
impl Iterator for Cursor<'_> {
    type Item = RawHit;
    #[inline(always)]
    fn next(&mut self) -> Option<RawHit> {
        self.next_before(self.end)
    }
}

#[cfg(test)]
mod tests {
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
}
