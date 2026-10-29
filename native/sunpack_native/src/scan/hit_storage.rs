//! Private, immutable signature facts. Matching jobs encode their own physical
//! interval; only the bounded lookbehind at a read boundary needs reconciliation.
//! Offsets remain u64. All spill files belong to one scan and use scratch.rs.
use super::{HitBuffer, PackedHit, RawHit, HIT_LOOKBEHIND, PATTERNS};
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
const SEG_BYTES: usize = 48;
const TAG_SHIFT: u32 = 11;
const TYPE_SHIFT: u32 = 8;
const TAGS: u16 = ((1u32 << (PATTERNS.len() + 1)) - 1) as u16;

fn word(data: &[u8], pos: usize) -> u64 {
    u64::from_ne_bytes(data[pos..pos + 8].try_into().unwrap())
}
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
    (control >> TAG_SHIFT) as u16
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
fn put_bits(data: &mut [u8], index: usize, width: u32, value: u32) {
    if width == 0 {
        return;
    }
    let bit = index * width as usize;
    let shift = bit % 64;
    let pos = bit / 64 * 8;
    let a = word(data, pos) | ((value as u64) << shift);
    data[pos..pos + 8].copy_from_slice(&a.to_ne_bytes());
    if shift + width as usize > 64 {
        let b = word(data, pos + 8) | ((value as u64) >> (64 - shift));
        data[pos + 8..pos + 16].copy_from_slice(&b.to_ne_bytes());
    }
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
fn encode_types(data: &mut [u8], hits: &[PackedHit], tags: u16) {
    let width = type_width(tags);
    if width == 0 {
        return;
    }
    for (i, &hit) in hits.iter().enumerate() {
        let t = tag(hit);
        let code = if width == 4 {
            t as u32
        } else {
            (tags & ((1 << t) - 1)).count_ones()
        };
        put_bits(data, i, width, code);
    }
}
fn decode_type(data: &[u8], i: usize, control: u32) -> u8 {
    let width = (control >> TYPE_SHIFT) & 7;
    if width == 0 {
        mask(control).trailing_zeros() as u8
    } else if width == 4 {
        get_bits(data, i, width) as u8
    } else {
        palette(mask(control))[get_bits(data, i, width) as usize]
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
    last: u32,
    control: u32,
}
impl Leaf {
    fn read(data: &[u8]) -> Self {
        Self {
            offset: word(data, 0),
            last: small(data, 8),
            control: small(data, 12),
        }
    }
    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.offset.to_ne_bytes());
        out.extend_from_slice(&self.last.to_ne_bytes());
        out.extend_from_slice(&self.control.to_ne_bytes());
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
    if data.len() < data.capacity() / 2 {
        data.shrink_to_fit();
    }
    data
}
fn stats(hits: &[PackedHit]) -> (u16, Option<u32>) {
    let mut tags = 0;
    let step = (hits.len() > 1).then(|| relative(hits[1]) - relative(hits[0]));
    let mut arithmetic = step;
    let mut previous = relative(hits[0]);
    for (i, &hit) in hits.iter().enumerate() {
        tags |= 1 << tag(hit);
        let offset = relative(hit);
        if i != 0 && Some(offset - previous) != step {
            arithmetic = None;
        }
        previous = offset;
    }
    (tags, arithmetic)
}
fn plan(hits: &[PackedHit], pos: usize) -> (Leaf, usize) {
    let (tags, step) = stats(hits);
    let span = relative(*hits.last().unwrap()) - relative(hits[0]);
    let types = bit_bytes(hits.len(), type_width(tags));
    let mut best = (control(RAW, 0, tags), pos, hits.len() * 4);
    let mut consider = |codec, width, alignment: usize, bytes: usize| {
        let start = pos.next_multiple_of(alignment);
        if start + bytes < best.1 + best.2 {
            best = (control(codec, width, tags), start, bytes);
        }
    };
    if step.is_some() {
        consider(AR, 0, 8, 8 + types);
    }
    consider(
        FOR,
        bits(span),
        8,
        8 + bit_bytes(hits.len(), bits(span)) + types,
    );
    // ceil(log2(U/n)) bounds H by 2n bits, including its final zero.
    let low = bits(span / hits.len() as u32);
    consider(EF, low, 64, 48 + bit_bytes(hits.len(), low) + types);
    (
        Leaf {
            offset: best.1 as u64,
            last: relative(*hits.last().unwrap()),
            control: best.0,
        },
        best.1 + best.2,
    )
}
fn encode_leaf(data: &mut [u8], hits: &[PackedHit], ctl: u32) {
    let codec = ctl & 7;
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
    let type_pos;
    if codec == AR {
        let step = relative(hits[1]) - first;
        data[4..8].copy_from_slice(&step.to_ne_bytes());
        type_pos = 8;
    } else if codec == FOR {
        type_pos = 8 + bit_bytes(hits.len(), width);
        for (i, &hit) in hits.iter().enumerate() {
            put_bits(&mut data[8..type_pos], i, width, relative(hit) - first);
        }
    } else {
        type_pos = 48 + bit_bytes(hits.len(), width);
        let last = relative(*hits.last().unwrap()) - first;
        let len = hits.len() as u32 + (last >> width) + 1;
        debug_assert!(len <= 256);
        data[4..8].copy_from_slice(&len.to_ne_bytes());
        let mut high = [0u64; 4];
        for (i, &hit) in hits.iter().enumerate() {
            let value = relative(hit) - first;
            let bit = (value >> width) as usize + i;
            high[bit / 64] |= 1 << (bit % 64);
            put_bits(
                &mut data[48..type_pos],
                i,
                width,
                value & ((1 << width) - 1),
            );
        }
        let mut count = 0u8;
        for (i, value) in high.into_iter().enumerate() {
            data[8 + i] = count;
            data[16 + i * 8..24 + i * 8].copy_from_slice(&value.to_ne_bytes());
            count += value.count_ones() as u8;
        }
        data[12] = count;
    }
    encode_types(&mut data[type_pos..], hits, mask(ctl));
}
fn encode(hits: Vec<PackedHit>) -> Option<Encoded> {
    if hits.is_empty() {
        return None;
    }
    let count = hits.len();
    let last = relative(*hits.last().unwrap());
    let (tags, step) = stats(&hits);
    let raw = |hits| Encoded {
        data: release_slack(into_bytes(hits)),
        control: control(RAW, 0, tags),
        count,
        last,
    };
    if step.is_some() {
        let size = 8 + bit_bytes(count, type_width(tags));
        if size < count * 4 {
            let ctl = control(AR, 0, tags);
            let mut data = vec![0; size];
            encode_leaf(&mut data, &hits, ctl);
            return Some(Encoded {
                data,
                control: ctl,
                count,
                last,
            });
        }
    }
    if count < LEAF {
        return Some(raw(hits));
    }
    let mut plans = Vec::with_capacity(count.div_ceil(LEAF));
    let mut body = 8;
    for (i, leaf) in hits.chunks(LEAF).enumerate() {
        let (plan, end) = plan(leaf, body);
        // Every write stays behind the unread input. This also covers the
        // initial directory pointer and each EF alignment gap.
        if end > (i * LEAF + leaf.len()) * 4 {
            return Some(raw(hits));
        }
        plans.push(plan);
        body = end;
    }
    if body + plans.len() * DESC_BYTES >= count * 4 {
        return Some(raw(hits));
    }
    let mut data = into_bytes(hits);
    let mut scratch = [PackedHit([0; 4]); LEAF];
    let mut previous_end = 8;
    for (i, plan) in plans.iter().enumerate() {
        let n = LEAF.min(count - i * LEAF);
        for (j, hit) in scratch[..n].iter_mut().enumerate() {
            let pos = (i * LEAF + j) * 4;
            hit.0.copy_from_slice(&data[pos..pos + 4]);
        }
        let start = plan.offset as usize;
        let ctl = plan.control;
        let width = (ctl >> 3) & 31;
        let types = bit_bytes(n, (ctl >> TYPE_SHIFT) & 7);
        let end = start
            + match ctl & 7 {
                RAW => n * 4,
                AR => 8 + types,
                FOR => 8 + bit_bytes(n, width) + types,
                EF => 48 + bit_bytes(n, width) + types,
                _ => unreachable!(),
            };
        data[previous_end..start].fill(0);
        encode_leaf(&mut data[start..end], &scratch[..n], plan.control);
        previous_end = end;
    }
    data.truncate(body);
    data[..8].copy_from_slice(&(body as u64).to_ne_bytes());
    for plan in plans {
        plan.write(&mut data);
    }
    Some(Encoded {
        data: release_slack(data),
        control: control(LEAVES, 0, tags),
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
    pub(super) raw_count: usize,
    working_bytes: usize,
}
fn ordered(hits: &[PackedHit]) -> bool {
    hits.windows(2).all(|pair| pair[0].key() <= pair[1].key())
}
fn prepare_part(
    mut hits: Vec<PackedHit>,
    base: u64,
    start: u64,
    end: u64,
    overlap: usize,
    last: bool,
) -> Part {
    if !ordered(&hits) {
        hits.sort_unstable_by_key(|hit| hit.key());
    }
    let head_end = hits.partition_point(|hit| base + (relative(*hit) as u64) < start);
    let tail_start = if last {
        hits.len()
    } else {
        hits.partition_point(|hit| {
            base + (relative(*hit) as u64)
                < end
                    .saturating_sub(HIT_LOOKBEHIND + overlap as u64)
                    .max(start)
        })
    };
    let tail = hits.split_off(tail_start);
    let head = hits.drain(..head_end).collect();
    Part {
        interior: encode(hits),
        head,
        tail,
    }
}
pub(super) fn prepare(
    batch: HitBuffer,
    start: u64,
    end: u64,
    overlap: usize,
    last: bool,
) -> Prepared {
    if batch.hits.is_empty() {
        return Prepared {
            start,
            base: batch.base,
            parts: std::array::from_fn(|_| Part {
                interior: None,
                head: Vec::new(),
                tail: Vec::new(),
            }),
            raw_count: 0,
            working_bytes: 0,
        };
    }
    let HitBuffer { base, mut hits } = batch;
    let mut footers = Vec::new();
    let mut raw_count = 0;
    if hits.iter().all(|hit| tag(*hit) == PATTERNS.len() as u8) {
        std::mem::swap(&mut hits, &mut footers);
    } else {
        hits.retain(|hit| {
            if tag(*hit) == PATTERNS.len() as u8 {
                footers.push(*hit);
                false
            } else {
                raw_count += usize::from(tag(*hit) != 12);
                true
            }
        });
    }
    let working_bytes = (hits.capacity() + footers.capacity()) * 4;
    Prepared {
        start,
        base,
        raw_count,
        working_bytes,
        parts: [
            prepare_part(hits, base, start, end, overlap, last),
            prepare_part(footers, base, start, end, overlap, last),
        ],
    }
}

pub(super) struct Builder {
    arena: Spool,
    slots: Option<Slots>,
    chunks: usize,
    chunk: u64,
    window: usize,
    arena_spilled: bool,
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
            arena_spilled: false,
            single: None,
        })
    }
    fn write_segment(&mut self, base: u64, encoded: Encoded) -> io::Result<Segment> {
        // Mapped arena starts at a page boundary. Individual EF leaves are
        // aligned relative to this aligned segment, with safe byte loads.
        let end = self.arena.seek(SeekFrom::End(0))?;
        let start = end.next_multiple_of(64);
        self.arena.write_all(&[0; 64][..(start - end) as usize])?;
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
        if !self.arena_spilled
            && self
                .arena
                .memory_bytes()
                .saturating_add(working)
                .saturating_add(slots)
                > MEMORY_BYTES
        {
            self.arena.spill()?;
            self.arena_spilled = true;
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
                if !self.arena_spilled
                    && self.arena.memory_bytes() + directory_bytes + slot_bytes > MEMORY_BYTES
                {
                    self.arena.spill()?;
                    self.arena_spilled = true;
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
            data: self.arena.finish()?,
            dirs: [a.finish()?, b.finish()?],
        })
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
                    let offset = data.len().next_multiple_of(64);
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
    fn leaf(self, segment: Segment, index: usize) -> (Leaf, usize, &'a [u8]) {
        let payload = &self.data[segment.payload as usize..];
        if segment.control as u32 & 7 != LEAVES {
            return (
                Leaf {
                    offset: 0,
                    last: (segment.last - segment.base) as u32,
                    control: segment.control as u32,
                },
                segment.count as usize,
                payload,
            );
        }
        let desc = word(payload, 0) as usize + index * DESC_BYTES;
        let leaf = Leaf::read(&payload[desc..]);
        (
            leaf,
            LEAF.min(segment.count as usize - index * LEAF),
            &payload[leaf.offset as usize..],
        )
    }
    pub(super) fn get(self, rank: usize) -> Option<RawHit> {
        let si = self.find_segment(rank);
        if si == self.segments() {
            return None;
        }
        let segment = self.segment(si);
        let local = rank - (segment.end - segment.count) as usize;
        let is_leaves = segment.control as u32 & 7 == LEAVES;
        let (leaf, n, data) = self.leaf(segment, if is_leaves { local / LEAF } else { 0 });
        let i = if is_leaves { local % LEAF } else { local };
        let (offset, pattern) = decode_one(data, leaf.control, n, i);
        Some(RawHit::new(segment.base + offset as u64, pattern))
    }
    pub(super) fn lower_bound(self, offset: u64) -> usize {
        let (mut lo, mut hi) = (0, self.segments());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.segment(mid).last < offset {
                lo = mid + 1
            } else {
                hi = mid
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
            let (mut a, mut b) = (0, (segment.count as usize).div_ceil(LEAF));
            while a < b {
                let mid = (a + b) / 2;
                if small(payload, directory + mid * DESC_BYTES + 8) < relative {
                    a = mid + 1
                } else {
                    b = mid
                }
            }
            index = a;
        }
        let (leaf, n, data) = self.leaf(segment, index);
        rank + index * LEAF + leaf_lower_bound(data, leaf.control, n, relative)
    }
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
fn decode_one(data: &[u8], ctl: u32, n: usize, i: usize) -> (u32, u8) {
    let codec = ctl & 7;
    if codec == RAW {
        let packed = small(data, i * 4);
        return (packed >> 4, (packed & 15) as u8);
    }
    let width = (ctl >> 3) & 31;
    let first = small(data, 0);
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
        _ => unreachable!(),
    };
    (offset, decode_type(&data[type_pos..], i, ctl))
}
fn leaf_lower_bound(data: &[u8], ctl: u32, n: usize, target: u32) -> usize {
    let codec = ctl & 7;
    if codec == AR {
        let first = small(data, 0);
        let step = small(data, 4);
        if target <= first {
            return 0;
        }
        return if step == 0 {
            n
        } else {
            ((target - first) as usize).div_ceil(step as usize).min(n)
        };
    }
    let (mut lo, mut hi) = (0, n);
    if codec == EF {
        let first = small(data, 0);
        if target <= first {
            return 0;
        }
        let width = (ctl >> 3) & 31;
        let value = target - first;
        let q = value >> width;
        let max_q = (small(data, 4) - n as u32 - 1) as u32;
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
                lo = mid + 1
            } else {
                hi = mid
            }
        }
        return lo;
    }
    while lo < hi {
        let mid = (lo + hi) / 2;
        let value = if codec == RAW {
            small(data, mid * 4) >> 4
        } else {
            small(data, 0) + get_bits(&data[8..], mid, (ctl >> 3) & 31)
        };
        if value < target {
            lo = mid + 1
        } else {
            hi = mid
        }
    }
    lo
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
}
impl<'a> Cursor<'a> {
    fn lower_bound_cached(&self, offset: u64) -> usize {
        if self.cache_len != 0 && offset <= self.base + self.offsets[self.cache_len - 1] as u64 {
            let rank = self.offsets[..self.cache_len]
                .partition_point(|&value| self.base + (value as u64) < offset);
            self.cache_start + rank
        } else {
            self.view.lower_bound(offset)
        }
    }
    pub(super) fn seek_ge(&mut self, offset: u64) {
        self.next = self.next.max(self.lower_bound_cached(offset));
    }
    pub(super) fn equal_offset<'b>(
        &'b mut self,
        offset: u64,
    ) -> impl Iterator<Item = RawHit> + use<'a, 'b> {
        self.seek_ge(offset);
        let end = offset
            .checked_add(1)
            .map_or(self.end, |end| self.lower_bound_cached(end));
        std::iter::from_fn(move || if self.next < end { self.next() } else { None })
    }
    fn load(&mut self) {
        let si = self.view.find_segment(self.next);
        let segment = self.view.segment(si);
        let start = (segment.end - segment.count) as usize;
        if mask(segment.control as u32) & self.tags == 0 {
            self.next = segment.end as usize;
            return;
        }
        let local = self.next - start;
        let chunk = local / LEAF;
        let leaves = segment.control as u32 & 7 == LEAVES;
        let (leaf, n, data) = self.view.leaf(segment, if leaves { chunk } else { 0 });
        if mask(leaf.control) & self.tags == 0 {
            self.next = (start + (chunk + 1) * LEAF).min(segment.end as usize);
            return;
        }
        self.cache_start = start + chunk * LEAF;
        self.cache_len = LEAF.min(segment.count as usize - chunk * LEAF);
        self.base = segment.base;
        let codec = leaf.control & 7;
        if codec == EF {
            let width = (leaf.control >> 3) & 31;
            let type_pos = 48 + bit_bytes(n, width);
            let first = small(data, 0);
            let mut rank = 0;
            let palette = palette(mask(leaf.control));
            let tw = (leaf.control >> TYPE_SHIFT) & 7;
            for wi in 0..4 {
                let mut high = word(data, 16 + wi * 8);
                while high != 0 {
                    let bit = wi * 64 + high.trailing_zeros() as usize;
                    self.offsets[rank] = first
                        + (((bit - rank) as u32) << width)
                        + get_bits(&data[48..], rank, width);
                    let t = get_bits(&data[type_pos..], rank, tw) as usize;
                    self.patterns[rank] = if tw == 4 { t as u8 } else { palette[t] };
                    rank += 1;
                    high &= high - 1;
                }
            }
            debug_assert_eq!(rank, n);
        } else {
            let first = if leaves { 0 } else { chunk * LEAF };
            for i in 0..self.cache_len {
                let (offset, pattern) = decode_one(data, leaf.control, n, first + i);
                self.offsets[i] = offset;
                self.patterns[i] = pattern;
            }
        }
    }
}
impl Iterator for Cursor<'_> {
    type Item = RawHit;
    fn next(&mut self) -> Option<RawHit> {
        while self.next < self.end {
            if self.next < self.cache_start || self.next >= self.cache_start + self.cache_len {
                self.load();
                if self.next < self.cache_start || self.next >= self.cache_start + self.cache_len {
                    continue;
                }
            }
            let i = self.next - self.cache_start;
            self.next += 1;
            if (1 << self.patterns[i]) & self.tags != 0 {
                return Some(RawHit::new(
                    self.base + self.offsets[i] as u64,
                    self.patterns[i],
                ));
            }
        }
        None
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
        let mut used = [false; 5];
        let mut random = 0x1234_5678u32;
        for mode in 0..8 {
            for count in [0, 1, 2, 127, 128, 129, 257, 4099] {
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
                        5 => u32::from(i % 128 == 127) * 50000 + random % 2,
                        6 => random % 4,
                        _ => random % 2,
                    };
                    hits.push(RawHit::new(
                        base + offset as u64,
                        match mode {
                            0 | 2 | 4 | 5 => 13,
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
                        for li in 0..(segment.count as usize).div_ceil(LEAF) {
                            let (leaf, _, _) = view.leaf(segment, li);
                            used[(leaf.control & 7) as usize] = true;
                        }
                    }
                }
                assert_view(view, &hits);
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
            let mut batch = HitBuffer {
                base,
                hits: Vec::new(),
            };
            for i in 0..10000 {
                random = random.wrapping_mul(1664525).wrapping_add(1013904223);
                let offset = start + (random as u64 % chunk as u64);
                let pattern = (i % 14) as u8;
                batch.push(RawHit::new(offset, pattern));
                expected[usize::from(pattern == 13)].push(RawHit::new(offset, pattern));
            }
            if ordinal != 0 {
                for (distance, pattern) in [(1, 9), (11, 13), (257, 9), (268, 9)] {
                    let hit = RawHit::new(start - distance, pattern);
                    batch.push(hit.clone());
                    expected[usize::from(pattern == 13)].push(hit);
                }
            }
            builder
                .push(prepare(
                    batch,
                    start,
                    start + chunk as u64,
                    11,
                    ordinal + 1 == chunks,
                ))
                .unwrap();
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
            let mut batch = HitBuffer {
                base: start,
                hits: Vec::new(),
            };
            batch.push(RawHit::new(start + 1000, 8));
            batch.push(RawHit::new(start + chunk - 1, 5));
            builder
                .push(prepare(
                    batch,
                    start,
                    start + chunk,
                    11,
                    ordinal + 1 == chunks,
                ))
                .unwrap();
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
