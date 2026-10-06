//! One structural LZ4 parser shared by routing, reports and embedded scanning.
//! Walk block lengths; do not decode or hash payload during archive analysis.
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::ffi::c_void;
use std::io::{self, Read, Seek, SeekFrom};

pub(crate) const MAGIC: &[u8] = b"\x04\x22\x4d\x18";
pub(crate) const LEGACY: &[u8] = b"\x02\x21\x4c\x18";
pub(crate) const MAX_RECORDS: usize = 1_000_000;
const MAX_FRAMES: usize = 65_536;
const LEGACY_MAX: u32 = 8 * 1024 * 1024 + (8 * 1024 * 1024 / 255) + 16;

unsafe extern "C" {
    fn SUNPACK_LZ4_XXH32(input: *const c_void, size: usize, seed: u32) -> u32;
    fn sup_lz4_decode(
        opaque: *mut c_void,
        read: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> isize,
        skip: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
        write: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> i32,
        dictionary: Option<
            unsafe extern "C" fn(*mut c_void, u32, i32, *mut *const c_void, *mut usize) -> i32,
        >,
        progress: Option<unsafe extern "C" fn(*mut c_void, u64, u64) -> i32>,
        result: *mut DecodeResult,
    ) -> i32;
}
pub(crate) fn xxh32(bytes: &[u8]) -> u32 {
    // The library reads exactly the supplied live slice; no retained pointers.
    unsafe { SUNPACK_LZ4_XXH32(bytes.as_ptr().cast(), bytes.len(), 0) }
}
pub(crate) fn skippable(magic: u32) -> bool {
    magic & 0xfffffff0 == 0x184d2a50
}
pub(crate) fn leading(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
        || bytes.starts_with(LEGACY)
        || bytes
            .get(..4)
            .is_some_and(|p| skippable(u32::from_le_bytes(p.try_into().unwrap())))
}

pub(crate) fn identity(reader: &ManagedReader, offset: u64) -> Result<bool, &'static str> {
    let limit = reader.len();
    let mut cursor = offset;
    for _ in 0..MAX_FRAMES {
        let magic = word(reader, cursor, limit)?;
        if skippable(magic) {
            let size = word(reader, cursor + 4, limit)?;
            advance(&mut cursor, 8 + u64::from(size), limit)?;
            continue;
        }
        if magic == 0x184c2102 {
            return Ok(cursor + 4 <= limit);
        }
        if magic != 0x184d2204 {
            return Ok(false);
        }
        let bytes = field(reader, cursor, ((limit - cursor).min(19)) as usize, limit)?;
        let header = parse_header(&bytes)?;
        let block = word(reader, cursor + header.len as u64, limit)?;
        return Ok(block & 0x7fffffff <= header.block_max);
    }
    Err("lz4_walk_budget_exhausted")
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) len: usize,
    pub(crate) block_max: u32,
    pub(crate) content_size: Option<u64>,
    pub(crate) dictionary_id: Option<u32>,
    pub(crate) block_checksum: bool,
    pub(crate) content_checksum: bool,
}
pub(crate) fn parse_header(bytes: &[u8]) -> Result<Header, &'static str> {
    if bytes.len() < 7 {
        return Err("lz4_header_truncated");
    }
    if !bytes.starts_with(MAGIC) {
        return Err("lz4_magic_not_found");
    }
    let (flags, bd) = (bytes[4], bytes[5]);
    if flags >> 6 != 1 {
        return Err("lz4_version_unsupported");
    }
    if flags & 2 != 0 || bd & 0x8f != 0 {
        return Err("lz4_reserved_bits_set");
    }
    let block_max = match (bd >> 4) & 7 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => return Err("lz4_block_size_invalid"),
    };
    let size_present = flags & 8 != 0;
    let dict_present = flags & 1 != 0;
    let len = 7 + if size_present { 8 } else { 0 } + if dict_present { 4 } else { 0 };
    if bytes.len() < len {
        return Err("lz4_header_truncated");
    }
    if (xxh32(&bytes[4..len - 1]) >> 8) as u8 != bytes[len - 1] {
        return Err("lz4_header_checksum_bad");
    }
    Ok(Header {
        len,
        block_max,
        content_size: size_present.then(|| u64::from_le_bytes(bytes[6..14].try_into().unwrap())),
        dictionary_id: dict_present
            .then(|| u32::from_le_bytes(bytes[len - 5..len - 1].try_into().unwrap())),
        block_checksum: flags & 16 != 0,
        content_checksum: flags & 4 != 0,
    })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Index {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) frames: usize,
    pub(crate) skips: usize,
    pub(crate) legacy_frames: usize,
    pub(crate) content_checksums: usize,
    pub(crate) block_checksums: usize,
    pub(crate) blocks: usize,
    pub(crate) decoded_size: Option<u64>,
    pub(crate) dictionaries: Vec<u32>,
    pub(crate) complete: bool,
    pub(crate) error: &'static str,
}
fn field(
    reader: &ManagedReader,
    cursor: u64,
    n: usize,
    limit: u64,
) -> Result<Vec<u8>, &'static str> {
    if cursor.checked_add(n as u64).is_none_or(|end| end > limit) {
        return Err("lz4_stream_truncated");
    }
    let data = reader.read_cached_at(cursor, n).map_err(|_| "os_error")?;
    if data.len() != n {
        return Err("lz4_stream_truncated");
    }
    Ok(data.as_slice().to_vec())
}
fn word(reader: &ManagedReader, cursor: u64, limit: u64) -> Result<u32, &'static str> {
    if cursor.checked_add(4).is_none_or(|end| end > limit) {
        return Err("lz4_stream_truncated");
    }
    let data = reader.read_cached_at(cursor, 4).map_err(|_| "os_error")?;
    let bytes: [u8; 4] = data
        .as_slice()
        .try_into()
        .map_err(|_| "lz4_stream_truncated")?;
    Ok(u32::from_le_bytes(bytes))
}
fn advance(cursor: &mut u64, n: u64, limit: u64) -> Result<(), &'static str> {
    *cursor = cursor.checked_add(n).ok_or("lz4_size_overflow")?;
    if *cursor > limit {
        return Err("lz4_stream_truncated");
    }
    Ok(())
}
pub(crate) fn walk(reader: &ManagedReader, offset: u64, limit: u64) -> Index {
    let mut index = Index {
        start: offset,
        end: offset,
        decoded_size: Some(0),
        ..Index::default()
    };
    let result = walk_inner(reader, limit.min(reader.len()), &mut index);
    index.error = result.err().unwrap_or("");
    index.complete = index.error.is_empty() && index.frames > 0;
    index
}
fn walk_inner(reader: &ManagedReader, limit: u64, index: &mut Index) -> Result<(), &'static str> {
    let mut cursor = index.start;
    let mut dictionary_ids = std::collections::BTreeSet::new();
    loop {
        if cursor == limit {
            index.end = cursor;
            return Ok(());
        }
        if index.frames + index.skips >= MAX_FRAMES {
            return Err("lz4_walk_budget_exhausted");
        }
        if limit - cursor < 4 {
            // A partial known magic is a truncated next frame, not carrier junk.
            let tail = field(reader, cursor, (limit - cursor) as usize, limit)?;
            if MAGIC.starts_with(&tail)
                || LEGACY.starts_with(&tail)
                || tail.first().is_some_and(|b| (0x50..=0x5f).contains(b))
                    && b"\x2a\x4d\x18".starts_with(&tail[1..])
            {
                return Err("lz4_stream_truncated");
            }
            if index.frames > 0 {
                return Ok(());
            }
            return Err("lz4_magic_not_found");
        }
        let magic = word(reader, cursor, limit)?;
        if skippable(magic) {
            let size = word(reader, cursor + 4, limit)?;
            advance(&mut cursor, 8 + u64::from(size), limit)?;
            index.skips += 1;
            index.end = cursor;
            continue;
        }
        if magic == 0x184d2204 {
            let header = field(reader, cursor, ((limit - cursor).min(19)) as usize, limit)?;
            let header = parse_header(&header)?;
            advance(&mut cursor, header.len as u64, limit)?;
            loop {
                if index.blocks >= MAX_RECORDS {
                    return Err("lz4_walk_budget_exhausted");
                }
                let value = word(reader, cursor, limit)?;
                advance(&mut cursor, 4, limit)?;
                if value == 0 {
                    break;
                }
                let size = value & 0x7fffffff;
                if size > header.block_max || (size == 0 && value & 0x80000000 == 0) {
                    return Err("lz4_block_size_invalid");
                }
                advance(
                    &mut cursor,
                    u64::from(size) + if header.block_checksum { 4 } else { 0 },
                    limit,
                )?;
                index.blocks += 1;
            }
            if header.content_checksum {
                advance(&mut cursor, 4, limit)?;
                index.content_checksums += 1;
            }
            if header.block_checksum {
                index.block_checksums += 1;
            }
            if let Some(id) = header.dictionary_id {
                if dictionary_ids.insert(id) {
                    index.dictionaries.push(id);
                }
            }
            index.decoded_size = match (index.decoded_size, header.content_size) {
                (Some(a), Some(b)) => Some(a.checked_add(b).ok_or("lz4_size_overflow")?),
                _ => None,
            };
        } else if magic == 0x184c2102 {
            advance(&mut cursor, 4, limit)?;
            loop {
                if cursor == limit {
                    break;
                }
                if index.blocks >= MAX_RECORDS {
                    return Err("lz4_walk_budget_exhausted");
                }
                let size = word(reader, cursor, limit).map_err(|error| {
                    if error == "os_error" {
                        error
                    } else {
                        "lz4_legacy_boundary_unknown"
                    }
                })?;
                if size == 0x184d2204 || size == 0x184c2102 || skippable(size) {
                    break;
                }
                if size == 0 {
                    advance(&mut cursor, 4, limit)?;
                    break;
                }
                if size > LEGACY_MAX {
                    return Err("lz4_legacy_boundary_unknown");
                }
                advance(&mut cursor, 4 + u64::from(size), limit)
                    .map_err(|_| "lz4_legacy_boundary_unknown")?;
                index.blocks += 1;
            }
            index.legacy_frames += 1;
            index.decoded_size = None;
        } else {
            if index.frames > 0 {
                return Ok(());
            }
            return Err("lz4_magic_not_found");
        }
        index.frames += 1;
        index.end = cursor;
    }
}
impl Index {
    pub(crate) fn to_dict<'py>(
        &self,
        py: Python<'py>,
        file_size: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "lz4")?;
        result.set_item("ext", ".lz4")?;
        result.set_item("file_size", file_size)?;
        result.set_item(
            "magic_matched",
            self.frames > 0
                || self.error.starts_with("lz4_") && self.error != "lz4_magic_not_found",
        )?;
        result.set_item(
            "plausible",
            self.frames > 0 || self.error == "lz4_legacy_boundary_unknown",
        )?;
        result.set_item("error", self.error)?;
        result.set_item(
            "damage_flags",
            if self.error.is_empty() {
                vec![]
            } else {
                vec![self.error]
            },
        )?;
        result.set_item("evidence", vec!["lz4:frame_structure"])?;
        result.set_item(
            "structure_status",
            if self.complete {
                "complete"
            } else {
                "incomplete"
            },
        )?;
        result.set_item("structure_validation_complete", self.complete)?;
        result.set_item("boundary_exact", self.complete)?;
        result.set_item("segment_end", self.complete.then_some(self.end))?;
        result.set_item("archive.trailing_data", file_size.saturating_sub(self.end))?;
        result.set_item(
            "integrity_status",
            if self.content_checksums + self.block_checksums > 0 {
                "deferred"
            } else {
                "not_present"
            },
        )?;
        result.set_item("integrity_validation_complete", false)?;
        result.set_item(
            "checksum_present",
            self.content_checksums + self.block_checksums > 0,
        )?;
        result.set_item("structure.stream_count", self.frames)?;
        result.set_item("structure.block_count", self.blocks)?;
        result.set_item("structure.decoded_size", self.decoded_size)?;
        result.set_item(
            "information_required",
            self.error == "lz4_legacy_boundary_unknown",
        )?;
        let plan = PyDict::new(py);
        plan.set_item("input_bytes", self.end.saturating_sub(self.start))?;
        plan.set_item("frames", self.frames)?;
        plan.set_item("skippable_frames", self.skips)?;
        plan.set_item("legacy_frames", self.legacy_frames)?;
        plan.set_item("content_checked_frames", self.content_checksums)?;
        plan.set_item("block_checked_frames", self.block_checksums)?;
        plan.set_item("expected_size", self.decoded_size)?;
        plan.set_item("complete", self.complete)?;
        plan.set_item("dictionary_ids", &self.dictionaries)?;
        result.set_item("stream_plan", plan)?;
        Ok(result)
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct DecodeResult {
    pub(crate) input_bytes: u64,
    pub(crate) output_bytes: u64,
    pub(crate) frames: u64,
    pub(crate) skippable_frames: u64,
    pub(crate) content_checked_frames: u64,
    pub(crate) block_checked_frames: u64,
    pub(crate) legacy_frames: u64,
    pub(crate) dictionary_id: u32,
    pub(crate) error: i32,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Dictionaries {
    pub(crate) default: String,
    pub(crate) by_id: std::collections::BTreeMap<u32, String>,
}
impl Dictionaries {
    pub(crate) fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("default_dictionary", &self.default)?;
        let entries = pyo3::types::PyList::empty(py);
        for (id, path) in &self.by_id {
            let entry = PyDict::new(py);
            entry.set_item("id", id)?;
            entry.set_item("path", path)?;
            entries.append(entry)?;
        }
        result.set_item("dictionaries", entries)?;
        Ok(result)
    }
}
struct Sample<R> {
    reader: R,
    output: Vec<u8>,
    limit: usize,
    stopped: bool,
    error: Option<io::Error>,
    dictionaries: Dictionaries,
    dictionary: Vec<u8>,
    dictionary_key: Option<u64>,
    input_remaining: u64,
    read_remaining: u64,
}
unsafe extern "C" fn sample_read<R: Read>(
    opaque: *mut c_void,
    dst: *mut c_void,
    n: usize,
) -> isize {
    let state = &mut *opaque.cast::<Sample<R>>();
    let n = n.min(
        state
            .input_remaining
            .min(state.read_remaining)
            .min(usize::MAX as u64) as usize,
    );
    match state
        .reader
        .read(std::slice::from_raw_parts_mut(dst.cast(), n))
    {
        Ok(n) => {
            state.input_remaining -= n as u64;
            state.read_remaining -= n as u64;
            n as isize
        }
        Err(e) => {
            state.error = Some(e);
            -1
        }
    }
}
unsafe extern "C" fn sample_write<R: Read>(
    opaque: *mut c_void,
    src: *const c_void,
    n: usize,
) -> i32 {
    let state = &mut *opaque.cast::<Sample<R>>();
    let take = n.min(state.limit - state.output.len());
    state
        .output
        .extend_from_slice(std::slice::from_raw_parts(src.cast(), take));
    if state.output.len() == state.limit {
        state.stopped = true;
        1
    } else {
        0
    }
}
pub(crate) fn sample<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, &'static str> {
    sample_with_dictionaries(reader, limit, &Dictionaries::default())
}
unsafe extern "C" fn sample_dictionary<R: Read>(
    opaque: *mut c_void,
    id: u32,
    has_id: i32,
    data: *mut *const c_void,
    size: *mut usize,
) -> i32 {
    let state = &mut *opaque.cast::<Sample<R>>();
    let keyed = has_id != 0;
    let key = if keyed { u64::from(id) } else { 1u64 << 32 };
    if state.dictionary_key == Some(key) {
        *data = state.dictionary.as_ptr().cast();
        *size = state.dictionary.len();
        return 1;
    }
    let path = if keyed {
        state.dictionaries.by_id.get(&id)
    } else {
        Some(&state.dictionaries.default)
    };
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        return 0;
    };
    let result = (|| -> io::Result<()> {
        let mut file = std::fs::File::open(path)?;
        let length = file.metadata()?.len();
        let tail = length.min(65536) as usize;
        file.seek(SeekFrom::Start(length - tail as u64))?;
        state.dictionary.resize(tail, 0);
        file.read_exact(&mut state.dictionary)?;
        Ok(())
    })();
    if let Err(e) = result {
        state.error = Some(e);
        return -1;
    }
    state.dictionary_key = Some(key);
    *data = state.dictionary.as_ptr().cast();
    *size = state.dictionary.len();
    1
}
pub(crate) fn sample_with_dictionaries<R: Read>(
    reader: R,
    limit: usize,
    dictionaries: &Dictionaries,
) -> Result<Vec<u8>, &'static str> {
    let state = Sample {
        reader,
        output: Vec::with_capacity(limit),
        limit,
        stopped: false,
        error: None,
        dictionaries: dictionaries.clone(),
        dictionary: Vec::new(),
        dictionary_key: None,
        input_remaining: u64::MAX,
        read_remaining: u64::MAX,
    };
    run_sample(state, None)
}
unsafe extern "C" fn sample_skip<R: Read + Seek>(opaque: *mut c_void, n: u64) -> i32 {
    let state = &mut *opaque.cast::<Sample<R>>();
    if n > state.input_remaining {
        return 1;
    }
    if n > i64::MAX as u64 {
        return -1;
    }
    match state.reader.seek(SeekFrom::Current(n as i64)) {
        Ok(_) => {
            state.input_remaining -= n;
            0
        }
        Err(e) => {
            state.error = Some(e);
            -1
        }
    }
}
pub(crate) fn sample_seekable<R: Read + Seek>(
    reader: R,
    limit: usize,
    input_limit: u64,
    read_budget: u64,
    dictionaries: &Dictionaries,
) -> Result<Vec<u8>, &'static str> {
    let state = Sample {
        reader,
        output: Vec::with_capacity(limit),
        limit,
        stopped: false,
        error: None,
        dictionaries: dictionaries.clone(),
        dictionary: Vec::new(),
        dictionary_key: None,
        input_remaining: input_limit,
        read_remaining: read_budget,
    };
    run_sample(state, Some(sample_skip::<R>))
}
fn run_sample<R: Read>(
    mut state: Sample<R>,
    skip: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
) -> Result<Vec<u8>, &'static str> {
    let mut result = DecodeResult::default();
    let rc = unsafe {
        sup_lz4_decode(
            (&mut state as *mut Sample<R>).cast(),
            sample_read::<R>,
            skip,
            sample_write::<R>,
            Some(sample_dictionary::<R>),
            None,
            &mut result,
        )
    };
    if state.stopped || rc == 0 {
        Ok(state.output)
    } else {
        Err(if rc == 5 || rc == 8 {
            "lz4_dictionary_required"
        } else {
            "lz4_decompression_probe_failed"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::reader::ReaderConfig;
    pub(super) fn frame(
        payload: &[u8],
        flags: u8,
        bd: u8,
        size: Option<u64>,
        dict: Option<u32>,
    ) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[flags, bd]);
        if let Some(size) = size {
            out.extend_from_slice(&size.to_le_bytes());
        }
        if let Some(id) = dict {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out.push((xxh32(&out[4..]) >> 8) as u8);
        if !payload.is_empty() {
            out.extend_from_slice(&(0x80000000 | payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
            if flags & 16 != 0 {
                out.extend_from_slice(&xxh32(payload).to_le_bytes());
            }
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        if flags & 4 != 0 {
            out.extend_from_slice(&xxh32(payload).to_le_bytes());
        }
        out
    }
    pub(super) fn index(data: Vec<u8>, start: u64) -> Index {
        let reader = ManagedReader::from_bytes(data, ReaderConfig::default());
        walk(&reader, start, reader.len())
    }
    #[test]
    fn empty_raw_block_and_partial_next_skippable_are_distinct() {
        let mut bytes = frame(b"", 0x5c, 0x40, Some(0), None);
        let at = parse_header(&bytes).unwrap().len;
        let mut block = 0x80000000u32.to_le_bytes().to_vec();
        block.extend_from_slice(&xxh32(b"").to_le_bytes());
        bytes.splice(at..at, block);
        let parsed = index(bytes.clone(), 0);
        assert!(parsed.complete);
        assert_eq!(parsed.blocks, 1);
        assert_eq!(sample(std::io::Cursor::new(&bytes), 1).unwrap(), b"");
        for magic in 0x50..=0x5fu8 {
            for n in 1..4 {
                let mut truncated = bytes.clone();
                truncated.extend_from_slice(&[magic, 0x2a, 0x4d][..n]);
                assert_eq!(index(truncated, 0).error, "lz4_stream_truncated");
            }
        }
    }
    #[test]
    fn all_header_layouts_preserve_known_zero_and_dictionary_id() {
        for block in 4..=7 {
            for option in 0..32 {
                let flags = 0x40 | option;
                if flags & 2 != 0 {
                    continue;
                }
                let size = (flags & 8 != 0).then_some(0);
                let dict = (flags & 1 != 0).then_some(123);
                let bytes = frame(b"", flags, block << 4, size, dict);
                let header = parse_header(&bytes).unwrap();
                assert_eq!(header.content_size, size);
                assert_eq!(header.dictionary_id, dict);
                let parsed = index(bytes, 0);
                assert!(parsed.complete, "{parsed:?}");
                assert_eq!(parsed.frames, 1);
            }
        }
    }
    #[test]
    fn concatenated_skip_bounds_and_trailing_carrier() {
        let skip = [0x5f, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 0, 1, 2];
        let a = frame(b"hello", 0x7c, 0x40, Some(5), None);
        let mut bytes = vec![0x88; 31];
        bytes.extend_from_slice(&skip);
        bytes.extend_from_slice(&a);
        bytes.extend_from_slice(&skip);
        bytes.extend_from_slice(&a);
        let end = bytes.len();
        bytes.extend_from_slice(b"carrier-tail");
        let parsed = index(bytes, 31);
        assert!(parsed.complete);
        assert_eq!(parsed.end, end as u64);
        assert_eq!(parsed.frames, 2);
        assert_eq!(parsed.skips, 2);
        assert_eq!(parsed.decoded_size, Some(10));
        assert_eq!(parsed.content_checksums, 2);
        assert_eq!(parsed.block_checksums, 2);
    }
    #[test]
    fn header_corruption_truncation_and_size_limits_fail_closed() {
        let original = frame(b"hello", 0x7c, 0x40, Some(5), None);
        for length in 4..original.len() {
            assert!(!index(original[..length].to_vec(), 0).complete);
        }
        let mut bytes = original.clone();
        bytes[14] ^= 1;
        assert_eq!(index(bytes, 0).error, "lz4_header_checksum_bad");
        let mut bytes = original;
        bytes[15..19].copy_from_slice(&0x80010001u32.to_le_bytes());
        assert_eq!(index(bytes, 0).error, "lz4_block_size_invalid");
        let mut header = frame(b"", 0x60, 0x40, None, None);
        header[5] = 0x80;
        assert_eq!(parse_header(&header).unwrap_err(), "lz4_reserved_bits_set");
    }
    #[test]
    fn legacy_tail_is_information_required_and_explicit_eof_is_usable() {
        // A compressed literal-only block: token + five bytes.
        let mut bytes = LEGACY.to_vec();
        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(b"\x50hello");
        let parsed = index(bytes.clone(), 0);
        assert!(parsed.complete);
        assert_eq!(parsed.legacy_frames, 1);
        assert_eq!(
            sample(std::io::Cursor::new(&bytes), 1024).unwrap(),
            b"hello"
        );
        bytes.extend_from_slice(b"trailing carrier");
        let parsed = index(bytes, 0);
        assert!(!parsed.complete);
        assert_eq!(parsed.error, "lz4_legacy_boundary_unknown");
    }
    #[test]
    fn sample_checks_checksum_and_returns_bounded_prefix() {
        let payload = vec![b'x'; 60000];
        let mut bytes = frame(&payload, 0x74, 0x40, None, None);
        assert_eq!(
            sample(std::io::Cursor::new(&bytes), 1024).unwrap().len(),
            1024
        );
        assert_eq!(
            sample(std::io::Cursor::new(&bytes), 65536).unwrap(),
            payload
        );
        *bytes.last_mut().unwrap() ^= 1;
        assert!(sample(std::io::Cursor::new(&bytes), 65536).is_err());
    }
    #[test]
    fn explicit_zero_dictionary_id_never_uses_the_default() {
        let bytes = frame(b"hello", 0x61, 0x40, None, Some(0));
        assert_eq!(index(bytes.clone(), 0).dictionaries, [0]);
        let dictionaries = Dictionaries {
            default: "default-must-not-be-opened".into(),
            ..Dictionaries::default()
        };
        assert_eq!(
            sample_with_dictionaries(std::io::Cursor::new(&bytes), 32, &dictionaries),
            Err("lz4_dictionary_required")
        );
        // The missing dependency is required even when this frame's blocks
        // happen to contain only literals and could decode without a dictionary.
        assert_eq!(
            sample(std::io::Cursor::new(&bytes), 32),
            Err("lz4_dictionary_required")
        );
        let mut state = Sample {
            reader: std::io::Cursor::new(&bytes),
            output: Vec::new(),
            limit: 32,
            stopped: false,
            error: None,
            dictionaries,
            dictionary: Vec::new(),
            dictionary_key: None,
            input_remaining: u64::MAX,
            read_remaining: u64::MAX,
        };
        let mut data = std::ptr::null();
        let mut size = 0;
        let opaque = (&mut state as *mut Sample<_>).cast();
        assert_eq!(
            unsafe {
                sample_dictionary::<std::io::Cursor<&Vec<u8>>>(opaque, 0, 1, &mut data, &mut size)
            },
            0
        );
        assert!(
            state.error.is_none(),
            "an explicit ID must not open the default path"
        );
    }
}

#[cfg(test)]
#[path = "lz4_differential_tests.rs"]
mod differential_tests;
