//! One structural LZ4 parser shared by routing, reports and embedded scanning.
//! Walk block lengths; do not decode or hash payload during archive analysis.
use crate::io::reader::ManagedReader;
use std::ffi::c_void;
use std::io::Read;

pub(crate) const MAGIC: &[u8] = b"\x04\x22\x4d\x18";

unsafe extern "C" {
    fn SUNPACK_LZ4_XXH32(input: *const c_void, size: usize, seed: u32) -> u32;
    fn sup_lz4_decode(
        opaque: *mut c_void,
        read: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> isize,
        skip: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
        write: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> i32,
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
        || bytes
            .get(..4)
            .is_some_and(|p| skippable(u32::from_le_bytes(p.try_into().unwrap())))
}

pub(crate) fn identity(
    prefix: &[u8],
    limit: u64,
    mut read: impl FnMut(u64, usize) -> std::io::Result<Vec<u8>>,
) -> Result<bool, &'static str> {
    // A maximal frame header and its first block word fit in 23 bytes.
    // Reuse the filesystem's prefix unless a skippable frame jumps past it.
    let mut window;
    let mut head = &prefix[..limit.min(prefix.len() as u64) as usize];
    let mut offset = 0;
    loop {
        let needed = (limit - offset).min(23) as usize;
        if head.len() < needed {
            // Batch runs of short skippable headers as well as isolated ones.
            let size = (limit - offset).min(4096) as usize;
            window = read(offset, size).map_err(|_| "os_error")?;
            head = &window;
        }
        let word = |at: usize| {
            head.get(at..at + 4)
                .map(|p| u32::from_le_bytes(p.try_into().unwrap()))
                .ok_or("lz4_stream_truncated")
        };
        let magic = word(0)?;
        if skippable(magic) {
            let span = 8 + u64::from(word(4)?);
            advance(&mut offset, span, limit)?;
            head = usize::try_from(span)
                .ok()
                .and_then(|span| head.get(span..))
                .unwrap_or_default();
            continue;
        }
        if magic != 0x184d2204 {
            return Ok(false);
        }
        let header = parse_header(head)?;
        let block = word(header.len)?;
        return Ok(header.block_span(block).is_ok());
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) len: usize,
    pub(crate) block_max: u32,
    pub(crate) content_size: Option<u64>,
    pub(crate) block_checksum: bool,
    pub(crate) content_checksum: bool,
}

impl Header {
    /// Number of bytes after the size field, including the relevant checksum.
    pub(crate) fn block_span(&self, value: u32) -> Result<u64, &'static str> {
        if value == 0 {
            return Ok(if self.content_checksum { 4 } else { 0 });
        }
        let size = value & 0x7fff_ffff;
        if size > self.block_max {
            return Err("lz4_block_size_invalid");
        }
        Ok(u64::from(size) + if self.block_checksum { 4 } else { 0 })
    }
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
        block_checksum: flags & 16 != 0,
        content_checksum: flags & 4 != 0,
    })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Index {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) frames: usize,
    #[cfg(test)]
    pub(crate) skips: usize,
    #[cfg(test)]
    pub(crate) content_checksums: usize,
    #[cfg(test)]
    pub(crate) block_checksums: usize,
    #[cfg(test)]
    pub(crate) blocks: usize,
    pub(crate) decoded_size: Option<u64>,
    pub(crate) complete: bool,
    pub(crate) error: &'static str,
}
// One bounded window per parse, never a process-wide cache. Length jumps still
// skip payload, including large skippable frames and virtual multi-volume input.
struct StructureReader<'a> {
    reader: &'a ManagedReader,
    limit: u64,
    window_bytes: usize,
    start: u64,
    window: Vec<u8>,
}

impl<'a> StructureReader<'a> {
    fn new(reader: &'a ManagedReader, limit: u64, window_bytes: usize) -> Self {
        Self {
            reader,
            limit,
            window_bytes,
            start: 0,
            window: Vec::new(),
        }
    }

    fn field(&mut self, cursor: u64, n: usize) -> Result<&[u8], &'static str> {
        let end = cursor.checked_add(n as u64).ok_or("lz4_size_overflow")?;
        if end > self.limit {
            return Err("lz4_stream_truncated");
        }
        if cursor < self.start || end > self.start + self.window.len() as u64 {
            // Nearby headers can land just past the window after a short
            // compressed block. Grow for those too, while long payload
            // jumps still start with a small probe.
            let previous = self.window.len();
            let window_bytes = if !self.window.is_empty()
                && cursor >= self.start
                && cursor - self.start <= (previous + previous.min(256)) as u64
            {
                (previous * 4).min(self.window_bytes)
            } else {
                self.window_bytes.min(256)
            };
            self.start = cursor;
            let wanted = (self.limit - cursor).min(window_bytes as u64) as usize;
            self.window
                .try_reserve_exact(wanted.saturating_sub(previous))
                .map_err(|_| "os_error")?;
            self.window.resize(wanted, 0);
            let mut read = 0;
            while read < wanted {
                let count = self.reader
                    .read_into_at(cursor + read as u64, &mut self.window[read..])
                    .map_err(|_| "os_error")?;
                if count == 0 {
                    break;
                }
                read += count;
            }
            self.window.truncate(read);
        }
        let from = (cursor - self.start) as usize;
        self.window
            .get(from..from + n)
            .ok_or("lz4_stream_truncated")
    }

    fn word(&mut self, cursor: u64) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.field(cursor, 4)?.try_into().unwrap(),
        ))
    }
}
fn advance(cursor: &mut u64, n: u64, limit: u64) -> Result<(), &'static str> {
    *cursor = cursor.checked_add(n).ok_or("lz4_size_overflow")?;
    if *cursor > limit {
        return Err("lz4_stream_truncated");
    }
    Ok(())
}
#[cfg(test)]
fn walk(reader: &ManagedReader, offset: u64, limit: u64) -> Index {
    walk_observed(reader, offset, limit, &mut |_| Ok(()))
}

pub(crate) fn walk_observed(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    visit: &mut dyn FnMut(u64) -> Result<(), &'static str>,
) -> Index {
    let mut index = Index {
        start: offset,
        end: offset,
        decoded_size: Some(0),
        ..Index::default()
    };
    let mut input = StructureReader::new(reader, limit.min(reader.len()), 16 * 1024);
    let result = walk_inner(&mut input, &mut index, visit);
    index.error = result.err().unwrap_or("");
    index.complete = index.error.is_empty() && index.frames > 0;
    index
}
fn walk_inner(
    input: &mut StructureReader<'_>,
    index: &mut Index,
    visit: &mut dyn FnMut(u64) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let limit = input.limit;
    let mut cursor = index.start;
    loop {
        if cursor == limit {
            index.end = cursor;
            return Ok(());
        }
        // Share only actual frame nodes. Bytes skipped as payload can contain
        // independent archives and must never inherit this suffix's failure.
        visit(cursor)?;
        if limit - cursor < 4 {
            // A partial known magic is a truncated next frame, not carrier junk.
            let tail = input.field(cursor, (limit - cursor) as usize)?;
            if MAGIC.starts_with(tail)
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
        let magic = input.word(cursor)?;
        if skippable(magic) {
            let size = input.word(cursor + 4)?;
            advance(&mut cursor, 8 + u64::from(size), limit)?;
            #[cfg(test)]
            { index.skips += 1; }
            index.end = cursor;
            continue;
        }
        if magic == 0x184d2204 {
            let header = parse_header(input.field(cursor, ((limit - cursor).min(19)) as usize)?)?;
            advance(&mut cursor, header.len as u64, limit)?;
            loop {
                let value = input.word(cursor)?;
                advance(&mut cursor, 4 + header.block_span(value)?, limit)?;
                if value == 0 {
                    break;
                }
                #[cfg(test)]
                { index.blocks += 1; }
            }
            if header.content_checksum {
                #[cfg(test)]
                { index.content_checksums += 1; }
            }
            #[cfg(test)]
            if header.block_checksum {
                index.block_checksums += 1;
            }
            index.decoded_size = match (index.decoded_size, header.content_size) {
                (Some(a), Some(b)) => Some(a.checked_add(b).ok_or("lz4_size_overflow")?),
                _ => None,
            };
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
#[repr(C)]
#[derive(Default)]
pub(crate) struct DecodeResult {
    pub(crate) input_bytes: u64,
    pub(crate) output_bytes: u64,
    pub(crate) frames: u64,
    pub(crate) skippable_frames: u64,
    pub(crate) content_checked_frames: u64,
    pub(crate) block_checked_frames: u64,
    pub(crate) error: i32,
}
pub(crate) fn decode_into<R: Read, W: std::io::Write>(reader: R, writer: W) -> std::io::Result<()> {
    struct State<R, W> {
        reader: R,
        writer: W,
        error: Option<std::io::Error>,
    }
    unsafe extern "C" fn read<R: Read, W>(state: *mut c_void, dst: *mut c_void, n: usize) -> isize {
        let state = &mut *state.cast::<State<R, W>>();
        match state
            .reader
            .read(std::slice::from_raw_parts_mut(dst.cast(), n))
        {
            Ok(n) => n as isize,
            Err(error) => {
                state.error = Some(error);
                -1
            }
        }
    }
    unsafe extern "C" fn write<R, W: std::io::Write>(
        state: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> i32 {
        let state = &mut *state.cast::<State<R, W>>();
        match state
            .writer
            .write_all(std::slice::from_raw_parts(src.cast(), n))
        {
            Ok(()) => 0,
            Err(error) => {
                state.error = Some(error);
                -1
            }
        }
    }
    let mut state = State {
        reader,
        writer,
        error: None,
    };
    let rc = unsafe {
        sup_lz4_decode(
            (&mut state as *mut State<R, W>).cast(),
            read::<R, W>,
            None,
            write::<R, W>,
            None,
            &mut DecodeResult::default(),
        )
    };
    if let Some(error) = state.error {
        return Err(error);
    }
    if rc != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "LZ4 frame validation failed",
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../tests/unit/formats/lz4/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/formats/lz4/lz4_differential_tests.rs"]
mod differential_tests;
