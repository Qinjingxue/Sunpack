//! Shared binary persistence envelope. No text formats or format migration.
use crate::io::scratch::{Blob, Spool};
use crc32fast::Hasher;
use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};

pub(crate) const FILE_HEADER_BYTES: u64 = 16;
pub(crate) const FRAME_HEADER_BYTES: usize = 16;
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Kind {
    TaskWal = 1,
    CatalogWal = 2,
    TaskSnapshot = 3,
    CatalogSnapshot = 4,
}

pub(crate) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(crate) fn file_header(kind: Kind) -> [u8; 16] {
    let mut header = [0; 16];
    header[..4].copy_from_slice(b"SPWL");
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
    header
}

// MORE fragments share one sequence. Only the final CRC commits the transaction.
const MORE: u32 = 1 << 31;
const WRITE_FRAME_BYTES: usize = 1024 * 1024;
struct Fragments<'a, W> {
    output: &'a mut W,
    seq: u64,
    buffer: Vec<u8>,
}
impl<W: Write> Fragments<'_, W> {
    fn emit(&mut self, more: bool) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Err(invalid("empty WAL transaction"));
        }
        let mut header = [0; FRAME_HEADER_BYTES];
        let len = self.buffer.len() as u32 | if more { MORE } else { 0 };
        header[..4].copy_from_slice(&len.to_le_bytes());
        header[4..12].copy_from_slice(&self.seq.to_le_bytes());
        let mut hash = Hasher::new();
        hash.update(&header[..12]);
        hash.update(&self.buffer);
        header[12..].copy_from_slice(&hash.finalize().to_le_bytes());
        self.output.write_all(&header)?;
        self.output.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }
}
impl<W: Write> Write for Fragments<'_, W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        while !bytes.is_empty() {
            if self.buffer.len() == WRITE_FRAME_BYTES {
                self.emit(true)?;
            }
            let take = bytes.len().min(WRITE_FRAME_BYTES - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn append_frame<W: Write>(
    output: &mut W,
    seq: u64,
    encode: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let mut writer = Fragments {
        output,
        seq,
        buffer: Vec::new(),
    };
    encode(&mut writer)?;
    writer.emit(false)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    let mut cursor = Cursor::new(bytes);
    let value = T::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor)).map_err(invalid)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid("trailing WAL payload"));
    }
    Ok(value)
}

/// Reuses one payload buffer. Only an incomplete final frame may be discarded.
pub(crate) struct Reader<R> {
    input: BufReader<R>,
    end: u64,
    pub valid_end: u64,
    pub torn: bool,
    pub payload: Blob,
}
impl<R: Read + Seek> Reader<R> {
    pub fn new(mut input: R, kind: Kind) -> io::Result<Self> {
        let end = input.seek(SeekFrom::End(0))?;
        input.rewind()?;
        let mut input = BufReader::new(input);
        let mut header = [0; 16];
        let available = end.min(FILE_HEADER_BYTES) as usize;
        input.read_exact(&mut header[..available])?;
        if header[..available] != file_header(kind)[..available] {
            return Err(invalid("unsupported binary WAL header"));
        }
        Ok(Self {
            input,
            end,
            valid_end: if available == 16 { 16 } else { 0 },
            torn: available != 16,
            payload: Vec::new().into(),
        })
    }
    pub fn next(&mut self) -> io::Result<Option<u64>> {
        if self.torn || self.valid_end == self.end {
            return Ok(None);
        }
        let mut cursor = self.valid_end;
        let mut payload = Spool::default();
        let mut sequence = None;
        let mut buffer = vec![0; BUFFER_BYTES];
        loop {
            if self.end - cursor < FRAME_HEADER_BYTES as u64 {
                self.torn = true;
                return Ok(None);
            }
            let mut header = [0; FRAME_HEADER_BYTES];
            self.input.read_exact(&mut header)?;
            let framed_len = u32::from_le_bytes(header[..4].try_into().unwrap());
            let len = (framed_len & !MORE) as usize;
            let seq = u64::from_le_bytes(header[4..12].try_into().unwrap());
            if len == 0 || len > MAX_FRAME_BYTES || sequence.is_some_and(|previous| previous != seq)
            {
                return Err(invalid("invalid WAL fragment"));
            }
            sequence = Some(seq);
            if self.end - cursor - (FRAME_HEADER_BYTES as u64) < len as u64 {
                self.torn = true;
                return Ok(None);
            }
            let mut hash = Hasher::new();
            hash.update(&header[..12]);
            let mut remaining = len;
            while remaining > 0 {
                let take = remaining.min(buffer.len());
                self.input.read_exact(&mut buffer[..take])?;
                hash.update(&buffer[..take]);
                payload.write_all(&buffer[..take])?;
                remaining -= take;
            }
            if hash.finalize() != u32::from_le_bytes(header[12..].try_into().unwrap()) {
                return Err(invalid("WAL checksum mismatch"));
            }
            cursor += (FRAME_HEADER_BYTES + len) as u64;
            if framed_len & MORE == 0 {
                self.payload = payload.finish()?;
                self.valid_end = cursor;
                return Ok(sequence);
            }
        }
    }
}

struct Checked<T> {
    inner: T,
    hash: Hasher,
    bytes: u64,
}
impl<W: Write> Write for Checked<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.hash.update(&bytes[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<R: Read> Read for Checked<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(bytes)?;
        self.hash.update(&bytes[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Snapshot payload streams directly from/to native state; no whole-file byte copy.
pub(crate) fn write_snapshot<W: Write + Seek, T: Serialize>(
    file: &mut W,
    kind: Kind,
    seq: u64,
    value: &T,
) -> io::Result<u64> {
    file.write_all(&file_header(kind))?;
    file.write_all(&[0; 24])?;
    let mut checked = Checked {
        inner: file,
        hash: Hasher::new(),
        bytes: 0,
    };
    {
        // Hash buffer-sized writes, not every MessagePack scalar.
        let mut output = BufWriter::with_capacity(BUFFER_BYTES, &mut checked);
        rmp_serde::encode::write(&mut output, value).map_err(invalid)?;
        output.flush()?;
    }
    let len = checked.bytes;
    let mut header = [0; 24];
    header[..8].copy_from_slice(&seq.to_le_bytes());
    header[8..16].copy_from_slice(&len.to_le_bytes());
    checked.hash.update(&header[..16]);
    header[16..20].copy_from_slice(&checked.hash.finalize().to_le_bytes());
    checked.inner.seek(SeekFrom::Start(FILE_HEADER_BYTES))?;
    checked.inner.write_all(&header)?;
    checked.inner.flush()?;
    Ok(FILE_HEADER_BYTES + 24 + len)
}

pub(crate) fn read_snapshot<R: Read + Seek, T: DeserializeOwned>(
    mut file: R,
    kind: Kind,
) -> io::Result<(u64, T)> {
    let end = file.seek(SeekFrom::End(0))?;
    file.rewind()?;
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    if header != file_header(kind) {
        return Err(invalid("unsupported binary snapshot header"));
    }
    let mut header = [0; 24];
    file.read_exact(&mut header)?;
    let seq = u64::from_le_bytes(header[..8].try_into().unwrap());
    let len = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if end.checked_sub(40) != Some(len) || header[20..] != [0; 4] {
        return Err(invalid("invalid snapshot length"));
    }
    let checked = Checked {
        inner: file.take(len),
        hash: Hasher::new(),
        bytes: 0,
    };
    let mut input = BufReader::with_capacity(BUFFER_BYTES, checked);
    let value = T::deserialize(&mut rmp_serde::Deserializer::new(&mut input)).map_err(invalid)?;
    if !input.fill_buf()?.is_empty() {
        return Err(invalid("trailing snapshot payload"));
    }
    let mut checked = input.into_inner();
    if checked.bytes != len {
        return Err(invalid("trailing snapshot payload"));
    }
    checked.hash.update(&header[..16]);
    if checked.hash.finalize() != u32::from_le_bytes(header[16..20].try_into().unwrap()) {
        return Err(invalid("snapshot checksum mismatch"));
    }
    Ok((seq, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // New physical-format failures are independent of orchestration tests.
    // Removing this loses header/length/CRC and byte-level tear coverage;
    // all fixtures stay in memory and cost no fsync or process startup.
    #[test]
    fn frames_reject_corruption_and_recover_only_incomplete_tails() {
        let mut bytes = file_header(Kind::TaskWal).to_vec();
        append_frame(&mut bytes, 7, |out| {
            rmp_serde::encode::write(out, &vec!["雪", "payload"]).map_err(invalid)
        })
        .unwrap();
        let mut reader = Reader::new(Cursor::new(&bytes), Kind::TaskWal).unwrap();
        assert_eq!(reader.next().unwrap(), Some(7));
        assert_eq!(
            decode::<Vec<String>>(&reader.payload).unwrap(),
            ["雪", "payload"]
        );
        assert!(reader.next().unwrap().is_none());
        assert!(!reader.torn);
        for offset in [0, 4, 6, 8, 20, 28, bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[offset] ^= 1;
            let result =
                Reader::new(Cursor::new(damaged), Kind::TaskWal).and_then(|mut r| r.next());
            assert!(result.is_err(), "undetected corruption at {offset}");
        }
        assert!(Reader::new(Cursor::new(&bytes), Kind::CatalogWal).is_err());
        for end in 0..bytes.len() {
            let mut reader = Reader::new(Cursor::new(&bytes[..end]), Kind::TaskWal).unwrap();
            assert!(reader.next().unwrap().is_none());
            assert!(reader.torn || end == 16);
            assert_eq!(reader.valid_end, if end < 16 { 0 } else { 16 });
        }
        let mut oversized = bytes.clone();
        oversized[16..20].copy_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
        assert!(Reader::new(Cursor::new(oversized), Kind::TaskWal)
            .unwrap()
            .next()
            .is_err());
    }

    // No existing test checks checksum coverage of snapshot sequence metadata,
    // trailing bytes and wrong file type together. Removing it loses that
    // independent binary envelope coverage at negligible in-memory cost.
    #[test]
    fn snapshots_stream_and_validate_the_entire_envelope() {
        type Payload = (Vec<String>, serde_json::Value);
        let value: Payload = (
            vec!["雪".repeat(BUFFER_BYTES)],
            serde_json::json!({"values": [true, null, 3.25]}),
        );
        let mut file = Cursor::new(Vec::new());
        let len = write_snapshot(&mut file, Kind::TaskSnapshot, 19, &value).unwrap();
        assert_eq!(len, file.get_ref().len() as u64);
        let (seq, restored): (_, Payload) =
            read_snapshot(file.clone(), Kind::TaskSnapshot).unwrap();
        assert_eq!(seq, 19);
        assert_eq!(restored, value);
        assert!(read_snapshot::<_, Payload>(file.clone(), Kind::CatalogSnapshot).is_err());
        for offset in [0, 4, 6, 8, 16, 24, 32, 36, 40, len as usize - 1] {
            let mut damaged = file.clone();
            damaged.get_mut()[offset] ^= 1;
            assert!(read_snapshot::<_, Payload>(damaged, Kind::TaskSnapshot).is_err());
        }
        for end in [0, 15, 39, len as usize - 1] {
            let mut damaged = file.clone();
            damaged.get_mut().truncate(end);
            assert!(read_snapshot::<_, Payload>(damaged, Kind::TaskSnapshot).is_err());
        }
        file.get_mut().push(0);
        assert!(read_snapshot::<_, Payload>(file, Kind::TaskSnapshot).is_err());
    }
}
