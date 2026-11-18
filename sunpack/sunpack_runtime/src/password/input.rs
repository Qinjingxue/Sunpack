use super::context::{InputKey, InputMember};
use crate::io::archive_state::{InputExtent, InputPart};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, NativeArchiveSession};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone)]
pub(crate) struct RangeSpec {
    reader: ManagedReader,
    start: u64,
    len: u64,
    virtual_start: u64,
}

impl RangeSpec {
    pub(super) fn entire(reader: &ManagedReader) -> Self {
        Self { reader: reader.clone(), start: 0, len: reader.len(), virtual_start: 0 }
    }

    pub(super) fn covering(ranges: &[Self], offset: u64, size: u64) -> &[Self] {
        let start = ranges.partition_point(|r| r.virtual_start + r.len <= offset);
        let end = ranges.partition_point(|r| r.virtual_start < offset.saturating_add(size));
        &ranges[start..end.max(start)]
    }
}

// The caller already holds lifecycle borrows. Reuse their validated readers
// instead of reopening every physical member for every password batch.
struct InputReaders<'a>(HashMap<&'a str, ManagedReader>);

impl<'a> InputReaders<'a> {
    fn new(sessions: &'a [NativeArchiveSession]) -> Self {
        Self(
            sessions
                .iter()
                .map(NativeArchiveSession::borrowed_reader)
                .collect(),
        )
    }

    fn open(&mut self, path: &'a str, reuse: bool) -> std::io::Result<ManagedReader> {
        // A case-sensitive Windows directory can contain both spellings.
        // Sessions are opened from the same physical extent paths.
        if let Some(reader) = self.0.get(path) {
            return Ok(reader.clone());
        }
        let reader = ManagedReader::open(path)?;
        if reuse {
            self.0.insert(path, reader.clone());
        }
        Ok(reader)
    }
}

pub(crate) fn parse_ranges<'a>(
    ranges: impl Iterator<Item = &'a InputExtent>,
    sessions: &'a [NativeArchiveSession],
) -> std::io::Result<Vec<RangeSpec>> {
    parse_range_prefix(ranges, sessions, None)
}

/// Stop opening members once the requested logical prefix is complete.
pub(crate) fn parse_range_prefix<'a>(
    ranges: impl Iterator<Item = &'a InputExtent>,
    sessions: &'a [NativeArchiveSession],
    limit: Option<u64>,
) -> std::io::Result<Vec<RangeSpec>> {
    let mut parsed = if limit.is_some() { Vec::new() } else { Vec::with_capacity(ranges.size_hint().0) };
    extend_range_prefix(ranges, sessions, limit, &mut parsed)?;
    Ok(parsed)
}

/// Structural evidence at the head can use the part before the first
/// unavailable range without repeatedly parsing shorter descriptions.
pub(super) fn available_range_prefix<'a>(
    ranges: impl Iterator<Item = &'a InputExtent>,
    sessions: &'a [NativeArchiveSession],
) -> Vec<RangeSpec> {
    let mut parsed = Vec::new();
    let _ = extend_range_prefix(ranges, sessions, None, &mut parsed);
    parsed
}

#[cfg(test)]
thread_local! {
    static RANGE_PROJECTIONS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn extend_range_prefix<'a>(
    ranges: impl Iterator<Item = &'a InputExtent>,
    sessions: &'a [NativeArchiveSession],
    limit: Option<u64>,
    parsed: &mut Vec<RangeSpec>,
) -> std::io::Result<()> {
    let mut readers = InputReaders::new(sessions);
    let reuse = ranges.size_hint().1.is_none_or(|count| count > 1);
    let mut cursor = 0u64;
    for range in ranges {
        #[cfg(test)]
        RANGE_PROJECTIONS.with(|value| value.set(value.get().map(|n| n + 1)));
        let (path, start, end) = (&range.path, range.start, range.end);
        let reader = readers.open(path, reuse)?;
        let file_len = reader.len();
        if start > file_len {
            return Err(std::io::Error::other("range start is beyond file length"));
        }
        let effective_end = end.unwrap_or(file_len).min(file_len);
        if effective_end < start {
            return Err(std::io::Error::other("range end is before start"));
        }
        let mut len = effective_end - start;
        if let Some(limit) = limit {
            let remaining = limit - cursor;
            if len < remaining && end.is_some_and(|end| end > file_len) {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            len = len.min(remaining);
        }
        let next = cursor.checked_add(len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "logical input size overflow",
            )
        })?;
        parsed.push(RangeSpec {
            reader,
            start,
            len,
            virtual_start: cursor,
        });
        cursor = next;
        if Some(cursor) == limit {
            break;
        }
    }
    Ok(())
}

pub(crate) fn ranges_key(format: &'static str, ranges: &[RangeSpec]) -> std::io::Result<InputKey> {
    Ok(InputKey::new(
        format,
        "ranges",
        ranges
            .iter()
            .map(|range| {
                InputMember::new(&range.reader, range.start, Some(range.start + range.len), 0)
            })
            .collect::<std::io::Result<_>>()?,
    ))
}

/// Read up to `max_len` bytes at a logical offset; the result is shorter only
/// at the end of the logical input.
pub(crate) fn read_ranges_at_field(
    ranges: &[RangeSpec],
    offset: u64,
    max_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, ReadFault> {
    let mut reader = VirtualRangeReader::new(ranges);
    let total_len = reader.len();
    reader.read_at(offset, max_len).map_err(|error| {
        let requested = (max_len as u64).min(total_len.saturating_sub(offset)) as usize;
        ReadFault::from_io(error, "read_ranges", offset, requested, 0, total_len)
            .with_field(field, FieldLocation::Head)
    })
}

pub(crate) struct VirtualRangeReader<'a> {
    ranges: &'a [RangeSpec],
    position: u64,
    total_len: u64,
    streaming: bool,
}

impl<'a> VirtualRangeReader<'a> {
    pub(crate) fn new(ranges: &'a [RangeSpec]) -> Self {
        let total_len = ranges
            .last()
            .map_or(0, |item| item.virtual_start + item.len);
        Self {
            ranges,
            position: 0,
            total_len,
            streaming: false,
        }
    }

    // Material copied into a prepared descriptor already owns its lifetime.
    // Do not also retain a potentially large CRC span in the reader caches.
    pub(crate) fn streaming(ranges: &'a [RangeSpec]) -> Self {
        Self { streaming: true, ..Self::new(ranges) }
    }

    pub(crate) fn len(&self) -> u64 {
        self.total_len
    }

    pub(crate) fn read_at(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.read_at_into(offset, len, &mut data)?;
        Ok(data)
    }

    pub(crate) fn read_at_into(
        &mut self,
        offset: u64,
        len: usize,
        output: &mut Vec<u8>,
    ) -> std::io::Result<()> {
        self.position = offset;
        let requested = (len as u64).min(self.total_len.saturating_sub(offset)) as usize;
        output.resize(requested, 0);
        let read = self.read(output)?;
        output.truncate(read);
        Ok(())
    }

    pub(crate) fn disk_starts(&self) -> Vec<u64> {
        self.ranges
            .iter()
            .filter(|range| range.len != 0)
            .map(|range| range.virtual_start)
            .collect()
    }
}

impl Read for VirtualRangeReader<'_> {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        let mut index = self
            .ranges
            .partition_point(|range| range.virtual_start + range.len <= self.position);
        let mut total_read = 0;
        while let Some(range) = self.ranges.get(index) {
            if buf.is_empty() {
                break;
            }
            let local_offset = self.position - range.virtual_start;
            if local_offset == range.len {
                index += 1;
                continue;
            }
            let to_read = (range.len - local_offset).min(buf.len() as u64) as usize;
            let physical_offset = range.start + local_offset;
            let read_now = if self.streaming {
                range.reader.read_direct_into_at(physical_offset, &mut buf[..to_read])?
            } else {
                range.reader.read_into_at(physical_offset, &mut buf[..to_read])?
            };
            if read_now == 0 {
                break;
            }
            self.position += read_now as u64;
            total_read += read_now;
            let (_, rest) = buf.split_at_mut(read_now);
            buf = rest;
        }
        Ok(total_read)
    }
}

impl Seek for VirtualRangeReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::End(value) => self.total_len as i128 + value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "negative seek",
            ));
        }
        self.position = (next as u64).min(self.total_len);
        Ok(self.position)
    }
}

pub(crate) struct VolumeSpec {
    pub(crate) reader: ManagedReader,
    pub(crate) number: u32,
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
}

pub(crate) fn parse_volumes<'a>(
    parts: &'a [InputPart],
    sessions: &'a [NativeArchiveSession],
) -> std::io::Result<Vec<VolumeSpec>> {
    let mut readers = InputReaders::new(sessions);
    let mut parsed = Vec::with_capacity(parts.len());
    for item in parts {
        let number = item
            .volume_number
            .ok_or_else(|| std::io::Error::other("volume_number is required"))?;
        let InputExtent { path, start, end } = &item.extent;
        let (start, end) = (*start, *end);
        let reader = readers.open(path, parts.len() > 1)?;
        if start > end.unwrap_or(reader.len()).min(reader.len()) {
            return Err(std::io::Error::other("volume range is outside file length"));
        }
        let canonical_name = &item.canonical_name;
        if number == 0 || canonical_name.is_empty() {
            return Err(std::io::Error::other(
                "structured volumes require positive numbers and canonical names",
            ));
        }
        parsed.push(VolumeSpec {
            reader,
            number,
            start,
            end,
        });
    }
    parsed.sort_unstable_by_key(|volume| volume.number);
    if parsed
        .windows(2)
        .any(|pair| pair[0].number == pair[1].number)
    {
        return Err(std::io::Error::other(
            "structured volume numbers must be unique",
        ));
    }
    Ok(parsed)
}

pub(crate) struct VolumeSet {
    volumes: Vec<VolumeSpec>,
}

impl VolumeSet {
    /// Bytes whose disk positions are known without crossing a missing disk.
    pub(crate) fn contiguous_prefix_len(&self) -> u64 {
        self.volumes.iter().enumerate()
            .take_while(|(index, volume)| volume.number == *index as u32 + 1)
            .try_fold(0u64, |total, (index, _)| total.checked_add(self.volume_len(index)?))
            .unwrap_or(0)
    }
    pub(super) fn last_number(&self) -> usize {
        self.volumes.last().map_or(0, |v| v.number as usize)
    }
    pub(super) fn ordinal(&self, disk: usize) -> Option<usize> {
        self.volumes.binary_search_by_key(&disk.checked_add(1)?, |v| v.number as usize).ok()
    }

    pub(crate) fn new(volumes: Vec<VolumeSpec>) -> Self {
        Self { volumes }
    }

    pub(crate) fn len(&self) -> usize {
        self.volumes.len()
    }

    pub(crate) fn key(&self, format: &'static str) -> std::io::Result<InputKey> {
        Ok(InputKey::new(
            format,
            "volumes",
            self.volumes
                .iter()
                .map(|volume| {
                    InputMember::new(&volume.reader, volume.start, volume.end, volume.number)
                })
                .collect::<std::io::Result<_>>()?,
        ))
    }

    pub(crate) fn volume_len(&self, disk: usize) -> Option<u64> {
        self.volumes.get(disk).map(|volume| {
            volume
                .end
                .unwrap_or(volume.reader.len())
                .min(volume.reader.len())
                - volume.start
        })
    }

    pub(crate) fn read_disk_spanning(
        &self, mut disk: usize, mut offset: u64, size: usize,
    ) -> std::io::Result<Vec<u8>> {
        let first_number = self.volumes.get(disk).map(|v| v.number as usize);
        let first_ordinal = disk;
        let mut output = vec![0u8; size];
        let mut written = 0usize;
        while written < size {
            let Some(volume) = self.volumes.get(disk) else {
                break;
            };
            if first_number.and_then(|n| n.checked_add(disk - first_ordinal)) != Some(volume.number as usize) { break; }
            let volume_len = self.volume_len(disk).unwrap();
            if offset >= volume_len {
                if offset == volume_len {
                    disk += 1;
                    offset = 0;
                    continue;
                }
                break;
            }
            let available = (volume_len - offset) as usize;
            let requested = available.min(size - written);
            let buffer = &mut output[written..written + requested];
            let read = volume.reader.read_into_at(volume.start + offset, buffer)?;
            if read == 0 {
                break;
            }
            written += read;
            offset += read as u64;
            if offset == volume_len {
                disk += 1;
                offset = 0;
            }
        }
        output.truncate(written);
        Ok(output)
    }

    pub(crate) fn read_disk_spanning_field(
        &self,
        disk: usize,
        offset: u64,
        size: usize,
        field: &'static str,
        location: FieldLocation,
    ) -> Result<Vec<u8>, ReadFault> {
        let data = self
            .read_disk_spanning(disk, offset, size)
            .map_err(|error| {
                ReadFault::from_io(
                    error,
                    "read_volume",
                    offset,
                    size,
                    0,
                    self.volume_len(disk).unwrap_or(0),
                )
                .with_field(field, location)
                .with_volume(disk as u32 + 1)
            })?;
        if data.len() != size {
            return Err(ReadFault::short_read(
                "read_volume",
                offset,
                size,
                data.len(),
                self.volume_len(disk).unwrap_or(0),
            )
            .with_field(field, location)
            .with_volume(disk as u32 + 1)
            .with_possible_missing_volume());
        }
        Ok(data)
    }

    pub(super) fn contiguous_ranges(&self) -> Vec<RangeSpec> {
        let mut position = 0u64;
        self.volumes.iter().enumerate()
            .take_while(|(index, volume)| volume.number as usize == *index + 1)
            .map_while(|(disk, _)| {
                let mut range = self.disk_range(disk)?;
                range.virtual_start = position;
                position = position.checked_add(range.len)?;
                Some(range)
            }).collect()
    }

    pub(super) fn disk_range(&self, disk: usize) -> Option<RangeSpec> {
        let volume = self.volumes.get(disk)?;
        Some(RangeSpec { reader: volume.reader.clone(), start: volume.start,
            len: self.volume_len(disk)?, virtual_start: 0 })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/password/input/tests.rs"]
mod tests;

#[path = "input_attempts.rs"]
pub(crate) mod attempts;

#[path = "input_prefix.rs"]
pub(crate) mod prefix;
