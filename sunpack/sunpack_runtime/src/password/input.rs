use super::context::{InputKey, InputMember, PreparedStatus};
use crate::io::archive_state::{InputExtent, InputPart};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, NativeArchiveSession};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

pub(crate) struct RangeSpec {
    reader: ManagedReader,
    start: u64,
    len: u64,
    virtual_start: u64,
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
    let mut readers = InputReaders::new(sessions);
    let (minimum, maximum) = ranges.size_hint();
    let mut parsed = Vec::with_capacity(minimum);
    let mut cursor = 0u64;
    for range in ranges {
        let (path, start, end) = (&range.path, range.start, range.end);
        let reader = readers.open(path, maximum.is_none_or(|count| count > 1))?;
        let file_len = reader.len();
        if start > file_len {
            return Err(std::io::Error::other("range start is beyond file length"));
        }
        let effective_end = end.unwrap_or(file_len).min(file_len);
        if effective_end < start {
            return Err(std::io::Error::other("range end is before start"));
        }
        let len = effective_end - start;
        parsed.push(RangeSpec {
            reader,
            start,
            len,
            virtual_start: cursor,
        });
        cursor = cursor.checked_add(len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "logical input size overflow",
            )
        })?;
    }
    Ok(parsed)
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
        }
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
            let read_now = range
                .reader
                .read_into_at(physical_offset, &mut buf[..to_read])?;
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
    pub(crate) fn require_contiguous(&self) -> Result<(), PreparedStatus> {
        if self.volumes.is_empty()
            || self
                .volumes
                .iter()
                .enumerate()
                .any(|(index, volume)| volume.number != index as u32 + 1)
        {
            return Err(PreparedStatus::new(
                "missing_volume",
                "structured volume numbers are not contiguous from one; missing volume",
            ));
        }
        Ok(())
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
        &self,
        mut disk: usize,
        mut offset: u64,
        size: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut output = vec![0u8; size];
        let mut written = 0usize;
        while written < size {
            let Some(volume) = self.volumes.get(disk) else {
                break;
            };
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
            let read = volume.reader.read_into_at(
                volume.start + offset,
                &mut output[written..written + requested],
            )?;
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

    pub(crate) fn advance_disk_offset(
        &self,
        mut disk: usize,
        mut offset: u64,
        mut amount: u64,
    ) -> Option<(usize, u64)> {
        loop {
            let volume_len = self.volume_len(disk)?;
            if offset > volume_len {
                return None;
            }
            let remaining = volume_len - offset;
            if amount <= remaining {
                return Some((disk, offset + amount));
            }
            amount -= remaining;
            disk += 1;
            offset = 0;
        }
    }

    pub(crate) fn read_last_tail_field(
        &self,
        size: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, ReadFault> {
        let disk = self.volumes.len().saturating_sub(1);
        let Some(volume_len) = self.volume_len(disk) else {
            return Err(ReadFault::short_read("read_volume_tail", 0, size, 0, 0)
                .with_field(field, FieldLocation::Tail)
                .with_volume(disk as u32 + 1));
        };
        let read_size = size.min(volume_len as usize);
        self.read_disk_spanning_field(
            disk,
            volume_len - read_size as u64,
            read_size,
            field,
            FieldLocation::Tail,
        )
    }

    /// Read up to `size` bytes at `offset` inside the first volume only; the
    /// result is shorter only at the end of that volume.
    pub(crate) fn first_volume_read_at_field(
        &self,
        offset: u64,
        size: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, ReadFault> {
        let Some(volume_len) = self.volume_len(0) else {
            return Err(ReadFault::short_read("read_volume", offset, size, 0, 0)
                .with_field(field, FieldLocation::Head)
                .with_volume(1));
        };
        let requested = size.min(volume_len.saturating_sub(offset) as usize);
        if requested == 0 {
            return Ok(Vec::new());
        }
        self.read_disk_spanning(0, offset, requested)
            .map_err(|error| {
                ReadFault::from_io(error, "read_volume", offset, requested, 0, volume_len)
                    .with_field(field, FieldLocation::Head)
                    .with_volume(1)
            })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/password/input/tests.rs"]
mod tests;
