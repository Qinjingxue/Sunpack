use super::context::{InputKey, InputMember};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct RangeSpec {
    reader: ManagedReader,
    start: u64,
    end: Option<u64>,
    len: u64,
    virtual_start: u64,
}

pub(crate) fn parse_ranges(ranges: &Bound<'_, PyList>) -> PyResult<Vec<RangeSpec>> {
    let mut parsed = Vec::new();
    let mut cursor = 0u64;
    for item in ranges.iter() {
        let dict = item.cast::<PyDict>()?;
        let path = dict
            .get_item("path")?
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("range path is required")
            })?
            .extract::<String>()?;
        let start = dict
            .get_item("start")?
            .map(|value| value.extract::<u64>())
            .transpose()?
            .unwrap_or(0);
        let end = dict
            .get_item("end")?
            .map(|value| value.extract::<u64>())
            .transpose()?;
        let reader = ManagedReader::open(&path)?;
        let file_len = reader.len();
        if start > file_len {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "range start is beyond file length",
            ));
        }
        let effective_end = end.unwrap_or(file_len).min(file_len);
        if effective_end < start {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "range end is before start",
            ));
        }
        let len = effective_end - start;
        parsed.push(RangeSpec {
            reader,
            start,
            end,
            len,
            virtual_start: cursor,
        });
        cursor = cursor.saturating_add(len);
    }
    Ok(parsed)
}

pub(crate) fn ranges_total_len(ranges: &[RangeSpec]) -> u64 {
    ranges
        .last()
        .map(|item| item.virtual_start + item.len)
        .unwrap_or(0)
}

pub(crate) fn ranges_key(format: &'static str, ranges: &[RangeSpec]) -> std::io::Result<InputKey> {
    Ok(InputKey::new(
        format,
        "ranges",
        ranges
            .iter()
            .map(|range| InputMember::new(&range.reader, range.start, range.end, 0))
            .collect::<std::io::Result<_>>()?,
    ))
}

pub(crate) fn read_prefix_from_ranges_field(
    ranges: &[RangeSpec],
    max_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, ReadFault> {
    let total_len = ranges_total_len(ranges);
    let mut reader = VirtualRangeReader::new(Arc::from(ranges));
    let requested = max_len.min(total_len as usize);
    let mut data = vec![0u8; requested];
    let len = reader.read(&mut data).map_err(|error| {
        ReadFault::from_io(error, "read_ranges", 0, requested, 0, total_len)
            .with_field(field, FieldLocation::Head)
    })?;
    data.truncate(len);
    Ok(data)
}

pub(crate) struct VirtualRangeReader {
    ranges: Arc<[RangeSpec]>,
    position: u64,
    total_len: u64,
}

impl VirtualRangeReader {
    pub(crate) fn new(ranges: Arc<[RangeSpec]>) -> Self {
        let total_len = ranges_total_len(&ranges);
        Self {
            ranges,
            position: 0,
            total_len,
        }
    }

    fn current_range(&self) -> Option<&RangeSpec> {
        let index = self
            .ranges
            .partition_point(|range| range.virtual_start + range.len <= self.position);
        self.ranges.get(index).filter(|range| {
            self.position >= range.virtual_start && self.position < range.virtual_start + range.len
        })
    }
}

impl Read for VirtualRangeReader {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        let mut total_read = 0usize;
        while !buf.is_empty() && self.position < self.total_len {
            let Some(range) = self.current_range() else {
                break;
            };
            let local_offset = self.position - range.virtual_start;
            let available = (range.len - local_offset) as usize;
            let to_read = available.min(buf.len());
            let physical_offset = range.start + local_offset;
            let reader = range.reader.clone();
            let read_now = reader.read_into_at(physical_offset, &mut buf[..to_read])?;
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

impl Seek for VirtualRangeReader {
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

#[derive(Clone)]
pub(crate) struct VolumeSpec {
    pub(crate) reader: ManagedReader,
    pub(crate) number: u32,
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
}

pub(crate) fn parse_volumes(parts: &Bound<'_, PyList>) -> PyResult<Vec<VolumeSpec>> {
    let mut parsed = Vec::new();
    for item in parts.iter() {
        let dict = item.cast::<PyDict>()?;
        let path = dict
            .get_item("path")?
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("volume path is required")
            })?
            .extract::<String>()?;
        let number = dict
            .get_item("volume_number")?
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("volume_number is required")
            })?
            .extract::<u32>()?;
        let start = dict
            .get_item("start")?
            .map(|value| value.extract::<u64>())
            .transpose()?
            .unwrap_or(0);
        let reader = ManagedReader::open(&path)?;
        let end = dict
            .get_item("end")?
            .map(|value| value.extract::<u64>())
            .transpose()?;
        if start > end.unwrap_or(reader.len()).min(reader.len()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "volume range is outside file length",
            ));
        }
        let canonical_name = dict
            .get_item("canonical_name")?
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("canonical_name is required")
            })?
            .extract::<String>()?;
        if number == 0 || canonical_name.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
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
    parsed.sort_by_key(|volume| volume.number);
    if parsed.is_empty()
        || parsed
            .iter()
            .enumerate()
            .any(|(index, volume)| volume.number != index as u32 + 1)
    {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "structured volume numbers must be contiguous from one",
        ));
    }
    Ok(parsed)
}

pub(crate) struct VolumeSet {
    volumes: Arc<[VolumeSpec]>,
}

impl VolumeSet {
    pub(crate) fn new(volumes: Vec<VolumeSpec>) -> Self {
        Self {
            volumes: volumes.into(),
        }
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

    pub(crate) fn first_prefix_field(
        &self,
        size: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, ReadFault> {
        let Some(volume_len) = self.volume_len(0) else {
            return Err(ReadFault::short_read("read_volume", 0, size, 0, 0)
                .with_field(field, FieldLocation::Head)
                .with_volume(1));
        };
        let requested = size.min(volume_len as usize);
        self.read_disk_spanning(0, 0, requested).map_err(|error| {
            ReadFault::from_io(error, "read_volume", 0, requested, 0, volume_len)
                .with_field(field, FieldLocation::Head)
                .with_volume(1)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    #[test]
    fn virtual_ranges_read_and_seek_across_files() {
        let first = temp_file("password_range_first", b"012345");
        let second = temp_file("password_range_second", b"abcdef");
        let ranges: Arc<[RangeSpec]> = vec![
            RangeSpec {
                reader: ManagedReader::open(&first).unwrap(),
                start: 2,
                end: Some(5),
                len: 3,
                virtual_start: 0,
            },
            RangeSpec {
                reader: ManagedReader::open(&second).unwrap(),
                start: 1,
                end: Some(5),
                len: 4,
                virtual_start: 3,
            },
        ]
        .into();
        let mut reader = VirtualRangeReader::new(ranges);
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
}
