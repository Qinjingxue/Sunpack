use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FieldLocation {
    Head,
    Body,
    Tail,
}

impl FieldLocation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Body => "body",
            Self::Tail => "tail",
        }
    }

    pub(crate) fn possible_missing_volume(self) -> bool {
        self == Self::Tail
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReadFault {
    pub(crate) code: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) field: &'static str,
    pub(crate) location: FieldLocation,
    pub(crate) offset: u64,
    pub(crate) requested: usize,
    pub(crate) actual: usize,
    pub(crate) source_len: u64,
    pub(crate) volume_number: Option<u32>,
    pub(crate) missing_volume_hint: bool,
    pub(crate) io_kind: io::ErrorKind,
    pub(crate) os_error: Option<i32>,
    pub(crate) detail: String,
}

impl ReadFault {
    pub(crate) fn physical(
        operation: &'static str,
        offset: u64,
        requested: usize,
        actual: usize,
        source_len: u64,
        error: &io::Error,
    ) -> Self {
        Self {
            code: if error.kind() == io::ErrorKind::UnexpectedEof {
                "unexpected_eof"
            } else {
                "io_error"
            },
            operation,
            field: "",
            location: FieldLocation::Body,
            offset,
            requested,
            actual,
            source_len,
            volume_number: None,
            missing_volume_hint: false,
            io_kind: error.kind(),
            os_error: error.raw_os_error(),
            detail: error.to_string(),
        }
    }

    pub(crate) fn short_read(
        operation: &'static str,
        offset: u64,
        requested: usize,
        actual: usize,
        source_len: u64,
    ) -> Self {
        Self {
            code: "unexpected_eof",
            operation,
            field: "",
            location: FieldLocation::Body,
            offset,
            requested,
            actual,
            source_len,
            volume_number: None,
            missing_volume_hint: false,
            io_kind: io::ErrorKind::UnexpectedEof,
            os_error: None,
            detail: "requested bytes extend beyond available input".to_string(),
        }
    }

    pub(crate) fn invalid_field(
        operation: &'static str,
        offset: u64,
        field_size: usize,
        source_len: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code: "invalid_field",
            operation,
            field: "",
            location: FieldLocation::Body,
            offset,
            requested: field_size,
            actual: field_size,
            source_len,
            volume_number: None,
            missing_volume_hint: false,
            io_kind: io::ErrorKind::InvalidData,
            os_error: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn with_field(mut self, field: &'static str, location: FieldLocation) -> Self {
        self.field = field;
        self.location = location;
        self
    }

    pub(crate) fn with_volume(mut self, volume_number: u32) -> Self {
        self.volume_number = Some(volume_number);
        self
    }

    pub(crate) fn with_possible_missing_volume(mut self) -> Self {
        self.missing_volume_hint = true;
        self
    }

    pub(crate) fn possible_missing_volume(&self) -> bool {
        self.missing_volume_hint || self.location.possible_missing_volume()
    }

    pub(crate) fn from_io(
        error: io::Error,
        operation: &'static str,
        offset: u64,
        requested: usize,
        actual: usize,
        source_len: u64,
    ) -> Self {
        if let Some(existing) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ReadFault>())
        {
            return existing.clone();
        }
        Self::physical(operation, offset, requested, actual, source_len, &error)
    }

    pub(crate) fn into_io_error(self) -> io::Error {
        io::Error::new(self.io_kind, self)
    }

    pub(crate) fn write_python(&self, output: &Bound<'_, PyDict>) -> PyResult<()> {
        let py = output.py();
        let diagnostic = PyDict::new(py);
        diagnostic.set_item("code", self.code)?;
        diagnostic.set_item("operation", self.operation)?;
        diagnostic.set_item("field", self.field)?;
        diagnostic.set_item("location", self.location.as_str())?;
        diagnostic.set_item("offset", self.offset)?;
        diagnostic.set_item("requested", self.requested)?;
        diagnostic.set_item("actual", self.actual)?;
        diagnostic.set_item("source_len", self.source_len)?;
        diagnostic.set_item("volume_number", self.volume_number)?;
        diagnostic.set_item("io_kind", format!("{:?}", self.io_kind).to_lowercase())?;
        diagnostic.set_item("os_error", self.os_error)?;
        diagnostic.set_item("detail", &self.detail)?;
        diagnostic.set_item("possible_missing_volume", self.possible_missing_volume())?;
        output.set_item("read_error", diagnostic)?;
        output.set_item("error_field", self.field)?;
        output.set_item("possible_missing_volume", self.possible_missing_volume())?;
        Ok(())
    }

    pub(crate) fn write_python_with_damage_flags(
        &self,
        output: &Bound<'_, PyDict>,
    ) -> PyResult<()> {
        self.write_python(output)?;
        let mut flags = Vec::with_capacity(3);
        flags.push("read_error");
        if self.code == "unexpected_eof" {
            flags.push("input_truncated");
        }
        if self.possible_missing_volume() {
            flags.push("missing_volume");
        }
        output.set_item("damage_flags", PyList::new(output.py(), flags)?)
    }
}

impl fmt::Display for ReadFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} field={} location={} offset={} requested={} actual={} source_len={}: {}",
            self.code,
            self.field,
            self.location.as_str(),
            self.offset,
            self.requested,
            self.actual,
            self.source_len,
            self.detail
        )
    }
}

impl Error for ReadFault {}

pub(crate) fn read_exact_field<R: Read + Seek>(
    reader: &mut R,
    buffer: &mut [u8],
    source_len: u64,
    field: &'static str,
    location: FieldLocation,
) -> Result<(), ReadFault> {
    let offset = reader.stream_position().map_err(|error| {
        ReadFault::from_io(error, "tell", 0, 0, 0, source_len).with_field(field, location)
    })?;
    let mut actual = 0usize;
    while actual < buffer.len() {
        match reader.read(&mut buffer[actual..]) {
            Ok(0) => {
                return Err(ReadFault::short_read(
                    "read_exact",
                    offset,
                    buffer.len(),
                    actual,
                    source_len,
                )
                .with_field(field, location));
            }
            Ok(count) => actual += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ReadFault::from_io(
                    error,
                    "read_exact",
                    offset,
                    buffer.len(),
                    actual,
                    source_len,
                )
                .with_field(field, location));
            }
        }
    }
    Ok(())
}

pub(crate) fn seek_field<R: Seek>(
    reader: &mut R,
    offset: u64,
    source_len: u64,
    field: &'static str,
    location: FieldLocation,
) -> Result<u64, ReadFault> {
    reader.seek(SeekFrom::Start(offset)).map_err(|error| {
        ReadFault::from_io(error, "seek", offset, 0, 0, source_len).with_field(field, location)
    })
}
