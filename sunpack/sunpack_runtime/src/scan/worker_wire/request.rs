use super::{finish_frame, protocol_error, HEADER, REQUEST_CHUNK_BYTES};
use crate::io::cancellation::Cancellation;
use serde::ser::{self, Impossible, Serialize};
use std::fmt;
use std::io::{self, Write};

#[derive(Debug)]
struct EncodeError(io::Error);

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for EncodeError {}
impl ser::Error for EncodeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(protocol_error(message.to_string()))
    }
}
impl From<io::Error> for EncodeError {
    fn from(error: io::Error) -> Self {
        Self(error)
    }
}

pub(super) fn encode(output: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    value.serialize(&mut Encoder { output, depth: 0 }).map_err(|error| error.0)
}

struct Encoder<W> {
    output: W,
    depth: usize,
}

impl<W: Write> Encoder<W> {
    fn tag(&mut self, tag: u8) -> Result<(), EncodeError> {
        Ok(self.output.write_all(&[tag])?)
    }

    fn scalar<const N: usize>(&mut self, tag: u8, bytes: [u8; N]) -> Result<(), EncodeError> {
        let mut encoded = [0; 9];
        encoded[0] = tag;
        encoded[1..1 + N].copy_from_slice(&bytes);
        Ok(self.output.write_all(&encoded[..1 + N])?)
    }

    fn sized(&mut self, tag: u8, bytes: &[u8]) -> Result<(), EncodeError> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| protocol_error("worker string exceeds u32 length"))?;
        self.scalar(tag, len.to_le_bytes())?;
        Ok(self.output.write_all(bytes)?)
    }

    fn begin(&mut self, tag: u8) -> Result<&mut Self, EncodeError> {
        if self.depth == 64 {
            return Err(protocol_error("worker value nesting exceeds schema").into());
        }
        self.tag(tag)?;
        self.depth += 1;
        Ok(self)
    }

    fn end(&mut self) -> Result<(), EncodeError> {
        self.depth -= 1;
        self.tag(0)
    }
}

macro_rules! widen {
    ($($name:ident($input:ty) => $method:ident($output:ty)),* $(,)?) => {
        $(fn $name(self, value: $input) -> Result<(), EncodeError> {
            self.$method(<$output>::from(value))
        })*
    };
}

impl<'a, W: Write> ser::Serializer for &'a mut Encoder<W> {
    type Ok = ();
    type Error = EncodeError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeTupleVariant = Impossible<(), EncodeError>;
    type SerializeStructVariant = Impossible<(), EncodeError>;

    widen!(
        serialize_i8(i8) => serialize_i64(i64),
        serialize_i16(i16) => serialize_i64(i64),
        serialize_i32(i32) => serialize_i64(i64),
        serialize_u8(u8) => serialize_u64(u64),
        serialize_u16(u16) => serialize_u64(u64),
        serialize_u32(u32) => serialize_u64(u64),
        serialize_f32(f32) => serialize_f64(f64),
    );

    fn serialize_i64(self, value: i64) -> Result<(), EncodeError> {
        if value >= 0 { self.serialize_u64(value as u64) }
        else { self.scalar(5, value.to_le_bytes()) }
    }
    fn serialize_u64(self, value: u64) -> Result<(), EncodeError> {
        if let Ok(value) = u8::try_from(value) {
            self.scalar(11, [value])
        } else if let Ok(value) = u32::try_from(value) {
            self.scalar(12, value.to_le_bytes())
        } else {
            self.scalar(4, value.to_le_bytes())
        }
    }
    fn serialize_f64(self, value: f64) -> Result<(), EncodeError> {
        self.scalar(6, value.to_le_bytes())
    }
    fn serialize_bool(self, value: bool) -> Result<(), EncodeError> {
        self.tag(if value { 3 } else { 2 })
    }
    fn serialize_str(self, value: &str) -> Result<(), EncodeError> {
        self.sized(7, value.as_bytes())
    }
    fn serialize_char(self, value: char) -> Result<(), EncodeError> {
        self.serialize_str(value.encode_utf8(&mut [0; 4]))
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), EncodeError> {
        self.sized(8, value)
    }
    fn serialize_unit(self) -> Result<(), EncodeError> { self.tag(1) }
    fn serialize_none(self) -> Result<(), EncodeError> { self.serialize_unit() }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), EncodeError> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, name: &'static str) -> Result<(), EncodeError> {
        self.serialize_str(name)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), EncodeError> {
        value.serialize(self)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, value: &T) -> Result<(), EncodeError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self, _: &'static str, _: u32, _: &'static str, _: &T,
    ) -> Result<(), EncodeError> {
        Err(protocol_error("unsupported worker variant").into())
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self, EncodeError> { self.begin(9) }
    fn serialize_tuple(self, _: usize) -> Result<Self, EncodeError> { self.begin(9) }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, EncodeError> {
        self.begin(9)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self, EncodeError> { self.begin(10) }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, EncodeError> {
        self.begin(10)
    }
    fn serialize_tuple_variant(self, _: &'static str, _: u32, _: &'static str, _: usize)
        -> Result<Self::SerializeTupleVariant, EncodeError> {
        Err(protocol_error("unsupported worker variant").into())
    }
    fn serialize_struct_variant(self, _: &'static str, _: u32, _: &'static str, _: usize)
        -> Result<Self::SerializeStructVariant, EncodeError> {
        Err(protocol_error("unsupported worker variant").into())
    }
}

macro_rules! sequence {
    ($($trait:ident::$method:ident),*) => {
        $(impl<W: Write> ser::$trait for &mut Encoder<W> {
            type Ok = ();
            type Error = EncodeError;
            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
                value.serialize(&mut **self)
            }
            fn end(self) -> Result<(), EncodeError> { Encoder::end(self) }
        })*
    };
}
sequence!(SerializeSeq::serialize_element, SerializeTuple::serialize_element, SerializeTupleStruct::serialize_field);

impl<W: Write> ser::SerializeMap for &mut Encoder<W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), EncodeError> {
        key.serialize(&mut **self)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), EncodeError> { Encoder::end(self) }
}

impl<W: Write> ser::SerializeStruct for &mut Encoder<W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), EncodeError> {
        self.sized(7, key.as_bytes())?;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), EncodeError> { Encoder::end(self) }
}

struct SmallFrame {
    buffer: Vec<u8>,
    overflow: bool,
}

impl Write for SmallFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > REQUEST_CHUNK_BYTES + HEADER.len() - self.buffer.len() {
            self.overflow = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// The caller retains the usual one-write path. If it crosses one chunk, the
/// pipe owner replays the typed request from the start with bounded buffering.
pub(crate) fn small_request(value: &impl Serialize) -> io::Result<Option<Vec<u8>>> {
    let mut frame = SmallFrame { buffer: Vec::with_capacity(1024), overflow: false };
    frame.buffer.extend_from_slice(&HEADER);
    let encoded = encode(&mut frame, value);
    if frame.overflow {
        return Ok(None);
    }
    encoded?;
    finish_frame(&mut frame.buffer, false)?;
    Ok(Some(frame.buffer))
}

struct Chunks<'a, W> {
    output: &'a mut W,
    cancel: &'a Cancellation,
    buffer: Vec<u8>,
    started: bool,
    pipe_failed: bool,
}

impl<W: Write> Chunks<'_, W> {
    fn emit(&mut self, more: bool) -> io::Result<()> {
        self.cancel.check_io()?;
        finish_frame(&mut self.buffer, more)?;
        if let Err(error) = self.output.write_all(&self.buffer) {
            self.pipe_failed = true;
            return Err(error);
        }
        self.started = more;
        self.buffer.truncate(HEADER.len());
        Ok(())
    }
}

impl<W: Write> Write for Chunks<'_, W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let len = bytes.len();
        while !bytes.is_empty() {
            if self.buffer.len() == REQUEST_CHUNK_BYTES + HEADER.len() {
                self.emit(true)?;
            }
            let count = bytes.len().min(REQUEST_CHUNK_BYTES + HEADER.len() - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
        }
        Ok(len)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

// An empty continuation abandons a request before admission. Errors writing
// either data or that marker belong to the pipe and follow normal reaping.
pub(crate) fn write_request(
    output: &mut impl Write,
    value: &impl Serialize,
    cancel: &Cancellation,
) -> io::Result<io::Result<()>> {
    let mut chunks = Chunks {
        output, cancel,
        buffer: Vec::with_capacity(REQUEST_CHUNK_BYTES + HEADER.len()),
        started: false, pipe_failed: false,
    };
    chunks.buffer.extend_from_slice(&HEADER);
    let result = cancel.check_io()
        .and_then(|()| encode(&mut chunks, value))
        .and_then(|()| chunks.emit(false));
    match result {
        Ok(()) => Ok(Ok(())),
        Err(error) if chunks.pipe_failed => Err(error),
        Err(error) => {
            if chunks.started {
                chunks.output.write_all(&HEADER)?;
            }
            Ok(Err(error))
        }
    }
}
