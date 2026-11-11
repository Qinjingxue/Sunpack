//! Binary worker frames. The matching C++ codec is internal/worker_wire.hpp.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use std::{fmt, io};

#[derive(Debug)]
pub(super) struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}
impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}
pub(super) fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn invalid(message: &str) -> Error {
    Error(message.into())
}

pub(super) struct Decoder<'a> {
    pub data: &'a [u8],
    depth: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, depth: 0 }
    }
    pub fn routing_job_id(&mut self) -> Result<String, Error> {
        if self.byte()? != 10 {
            return Err(invalid("worker object expected"));
        }
        while self.data.first() != Some(&0) {
            let key = <&str>::deserialize(&mut *self)?;
            if key == "job_id" {
                return String::deserialize(&mut *self);
            }
            de::IgnoredAny::deserialize(&mut *self)?;
        }
        Err(invalid("worker job_id missing"))
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.data.len() {
            return Err(invalid("truncated worker value"));
        }
        let (head, tail) = self.data.split_at(count);
        self.data = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn string(&mut self) -> Result<&'a [u8], Error> {
        let count = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(count)
    }
    fn finish_container(&mut self) -> Result<(), Error> {
        self.depth -= 1;
        if self.byte()? != 0 {
            return Err(invalid("worker container has extra values"));
        }
        Ok(())
    }
}
impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.byte()? {
            1 => visitor.visit_unit(),
            2 => visitor.visit_bool(false),
            3 => visitor.visit_bool(true),
            4 => visitor.visit_u64(u64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            5 => visitor.visit_i64(i64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            6 => visitor.visit_f64(f64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            7 => visitor.visit_borrowed_str(
                std::str::from_utf8(self.string()?).map_err(|_| invalid("invalid worker UTF-8"))?,
            ),
            8 => visitor.visit_borrowed_bytes(self.string()?),
            tag @ (9 | 10) => {
                if self.depth == 64 {
                    return Err(invalid("worker value nesting exceeds schema"));
                }
                self.depth += 1;
                let value = if tag == 9 {
                    visitor.visit_seq(&mut *self)?
                } else {
                    visitor.visit_map(&mut *self)?
                };
                self.finish_container()?;
                Ok(value)
            }
            11 => visitor.visit_u64(self.byte()? as u64),
            12 => visitor.visit_u64(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64),
            _ => Err(invalid("invalid worker value tag")),
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.data.first() == Some(&1) {
            self.byte()?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    serde::forward_to_deserialize_any! { bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any }
}
impl<'de> SeqAccess<'de> for &mut Decoder<'de> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.data.first() == Some(&0) {
            Ok(None)
        } else {
            seed.deserialize(&mut **self).map(Some)
        }
    }
}
impl<'de> MapAccess<'de> for &mut Decoder<'de> {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.data.first() {
            Some(0) => Ok(None),
            Some(7) => seed.deserialize(&mut **self).map(Some),
            _ => Err(invalid("worker object key must be text")),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        seed.deserialize(&mut **self)
    }
}

fn sized(out: &mut Vec<u8>, tag: u8, data: &[u8]) -> io::Result<()> {
    let size = u32::try_from(data.len())
        .map_err(|_| protocol_error("worker string exceeds u32 length"))?;
    out.push(tag);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn encode(out: &mut Vec<u8>, value: &Value, depth: usize) -> io::Result<()> {
    if depth > 64 {
        return Err(protocol_error("worker value nesting exceeds schema"));
    }
    match value {
        Value::Null => out.push(1),
        Value::Bool(value) => out.push(if *value { 3 } else { 2 }),
        Value::Number(value) => {
            if let Some(n) = value.as_u64() {
                if n <= u8::MAX as u64 {
                    out.extend_from_slice(&[11, n as u8]);
                } else if n <= u32::MAX as u64 {
                    out.push(12);
                    out.extend_from_slice(&(n as u32).to_le_bytes());
                } else {
                    out.push(4);
                    out.extend_from_slice(&n.to_le_bytes());
                }
            } else if let Some(n) = value.as_i64() {
                out.push(5);
                out.extend_from_slice(&n.to_le_bytes());
            } else if let Some(n) = value.as_f64() {
                out.push(6);
                out.extend_from_slice(&n.to_le_bytes());
            } else {
                return Err(protocol_error("unsupported worker number"));
            }
        }
        Value::String(text) => sized(out, 7, text.as_bytes())?,
        Value::Array(items) => {
            out.push(9);
            for item in items {
                encode(out, item, depth + 1)?;
            }
            out.push(0);
        }
        Value::Object(fields) => {
            out.push(10);
            for (key, value) in fields {
                sized(out, 7, key.as_bytes())?;
                encode(out, value, depth + 1)?;
            }
            out.push(0);
        }
    }
    Ok(())
}

pub(crate) fn encode_worker_frame(value: &Value) -> io::Result<Vec<u8>> {
    if !value.is_object() {
        return Err(protocol_error("worker object expected"));
    }
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(b"SPBF\0\0\0\0");
    encode(&mut out, value, 0)?;
    let size = u32::try_from(out.len() - 8)
        .map_err(|_| protocol_error("worker frame exceeds u32 length"))?;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    Ok(out)
}

pub(super) fn frame_payload(frame: &[u8]) -> io::Result<&[u8]> {
    let size = frame_size(frame)?;
    if size != frame.len() {
        return Err(protocol_error("truncated or trailing worker frame"));
    }
    Ok(&frame[8..])
}
fn frame_size(header: &[u8]) -> io::Result<usize> {
    if header.len() < 8 || &header[..4] != b"SPBF" {
        return Err(protocol_error("invalid worker frame header"));
    }
    Ok(u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize + 8)
}

/// Holds only an incomplete frame. Complete frames in the incoming read are
/// decoded in place without full-stream copies.
#[derive(Default)]
pub(crate) struct NativeWorkerFrameDecoder {
    pending: Vec<u8>,
    failure: Option<String>,
}
impl NativeWorkerFrameDecoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn feed(
        &mut self,
        mut data: &[u8],
    ) -> io::Result<Vec<super::worker_event::WorkerFrame>> {
        self.check()?;
        let mut events = Vec::new();
        let decoded = (|| -> io::Result<()> {
            while !data.is_empty() {
                if self.pending.is_empty() && data.len() >= 8 {
                    let size = frame_size(data)?;
                    if data.len() >= size {
                        events.push(super::worker_event::parse_worker_transport_event(
                            &data[..size],
                        )?);
                        data = &data[size..];
                        continue;
                    }
                }
                let target = if self.pending.len() < 8 {
                    8
                } else {
                    frame_size(&self.pending)?
                };
                let count = (target - self.pending.len()).min(data.len());
                self.pending.extend_from_slice(&data[..count]);
                data = &data[count..];
                if self.pending.len() >= 8 && self.pending.len() == frame_size(&self.pending)? {
                    events.push(super::worker_event::parse_worker_transport_event(
                        &self.pending,
                    )?);
                    // Drop the backing allocation before an idle pipe wait.
                    self.pending = Vec::new();
                }
            }
            Ok(())
        })();
        if let Err(error) = decoded {
            self.pending = Vec::new();
            self.failure = Some(error.to_string());
            if events.is_empty() {
                return Err(error);
            }
        }
        Ok(events)
    }
    /// Deliver complete preceding frames before reporting a damaged suffix.
    /// Call after dispatching each batch, before waiting for more pipe input.
    pub(crate) fn check(&self) -> io::Result<()> {
        if let Some(error) = &self.failure {
            return Err(protocol_error(error.clone()));
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.check()?;
        if !self.pending.is_empty() {
            self.pending = Vec::new();
            return Err(protocol_error("truncated worker frame at EOF"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_worker_frame, NativeWorkerFrameDecoder};
    use serde_json::json;

    #[test]
    fn framing_keeps_complete_events_across_fragmentation_and_errors() {
        let expected = json!({
            "type": "progress", "job_id": "目录😀\u{0}\r\n\\\"",
            "values": [null, true, false, 0, 255, 256, u64::MAX, i64::MIN, 0.125]
        });
        let frame = encode_worker_frame(&expected).unwrap();
        for offset in 0..=frame.len() {
            let mut decoder = NativeWorkerFrameDecoder::new();
            let mut events = decoder.feed(&frame[..offset]).unwrap();
            let tail = [&frame[offset..], &frame].concat();
            events.extend(decoder.feed(&tail).unwrap());
            decoder.finish().unwrap();
            assert_eq!(events.len(), 2);
            assert!(events.into_iter().all(|event| event.summary == expected));
            if offset > 0 && offset < frame.len() {
                decoder.feed(&frame[..offset]).unwrap();
                assert!(decoder
                    .finish()
                    .unwrap_err()
                    .to_string()
                    .contains("truncated"));
            }
        }
        let mut decoder = NativeWorkerFrameDecoder::new();
        let tail = [frame.as_slice(), b"broken frame"].concat();
        assert_eq!(decoder.feed(&tail).unwrap()[0].summary, expected);
        assert!(decoder
            .check()
            .unwrap_err()
            .to_string()
            .contains("frame header"));
    }
}
