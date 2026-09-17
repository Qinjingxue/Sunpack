use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

const SNAPSHOT_BUFFER_BYTES: usize = 1024 * 1024;
const EXTRACTION_BATCH_RECORDS: usize = 256;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Signed(i128),
    Unsigned(u128),
    Float(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

fn type_error(message: impl Into<String>) -> PyErr {
    PyTypeError::new_err(message.into())
}

fn io_error(error: io::Error) -> PyErr {
    PyRuntimeError::new_err(format!("native Watch snapshot I/O failed: {error}"))
}

fn extract_json_key(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if value.is_instance_of::<PyString>() {
        return value.extract::<String>();
    }
    if value.is_none() {
        return Ok("null".to_string());
    }
    if value.is_instance_of::<PyBool>() {
        return Ok(if value.extract::<bool>()? {
            "true"
        } else {
            "false"
        }
        .to_string());
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(number) = value.extract::<i128>() {
            return Ok(number.to_string());
        }
        return Ok(value.extract::<u128>()?.to_string());
    }
    if value.is_instance_of::<PyFloat>() {
        return Ok(render_float(value.extract::<f64>()?));
    }
    Err(type_error(
        "Watch snapshot JSON object keys must be scalar JSON keys",
    ))
}

pub(crate) fn extract_json(value: &Bound<'_, PyAny>) -> PyResult<JsonValue> {
    if value.is_none() {
        return Ok(JsonValue::Null);
    }
    if value.is_instance_of::<PyBool>() {
        return Ok(JsonValue::Bool(value.extract::<bool>()?));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(number) = value.extract::<i128>() {
            return Ok(JsonValue::Signed(number));
        }
        return Ok(JsonValue::Unsigned(value.extract::<u128>()?));
    }
    if value.is_instance_of::<PyFloat>() {
        return Ok(JsonValue::Float(value.extract::<f64>()?));
    }
    if value.is_instance_of::<PyString>() {
        return Ok(JsonValue::String(value.extract::<String>()?));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut items = Vec::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            items.push((extract_json_key(&key)?, extract_json(&item)?));
        }
        return Ok(JsonValue::Object(items));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(extract_json(&item)?);
        }
        return Ok(JsonValue::Array(items));
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let mut items = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            items.push(extract_json(&item)?);
        }
        return Ok(JsonValue::Array(items));
    }
    Err(type_error(
        "Watch snapshot contains a value that is not JSON serializable",
    ))
}

fn extract_record(record: &Bound<'_, PyAny>) -> PyResult<JsonValue> {
    // Match dataclasses.fields()/getattr semantics from the former Python
    // serializer: only declared dataclass fields belong to the persisted schema.
    // Runtime-only attributes may exist on these mutable Python objects and must
    // never silently become part of the v17 snapshot format.
    let field_defs = record.getattr("__dataclass_fields__")?;
    let field_defs = field_defs
        .cast::<PyDict>()
        .map_err(|_| type_error("Watch snapshot record must be a dataclass"))?;
    let attrs = record.getattr("__dict__")?;
    let attrs = attrs
        .cast::<PyDict>()
        .map_err(|_| type_error("Watch snapshot dataclass must expose __dict__"))?;

    let mut items = Vec::with_capacity(field_defs.len());
    for (field_name, _) in field_defs.iter() {
        let key = field_name.extract::<String>()?;
        let value = attrs
            .get_item(key.as_str())?
            .ok_or_else(|| type_error(format!("Watch snapshot dataclass field is missing: {key}")))?;
        items.push((key, extract_json(&value)?));
    }
    Ok(JsonValue::Object(items))
}

fn render_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value == f64::INFINITY {
        return "Infinity".to_string();
    }
    if value == f64::NEG_INFINITY {
        return "-Infinity".to_string();
    }
    let mut rendered = value.to_string();
    if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
        rendered.push_str(".0");
    }
    rendered
}

fn write_json_string<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    writer.write_all(b"\"")?;
    let bytes = value.as_bytes();
    let mut plain_start = 0usize;
    for (offset, ch) in value.char_indices() {
        let escaped: Option<&'static [u8]> = match ch {
            '"' => Some(b"\\\""),
            '\\' => Some(b"\\\\"),
            '\u{08}' => Some(b"\\b"),
            '\u{0c}' => Some(b"\\f"),
            '\n' => Some(b"\\n"),
            '\r' => Some(b"\\r"),
            '\t' => Some(b"\\t"),
            _ => None,
        };
        if let Some(escaped) = escaped {
            if plain_start < offset {
                writer.write_all(&bytes[plain_start..offset])?;
            }
            writer.write_all(escaped)?;
            plain_start = offset + ch.len_utf8();
        } else if (ch as u32) <= 0x1f {
            if plain_start < offset {
                writer.write_all(&bytes[plain_start..offset])?;
            }
            let code = ch as usize;
            let escaped = [
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(code >> 4) & 0xf],
                HEX[code & 0xf],
            ];
            writer.write_all(&escaped)?;
            plain_start = offset + ch.len_utf8();
        }
    }
    if plain_start < bytes.len() {
        writer.write_all(&bytes[plain_start..])?;
    }
    writer.write_all(b"\"")
}

pub(crate) fn write_json_value<W: Write>(writer: &mut W, value: &JsonValue) -> io::Result<()> {
    match value {
        JsonValue::Null => writer.write_all(b"null"),
        JsonValue::Bool(true) => writer.write_all(b"true"),
        JsonValue::Bool(false) => writer.write_all(b"false"),
        JsonValue::Signed(value) => writer.write_all(value.to_string().as_bytes()),
        JsonValue::Unsigned(value) => writer.write_all(value.to_string().as_bytes()),
        JsonValue::Float(value) => writer.write_all(render_float(*value).as_bytes()),
        JsonValue::String(value) => write_json_string(writer, value),
        JsonValue::Array(values) => {
            writer.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    writer.write_all(b",")?;
                }
                write_json_value(writer, value)?;
            }
            writer.write_all(b"]")
        }
        JsonValue::Object(values) => {
            writer.write_all(b"{")?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    writer.write_all(b",")?;
                }
                write_json_string(writer, key)?;
                writer.write_all(b":")?;
                write_json_value(writer, value)?;
            }
            writer.write_all(b"}")
        }
    }
}

fn write_record_batch<W: Write>(
    writer: &mut W,
    batch: &[(String, JsonValue)],
    first_record: &mut bool,
) -> io::Result<()> {
    for (key, value) in batch {
        if *first_record {
            *first_record = false;
        } else {
            writer.write_all(b",")?;
        }
        write_json_string(writer, key)?;
        writer.write_all(b":")?;
        write_json_value(writer, value)?;
    }
    Ok(())
}

fn write_record_map(
    py: Python<'_>,
    writer: &mut BufWriter<std::fs::File>,
    name: &'static [u8],
    records: &Bound<'_, PyDict>,
) -> PyResult<()> {
    py.detach(|| {
        writer.write_all(b",")?;
        writer.write_all(name)?;
        writer.write_all(b":{")
    })
    .map_err(io_error)?;

    let mut first_record = true;
    let mut batch = Vec::with_capacity(EXTRACTION_BATCH_RECORDS);
    for (key, record) in records.iter() {
        batch.push((extract_json_key(&key)?, extract_record(&record)?));
        if batch.len() >= EXTRACTION_BATCH_RECORDS {
            py.detach(|| write_record_batch(writer, &batch, &mut first_record))
                .map_err(io_error)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        py.detach(|| write_record_batch(writer, &batch, &mut first_record))
            .map_err(io_error)?;
    }
    py.detach(|| writer.write_all(b"}")).map_err(io_error)?;
    Ok(())
}

#[pyfunction]
pub(crate) fn write_watch_state_snapshot_native(
    py: Python<'_>,
    path: String,
    version: u32,
    checkpoint_seq: u64,
    password_generation: u64,
    password_source_signature: String,
    watch_cursors: &Bound<'_, PyDict>,
    pending_work: &Bound<'_, PyDict>,
    entries: &Bound<'_, PyDict>,
    groups: &Bound<'_, PyDict>,
) -> PyResult<u64> {
    let path = PathBuf::from(path);
    let cursors = extract_json(watch_cursors.as_any())?;
    let file = py
        .detach(|| {
            let mut options = OpenOptions::new();
            options.write(true).truncate(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
                options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
            }
            options.open(&path)
        })
        .map_err(io_error)?;
    let mut writer = BufWriter::with_capacity(SNAPSHOT_BUFFER_BYTES, file);

    py.detach(|| -> io::Result<()> {
        writer.write_all(b"{\"version\":")?;
        writer.write_all(version.to_string().as_bytes())?;
        writer.write_all(b",\"checkpoint_seq\":")?;
        writer.write_all(checkpoint_seq.to_string().as_bytes())?;
        writer.write_all(b",\"password_generation\":")?;
        writer.write_all(password_generation.to_string().as_bytes())?;
        writer.write_all(b",\"password_source_signature\":")?;
        write_json_string(&mut writer, &password_source_signature)?;
        writer.write_all(b",\"watch_cursors\":")?;
        write_json_value(&mut writer, &cursors)
    })
    .map_err(io_error)?;

    write_record_map(py, &mut writer, b"\"pending_work\"", pending_work)?;
    write_record_map(py, &mut writer, b"\"entries\"", entries)?;
    write_record_map(py, &mut writer, b"\"groups\"", groups)?;

    py.detach(|| -> io::Result<u64> {
        writer.write_all(b"}")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(writer.get_ref().metadata()?.len())
    })
    .map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_encoder_matches_compact_utf8_json_contract() {
        let mut out = Vec::new();
        write_json_string(&mut out, "雪\n\"\\\u{0001}").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"雪\\n\\\"\\\\\\u0001\"");
    }

    #[test]
    fn float_encoder_preserves_float_shape_and_non_finite_values() {
        assert_eq!(render_float(1.0), "1.0");
        assert_eq!(render_float(-0.0), "-0.0");
        assert_eq!(render_float(f64::INFINITY), "Infinity");
        assert_eq!(render_float(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(render_float(f64::NAN), "NaN");
    }
}
