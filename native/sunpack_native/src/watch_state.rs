use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use std::io::{self, Write};

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
