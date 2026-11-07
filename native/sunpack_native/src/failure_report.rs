//! Stream diagnostic data without a second, report-sized Python/Rust representation.
//! Callers retain their input objects. Container traversal costs O(depth), and text
//! conversion/escaping uses fixed chunks. Custom __str__/iterator implementations
//! can themselves allocate: this writer cannot bound allocations inside user code.
//! Unsupported application objects are rejected rather than invoking default=str.
//! Integer decimal conversion follows Python (including its digit limit); the
//! bounded text guarantee covers existing Python strings, not integer conversion.
use std::collections::HashSet;
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::PathBuf;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyFloat, PyInt, PyIterator, PyString};

use crate::io::resource_lifecycle::TrackedFile;
use crate::io::cancellation::Cancellation;

const TEXT_CHUNK: usize = 16 * 1024;
const FILE_BUFFER: usize = 64 * 1024;

fn create_parent(path: &std::path::Path) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn finish_cleanup(py: Python<'_>, result: PyResult<()>, cleanup: io::Result<()>) -> PyResult<()> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            // Cancellation must remain NativeOperationCancelled for the broker.
            error.set_context(py, Some(cleanup.into()));
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup.map_err(PyErr::from),
    }
}

// Unicode occupies only 21 bits, so escape mode fits inside each 4-byte
// staging entry. The complete pending representation is at most 64 KiB.
const JSON_ESCAPE: u32 = 1 << 31;
const ATTACHED_STEPS: usize = 1024;

fn encode_staged(out: &mut Vec<u8>, chars: &[u32]) {
    out.clear();
    for &entry in chars {
        let code = entry & !JSON_ESCAPE;
        let json = entry & JSON_ESCAPE != 0;
        match code {
            0x22 if json => out.extend_from_slice(b"\\\""),
            0x5c if json => out.extend_from_slice(b"\\\\"),
            0x08 if json => out.extend_from_slice(b"\\b"),
            0x0c if json => out.extend_from_slice(b"\\f"),
            0x0a if json => out.extend_from_slice(b"\\n"),
            0x0d if json => out.extend_from_slice(b"\\r"),
            0x09 if json => out.extend_from_slice(b"\\t"),
            0..=0x1f if json => push_unicode_escape(out, code),
            // Python permits lone surrogates; JSON escapes preserve them exactly.
            0xd800..=0xdfff => push_unicode_escape(out, code),
            _ => {
                let mut bytes = [0; 4];
                let ch = char::from_u32(code).expect("Python Unicode code point");
                out.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
}

fn push_unicode_escape(out: &mut Vec<u8>, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(&[
        b'\\', b'u', HEX[((code >> 12) & 15) as usize],
        HEX[((code >> 8) & 15) as usize], HEX[((code >> 4) & 15) as usize],
        HEX[(code & 15) as usize],
    ]);
}

struct Writer {
    file: BufWriter<TrackedFile>,
    cancellation: Cancellation,
    pending: Vec<u32>,
    encoded: Vec<u8>,
    attached_steps: usize,
}

impl Writer {
    fn new(file: TrackedFile, cancellation: Cancellation) -> Self {
        Self {
            file: BufWriter::with_capacity(FILE_BUFFER, file),
            cancellation,
            pending: Vec::with_capacity(TEXT_CHUNK),
            encoded: Vec::with_capacity(TEXT_CHUNK * 6),
            attached_steps: 0,
        }
    }

    fn flush(&mut self, py: Python<'_>) -> PyResult<()> {
        self.cancellation.check()?;
        py.detach(|| -> io::Result<()> {
            encode_staged(&mut self.encoded, &self.pending);
            self.file.write_all(&self.encoded)?;
            self.pending.clear();
            Ok(())
        })?;
        self.attached_steps = 0;
        Ok(())
    }

    fn tick(&mut self, py: Python<'_>) -> PyResult<()> {
        self.cancellation.check()?;
        self.attached_steps += 1;
        if self.attached_steps >= ATTACHED_STEPS { self.flush(py)?; }
        Ok(())
    }

    fn push(&mut self, py: Python<'_>, code: u32) -> PyResult<()> {
        self.pending.push(code);
        if self.pending.len() == TEXT_CHUNK { self.flush(py)?; }
        Ok(())
    }

    fn bytes(&mut self, py: Python<'_>, bytes: &[u8]) -> PyResult<()> {
        self.tick(py)?;
        // All callers use ASCII punctuation, booleans or numeric constants.
        for &byte in bytes { self.push(py, byte as u32)?; }
        Ok(())
    }

    fn text(&mut self, py: Python<'_>, text: &Bound<'_, PyString>, json: bool) -> PyResult<()> {
        self.tick(py)?;
        if json { self.bytes(py, b"\"")?; }
        // Never request the original string's UTF-8 cache: for a huge non-ASCII
        // diagnostic that would allocate an additional full-size representation.
        let length = unsafe { pyo3::ffi::PyUnicode_GetLength(text.as_ptr()) };
        if length < 0 { return Err(PyErr::fetch(py)); }
        let flag = if json { JSON_ESCAPE } else { 0 };
        for index in 0..length {
            // This strong reference retains the immutable Unicode object; the
            // index is bounded by its code-point length, not its UTF-8 length.
            let code = unsafe { pyo3::ffi::PyUnicode_ReadChar(text.as_ptr(), index) };
            if code == u32::MAX { return Err(PyErr::fetch(py)); }
            self.push(py, code | flag)?;
        }
        if json { self.bytes(py, b"\"")?; }
        Ok(())
    }

    fn string(&mut self, py: Python<'_>, value: &Bound<'_, PyAny>, json: bool) -> PyResult<()> {
        self.text(py, value.cast::<PyString>()?, json)
    }

    fn json(&mut self, py: Python<'_>, root: Bound<'_, PyAny>) -> PyResult<()> {
        enum Frame<'py> {
            Value(Bound<'py, PyAny>),
            Container {
                // Retain the owner: iterator alone need not keep a custom mapping
                // alive, and a live pointer is required for cycle detection.
                owner: Bound<'py, PyAny>,
                iter: Bound<'py, PyIterator>,
                mapping: bool,
                first: bool,
            },
        }
        let abc = py.import("collections.abc")?;
        let mapping_type = abc.getattr("Mapping")?;
        let sequence_type = abc.getattr("Sequence")?;
        let mut active = HashSet::new();
        let mut stack = vec![Frame::Value(root)];
        while let Some(frame) = stack.pop() {
            self.tick(py)?;
            match frame {
                Frame::Value(value) => {
                    if value.is_none() {
                        self.bytes(py, b"null")?;
                    } else if value.is_instance_of::<PyString>() {
                        self.string(py, &value, true)?;
                    } else if value.is_instance_of::<PyBool>() {
                        self.bytes(py, if value.extract::<bool>()? { b"true" } else { b"false" })?;
                    } else if value.is_instance_of::<PyInt>() {
                        let text = py.get_type::<PyInt>().call_method1("__repr__", (&value,))?;
                        self.string(py, &text, false)?;
                    } else if value.is_instance_of::<PyFloat>() {
                        let number = value.extract::<f64>()?;
                        if number.is_nan() {
                            self.bytes(py, b"NaN")?;
                        } else if number == f64::INFINITY {
                            self.bytes(py, b"Infinity")?;
                        } else if number == f64::NEG_INFINITY {
                            self.bytes(py, b"-Infinity")?;
                        } else {
                            let text = py.get_type::<PyFloat>().call_method1("__repr__", (&value,))?;
                            self.string(py, &text, false)?;
                        }
                    } else {
                        let mapping = value.is_instance(&mapping_type)?;
                        // Byte strings are not JSON sequences; reject rather than
                        // silently changing them into integer arrays.
                        let sequence = !value.is_instance_of::<pyo3::types::PyBytes>()
                            && !value.is_instance_of::<pyo3::types::PyByteArray>()
                            && value.is_instance(&sequence_type)?;
                        if mapping || sequence {
                            let id = value.as_ptr() as usize;
                            if !active.insert(id) {
                                return Err(PyValueError::new_err("Circular reference in failure details"));
                            }
                            let iter = if mapping {
                                value.call_method0("items")?.try_iter()?
                            } else {
                                value.try_iter()?
                            };
                            self.bytes(py, if mapping { b"{" } else { b"[" })?;
                            stack.push(Frame::Container { owner: value, iter, mapping, first: true });
                        } else {
                            // Arbitrary __str__ can allocate an unbounded diagnostic.
                            // Require callers to supply JSON scalars/containers instead.
                            return Err(PyTypeError::new_err("Unsupported failure detail value; expected JSON scalar, Mapping or Sequence"));
                        }
                    }
                }
                Frame::Container { owner, mut iter, mapping, first } => {
                    if let Some(item) = iter.next() {
                        let item = item?;
                        if !first { self.bytes(py, b", ")?; }
                        let value = if mapping {
                            let key = item.get_item(0)?;
                            if key.is_instance_of::<PyString>() {
                                self.string(py, &key, true)?;
                            } else if key.is_none() {
                                self.bytes(py, b"\"null\"")?;
                            } else if key.is_instance_of::<PyBool>() {
                                self.bytes(py, if key.extract::<bool>()? { b"\"true\"" } else { b"\"false\"" })?;
                            } else if key.is_instance_of::<PyInt>() || key.is_instance_of::<PyFloat>() {
                                // json.dumps permits these scalar mapping keys.
                                let key_text = if key.is_instance_of::<PyFloat>() {
                                    let v = key.extract::<f64>()?;
                                    if v.is_nan() { PyString::new(py, "NaN") }
                                    else if v == f64::INFINITY { PyString::new(py, "Infinity") }
                                    else if v == f64::NEG_INFINITY { PyString::new(py, "-Infinity") }
                                    else { py.get_type::<PyFloat>().call_method1("__repr__", (&key,))?.cast_into::<PyString>()? }
                                } else {
                                    py.get_type::<PyInt>().call_method1("__repr__", (&key,))?
                                        .cast_into::<PyString>()?
                                };
                                self.text(py, &key_text, true)?;
                            } else {
                                return Err(PyTypeError::new_err("Failure detail keys must be str, int, float, bool or None"));
                            }
                            self.bytes(py, b": ")?;
                            item.get_item(1)?
                        } else { item };
                        stack.push(Frame::Container { owner, iter, mapping, first: false });
                        stack.push(Frame::Value(value));
                    } else {
                        active.remove(&(owner.as_ptr() as usize));
                        self.bytes(py, if mapping { b"}" } else { b"]" })?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[pyfunction]
pub(crate) fn append_failure_report(
    py: Python<'_>,
    path: PathBuf,
    failure_header: &Bound<'_, PyString>,
    error_prefix: &Bound<'_, PyString>,
    errors: &Bound<'_, PyAny>,
    unknown_error: &Bound<'_, PyString>,
    details_prefix: &Bound<'_, PyString>,
    payloads: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let cancellation = Cancellation::current();
    cancellation.check()?;
    let (file, original_len) = py.detach(|| -> io::Result<_> {
        create_parent(&path)?;
        let mut file = TrackedFile::open_with(&path, "failure_report", |o| { o.write(true).create(true); })?;
        let original_len = file.seek(io::SeekFrom::End(0))?;
        Ok((file, original_len))
    })?;
    let mut writer = Writer::new(file, cancellation);
    let result = (|| -> PyResult<()> {
        writer.text(py, failure_header, false)?;
        writer.bytes(py, b"\n")?;
        writer.text(py, error_prefix, false)?;
        let mut first = true;
        for error in errors.try_iter()? {
            if !first { writer.bytes(py, b"; ")?; }
            writer.string(py, &error?, false)?;
            first = false;
        }
        if first { writer.text(py, unknown_error, false)?; }
        writer.bytes(py, b"\n")?;
        if payloads.is_truthy()? {
            writer.text(py, details_prefix, false)?;
            writer.json(py, payloads.clone())?;
            writer.bytes(py, b"\n")?;
        }
        writer.bytes(py, b"\n")?;
        writer.flush(py)?;
        py.detach(|| writer.file.flush())?;
        Ok(())
    })();
    // Drop the buffer without flushing partial data on failure, then roll back
    // this record. Previously completed failures remain usable.
    let failed = result.is_err();
    let cleanup = py.detach(move || -> io::Result<()> {
        let (file, _) = writer.file.into_parts();
        if failed { file.set_len(original_len)?; }
        drop(file);
        Ok(())
    });
    finish_cleanup(py, result, cleanup)
}

#[pyfunction]
#[pyo3(signature = (details_path, temporary_path, output_path, header))]
pub(crate) fn publish_failure_report(
    py: Python<'_>,
    details_path: Option<PathBuf>,
    temporary_path: PathBuf,
    output_path: PathBuf,
    header: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let cancellation = Cancellation::current();
    cancellation.check()?;
    if temporary_path == output_path || details_path.as_ref() == Some(&temporary_path) {
        return Err(PyValueError::new_err("Failure report temporary path must be distinct"));
    }
    // create_new prevents clobbering a temp owned by another publication.
    let file = py.detach(|| -> io::Result<_> {
        create_parent(&temporary_path)?;
        create_parent(&output_path)?;
        TrackedFile::open_with(&temporary_path, "failure_publish", |o| {
            o.write(true).create_new(true);
        })
    })?;
    let mut writer = Writer::new(file, cancellation);
    let result = (|| -> PyResult<()> {
        for part in header.try_iter()? { writer.string(py, &part?, false)?; }
        writer.flush(py)?;
        py.detach(|| -> PyResult<()> {
            if let Some(path) = details_path {
                let mut source = TrackedFile::open_reader(path, "failure_publish_source")?;
                let mut buffer = [0u8; FILE_BUFFER];
                loop {
                    writer.cancellation.check()?;
                    let count = source.read(&mut buffer)?;
                    if count == 0 { break; }
                    writer.file.write_all(&buffer[..count])?;
                }
            }
            writer.cancellation.check()?;
            writer.file.flush()?;
            writer.file.get_ref().sync_all()?;
            Ok(())
        })?;
        Ok(())
    })();
    let cancellation = writer.cancellation.clone();
    py.detach(move || {
        // into_parts avoids BufWriter's best-effort flush while unwinding.
        let (file, _) = writer.file.into_parts();
        drop(file);
    });
    let result = result.and_then(|()| {
        cancellation.check()?;
        match py.detach(|| crate::io::atomic_file::replace_with_cancel(
            &temporary_path, &output_path, &cancellation,
        )) {
            Ok(()) => Ok(()),
            Err(error) => {
                // check_io stops native retries; restore the broker's distinct
                // BaseException instead of turning cancellation into OSError.
                cancellation.check()?;
                Err(error.into())
            }
        }
    });
    let cleanup = if result.is_err() {
        py.detach(|| std::fs::remove_file(&temporary_path))
    } else { Ok(()) };
    finish_cleanup(py, result, cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped_chunk(out: &mut impl Write, chars: &[u32], json: bool) -> io::Result<()> {
        let mut encoded = Vec::with_capacity(TEXT_CHUNK * 6);
        for chunk in chars.chunks(TEXT_CHUNK) {
            let staged: Vec<_> = chunk.iter().map(|code| code | if json { JSON_ESCAPE } else { 0 }).collect();
            encode_staged(&mut encoded, &staged);
            out.write_all(&encoded)?;
        }
        Ok(())
    }

    #[test]
    fn text_escaping_preserves_unicode_controls_and_surrogates() {
        // This checks lossless diagnostic escaping, including Python-only lone
        // surrogates that a Rust String/serde Value projection cannot represent.
        let input = [0x22, 0x5c, 0, 9, 10, 13, 0x4e2d, 0x1f642, 0xd800];
        let mut output = Vec::new();
        escaped_chunk(&mut output, &input, true).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "\\\"\\\\\\u0000\\t\\n\\r中🙂\\ud800");
    }

    #[test]
    fn chunk_boundaries_do_not_change_text_or_json() {
        // Boundary-independent output is needed when a diagnostic exceeds the
        // attached-Python work budget. No Python/Windows runtime is necessary.
        let mut input = vec![0x1f642; TEXT_CHUNK + 1];
        input[TEXT_CHUNK - 1] = 0x22;
        for json in [false, true] {
            let mut whole = Vec::new();
            escaped_chunk(&mut whole, &input, json).unwrap();
            let mut chunked = Vec::new();
            for chunk in input.chunks(TEXT_CHUNK) { escaped_chunk(&mut chunked, chunk, json).unwrap(); }
            assert_eq!(whole, chunked);
        }
    }
    #[test]
    fn scalar_container_chunks_mix_syntax_and_escaped_text_without_growth() {
        // Large scalar collections exercise mixed literal/escaped staging across
        // many flushes; the large-text test alone cannot detect quoted syntax.
        let mut pending = Vec::with_capacity(TEXT_CHUNK);
        let mut encoded = Vec::with_capacity(TEXT_CHUNK * 6);
        let mut output = Vec::new();
        let mut flushes = 0;
        let mut push = |code| {
            pending.push(code);
            if pending.len() == TEXT_CHUNK {
                encode_staged(&mut encoded, &pending);
                assert!(encoded.len() <= TEXT_CHUNK * 6);
                output.extend_from_slice(&encoded);
                pending.clear();
                flushes += 1;
            }
        };
        push(b'[' as u32);
        for index in 0..100_000 {
            if index != 0 { push(b',' as u32); }
            for byte in b"[1,true,null,\"" { push(*byte as u32); }
            push(0x4e2d | JSON_ESCAPE);
            push(0x0a | JSON_ESCAPE);
            push(0x22 | JSON_ESCAPE);
            for byte in b"\"]" { push(*byte as u32); }
        }
        push(b']' as u32);
        drop(push);
        encode_staged(&mut encoded, &pending);
        output.extend_from_slice(&encoded);
        assert!(flushes > 10);
        assert_eq!(pending.capacity(), TEXT_CHUNK);
        assert_eq!(encoded.capacity(), TEXT_CHUNK * 6);
        let decoded: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let rows = decoded.as_array().unwrap();
        assert_eq!(rows.len(), 100_000);
        for row in rows {
            assert_eq!(row, &serde_json::json!([1, true, null, "中\n\""]));
        }
    }

}
