use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs;

#[derive(Debug, Clone)]
pub(crate) enum Segment {
    Range { path: String, start: u64, len: u64 },
}

impl Segment {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Segment::Range { len, .. } => *len,
        }
    }
}

pub(crate) fn build_segments(source: &Bound<'_, PyDict>) -> PyResult<Vec<Segment>> {
    Ok(source_segments(source)?
        .into_iter()
        .filter(|segment| segment.len() > 0)
        .collect())
}

fn source_segments(source: &Bound<'_, PyDict>) -> PyResult<Vec<Segment>> {
    let entry_path = optional_string(source, "entry_path")?.unwrap_or_default();
    let open_mode = optional_string(source, "open_mode")?.unwrap_or_else(|| "file".to_string());
    if open_mode == "file_range" {
        if let Some(parts) = source.get_item("parts")? {
            let parts = parts.cast::<PyList>()?;
            if let Some(first) = parts.iter().next() {
                let item = first.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                return Ok(vec![range_segment(&path, start, end)?]);
            }
        }
        return Err(pyo3::exceptions::PyValueError::new_err(
            "file_range requires canonical parts",
        ));
    }
    if open_mode == "concat_ranges" {
        if let Some(ranges) = source.get_item("ranges")? {
            let ranges = ranges.cast::<PyList>()?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let item = item.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                output.push(range_segment(&path, start, end)?);
            }
            if !output.is_empty() {
                return Ok(output);
            }
        }
    }
    if let Some(parts) = source.get_item("parts")? {
        let parts = parts.cast::<PyList>()?;
        let mut output = Vec::new();
        for item in parts.iter() {
            let item = item.cast::<PyDict>()?;
            let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
            let start = optional_u64(item, "start")?.unwrap_or(0);
            let end = optional_u64(item, "end")?;
            if start != 0 || end.is_some() {
                output.push(range_segment(&path, start, end)?);
            } else if !path.is_empty() {
                output.push(range_segment(&path, 0, None)?);
            }
        }
        if !output.is_empty() {
            return Ok(output);
        }
    }
    Ok(vec![range_segment(&entry_path, 0, None)?])
}

fn range_segment(path: &str, start: u64, end: Option<u64>) -> PyResult<Segment> {
    let size = fs::metadata(path)?.len();
    if start > size {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range start is beyond input size",
        ));
    }
    let effective_end = end.unwrap_or(size).min(size);
    if effective_end < start {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range end is before range start",
        ));
    }
    Ok(Segment::Range {
        path: path.to_string(),
        start,
        len: effective_end - start,
    })
}

type ProjectedInput = Option<Py<PyDict>>;

/// Resolve the physical layout once for all selected analysis ranges.
#[pyfunction]
pub(crate) fn archive_input_slices(
    source: &Bound<'_, PyDict>,
    slices: Vec<(String, u64, Option<u64>)>,
) -> PyResult<(Vec<ProjectedInput>, ProjectedInput)> {
    let Some((first_format, first_start, first_end)) = slices.first() else {
        return Ok((Vec::new(), None));
    };
    let segments = build_segments(source)?;
    let total = segments
        .iter()
        .try_fold(0u64, |sum, part| sum.checked_add(part.len()))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("input size overflow"))?;
    let projected = slices
        .iter()
        .map(|(format, start, end)| {
            project_input_slice(source, &segments, total, format, *start, *end, false)
        })
        .collect::<PyResult<Vec<_>>>()?;
    let probe = if projected[0].is_none() {
        project_input_slice(
            source,
            &segments,
            total,
            first_format,
            *first_start,
            *first_end,
            true,
        )?
    } else {
        None
    };
    Ok((projected, probe))
}

fn project_input_slice(
    source: &Bound<'_, PyDict>,
    segments: &[Segment],
    total: u64,
    format_hint: &str,
    start: u64,
    end: Option<u64>,
    probe: bool,
) -> PyResult<ProjectedInput> {
    let py = source.py();
    let Some(mut end) = end.or(probe.then_some(total)) else {
        return Ok(None);
    };
    if start >= end || end > total {
        return Ok(None);
    }
    // RAR callbacks name independent volume containers. A password probe may
    // read the bounded head; extraction must keep the structured volume table.
    if format_hint == "rar" && segments.len() > 1 {
        if !probe || start == 0 {
            return Ok(probe.then(|| source.clone().unbind()));
        }
        end = end.min(segments[0].len());
        if start >= end {
            return Ok(None);
        }
    } else if start == 0 && end == total {
        return Ok(probe.then(|| source.clone().unbind()));
    }
    let mut cursor = 0u64;
    let mut mapped = Vec::new();
    for segment in segments {
        let Segment::Range {
            path,
            start: base,
            len,
        } = segment;
        let stop = cursor + len;
        let begin = start.max(cursor);
        let finish = end.min(stop);
        if begin < finish {
            let row = PyDict::new(py);
            row.set_item("path", path)?;
            row.set_item("start", base + begin - cursor)?;
            row.set_item("end", base + finish - cursor)?;
            mapped.push(row);
        }
        cursor = stop;
        if cursor >= end {
            break;
        }
    }
    if mapped.is_empty() {
        return Ok(None);
    }
    let output = PyDict::new(py);
    output.set_item("entry_path", source.get_item("entry_path")?)?;
    output.set_item("format_hint", format_hint)?;
    output.set_item("logical_name", source.get_item("logical_name")?)?;
    let single = mapped.len() == 1;
    output.set_item(
        "open_mode",
        if single {
            "file_range"
        } else {
            "concat_ranges"
        },
    )?;
    output.set_item(
        if single { "parts" } else { "ranges" },
        PyList::new(py, mapped)?,
    )?;
    Ok(Some(output.unbind()))
}

fn optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}
