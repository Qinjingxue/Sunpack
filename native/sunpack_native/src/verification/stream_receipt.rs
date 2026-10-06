//! Match the analysis-owned stream plan against finalized native output.
//! No source re-decode and no output re-hash: the decoder already checked XXH32.
use crate::scan::directory::NativeOutputInventory;
use pyo3::prelude::*;
use pyo3::types::PyDict;

fn number(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    dict.get_item(key)?
        .filter(|v| !v.is_none())
        .map(|v| v.extract())
        .transpose()
}
#[pyfunction]
pub(crate) fn verify_stream_receipt(
    py: Python<'_>,
    plan: &Bound<'_, PyDict>,
    receipt: &Bound<'_, PyDict>,
    inventory: PyRef<'_, NativeOutputInventory>,
) -> PyResult<Py<PyDict>> {
    let complete = plan
        .get_item("complete")?
        .is_some_and(|v| v.is_truthy().unwrap_or(false));
    let snapshot = inventory.verification_snapshot();
    let result = PyDict::new(py);
    let mut mismatch = Vec::new();
    for field in [
        "input_bytes",
        "frames",
        "skippable_frames",
        "legacy_frames",
        "content_checked_frames",
        "block_checked_frames",
    ] {
        if number(plan, field)?.is_none() || number(plan, field)? != number(receipt, field)? {
            mismatch.push(field);
        }
    }
    let frames = number(plan, "frames")?.unwrap_or(0);
    let output = number(receipt, "output_bytes")?;
    if let Some(expected) = number(plan, "expected_size")? {
        if output != Some(expected) {
            mismatch.push("expected_size");
        }
    }
    if number(receipt, "error")? != Some(0) {
        mismatch.push("decoder_error");
    }
    if !snapshot.exists
        || !snapshot.is_dir
        || snapshot.files.len() != 1
        || snapshot.files.iter().any(|item| {
            item.status != 1 || Some(item.size) != output || item.bytes_written != item.size
        })
    {
        mismatch.push("output_inventory");
    }
    let checked = number(receipt, "content_checked_frames")?.unwrap_or(0);
    let content = if checked == frames && frames > 0 {
        "verified_complete"
    } else if checked > 0 {
        "verified_partial"
    } else {
        "unknown"
    };
    result.set_item(
        "status",
        if !complete || frames == 0 {
            "skipped"
        } else if mismatch.is_empty() {
            "passed"
        } else {
            "failed"
        },
    )?;
    result.set_item("mismatches", mismatch)?;
    result.set_item("content_integrity", content)?;
    result.set_item(
        "verification_strength",
        if checked > 0 { "checksum" } else { "manifest" },
    )?;
    result.set_item("checksum_algorithm", "xxh32")?;
    result.set_item("frames", frames)?;
    result.set_item("content_checked_frames", checked)?;
    Ok(result.unbind())
}
