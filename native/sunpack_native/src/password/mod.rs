pub(crate) mod input;
pub(crate) mod rar;
pub(crate) mod seven_zip;
pub(crate) mod zip;

use crate::io::read_fault::ReadFault;
use pyo3::prelude::*;
use pyo3::types::PyDict;

pub(crate) fn password_read_fault_status(py: Python<'_>, fault: &ReadFault) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    let status = if fault.possible_missing_volume() {
        "needs_volume_or_tail_damaged"
    } else {
        "damaged"
    };
    result.set_item("status", status)?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", 0)?;
    result.set_item("message", fault.to_string())?;
    fault.write_python(&result)?;
    Ok(result.into())
}
pub(crate) mod context;
