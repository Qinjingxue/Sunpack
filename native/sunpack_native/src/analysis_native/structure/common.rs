fn dict<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    Ok(PyDict::new(py))
}

fn set_read_fault(
    result: &Bound<'_, PyDict>,
    fault: &ReadFault,
    legacy_error: &str,
) -> PyResult<()> {
    result.set_item("error", legacy_error)?;
    fault.write_python_with_damage_flags(result)
}
