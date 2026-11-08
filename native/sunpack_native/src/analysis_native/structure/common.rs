fn dict<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    Ok(PyDict::new(py))
}
