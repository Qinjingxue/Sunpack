use std::io;

/// Positive allocation evidence only; a generic I/O failure is not proof of OOM.
pub(crate) fn is_memory_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
        || matches!(error.raw_os_error(), Some(8 | 14 | 1455))
        || error.get_ref().is_some_and(|source| {
            source
                .downcast_ref::<crate::io::read_fault::ReadFault>()
                .is_some_and(|fault| {
                    fault.io_kind == io::ErrorKind::OutOfMemory
                        || matches!(fault.os_error, Some(8 | 14 | 1455))
                })
                || matches!(
                    source.downcast_ref::<xz2::stream::Error>(),
                    Some(xz2::stream::Error::Mem)
                )
        })
}

pub(crate) fn bytes_with_capacity(len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("could not allocate {len} input bytes"),
        )
    })?;
    Ok(bytes)
}

pub(crate) fn zeroed_bytes(len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = bytes_with_capacity(len)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

pub(crate) fn to_py_error(error: io::Error) -> pyo3::PyErr {
    if is_memory_error(&error) {
        pyo3::exceptions::PyMemoryError::new_err(error.to_string())
    } else {
        error.into()
    }
}
