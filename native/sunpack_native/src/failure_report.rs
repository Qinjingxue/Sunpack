//! Keep diagnostic output streaming and make partial writes recoverable.
use crate::io::{atomic_file, cancellation::Cancellation, resource_lifecycle::TrackedFile};
use serde::Serialize;
use std::{
    io::{self, BufWriter, Read, Seek, Write},
    path::Path,
};

const CHUNK_SIZE: usize = 64 * 1024;

struct CheckedWriter<'a, W> {
    inner: W,
    cancellation: &'a Cancellation,
}

impl<W: Write> Write for CheckedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation.check_io()?;
        self.inner.write(&bytes[..bytes.len().min(CHUNK_SIZE)])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cancellation.check_io()?;
        self.inner.flush()
    }
}

pub(crate) fn stream_json(
    output: impl Write,
    value: &impl Serialize,
    pretty: bool,
    cancellation: &Cancellation,
) -> io::Result<()> {
    let mut output = CheckedWriter {
        inner: output,
        cancellation,
    };
    let result = if pretty {
        serde_json::to_writer_pretty(&mut output, value)
    } else {
        serde_json::to_writer(&mut output, value)
    };
    // Keep the native cancellation error intact when serialization propagates
    // a stopped write.
    cancellation.check_io()?;
    result.map_err(io::Error::other)
}

pub(crate) struct FailureRecord<'a, T> {
    pub(crate) header: &'a str,
    pub(crate) error_prefix: &'a str,
    pub(crate) errors: &'a [String],
    pub(crate) unknown_error: &'a str,
    pub(crate) details_prefix: &'a str,
    pub(crate) details: Option<&'a T>,
}

fn create_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn finish(result: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(io::Error::new(
            error.kind(),
            format!("{error} (cleanup: {cleanup})"),
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

pub(crate) fn append_failure_report<T: Serialize>(
    path: &Path,
    record: &FailureRecord<'_, T>,
    cancellation: &Cancellation,
) -> io::Result<()> {
    cancellation.check_io()?;
    create_parent(path)?;
    let mut file = TrackedFile::open_with(path, "failure_report", |options| {
        options.write(true).create(true).truncate(false);
    })?;
    let original_len = file.seek(io::SeekFrom::End(0))?;
    let mut buffer = BufWriter::with_capacity(CHUNK_SIZE, file);
    let result = (|| {
        let mut output = CheckedWriter {
            inner: &mut buffer,
            cancellation,
        };
        writeln!(output, "{}", record.header)?;
        write!(output, "{}", record.error_prefix)?;
        match record.errors.split_first() {
            Some((first, remaining)) => {
                write!(output, "{first}")?;
                for error in remaining {
                    write!(output, "; {error}")?;
                }
            }
            None => write!(output, "{}", record.unknown_error)?,
        }
        writeln!(output)?;
        if let Some(details) = record.details {
            write!(output, "{}", record.details_prefix)?;
            stream_json(&mut output, details, false, cancellation)?;
            writeln!(output)?;
        }
        writeln!(output)?;
        output.flush()
    })();
    // Never flush pending bytes on failure. Truncation also rolls back bytes
    // that had reached the file, preserving every previously written record.
    let (file, _) = buffer.into_parts();
    let cleanup = if result.is_err() {
        file.set_len(original_len)
    } else {
        Ok(())
    };
    finish(result, cleanup)
}

pub(crate) fn publish_failure_report<'a>(
    details: Option<&Path>,
    temporary: &Path,
    output: &Path,
    header: impl IntoIterator<Item = &'a str>,
    cancellation: &Cancellation,
) -> io::Result<()> {
    cancellation.check_io()?;
    if temporary == output || details == Some(temporary) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Failure report temporary path must be distinct",
        ));
    }
    create_parent(temporary)?;
    create_parent(output)?;
    let file = TrackedFile::open_with(temporary, "failure_publish", |options| {
        options.write(true).create_new(true);
    })?;
    let mut buffer = BufWriter::with_capacity(CHUNK_SIZE, file);
    let result = (|| {
        let mut writer = CheckedWriter {
            inner: &mut buffer,
            cancellation,
        };
        for part in header {
            writer.write_all(part.as_bytes())?;
        }
        if let Some(path) = details {
            let mut source = TrackedFile::open_reader(path, "failure_publish_source")?;
            let mut bytes = [0; CHUNK_SIZE];
            loop {
                cancellation.check_io()?;
                let count = source.read(&mut bytes)?;
                if count == 0 {
                    break;
                }
                writer.write_all(&bytes[..count])?;
            }
        }
        writer.flush()?;
        buffer.get_ref().sync_all()
    })();
    let (file, _) = buffer.into_parts();
    drop(file);
    let result =
        result.and_then(|()| atomic_file::replace_with_cancel(temporary, output, cancellation));
    let cleanup = if result.is_err() {
        std::fs::remove_file(temporary)
    } else {
        Ok(())
    };
    finish(result, cleanup)
}
