//! Capture real post-filter matcher hits before index construction.
use super::HitBuffer;
use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::sync::Mutex;

pub(super) struct Capture {
    chunk: u64,
    output: Mutex<(BufWriter<File>, u64, io::Result<()>)>,
}

impl Capture {
    pub(super) fn open(size: u64, chunk: usize, window: usize) -> io::Result<Option<Self>> {
        let Some(path) = std::env::var_os("SUNPACK_BENCH_HIT_TRACE") else {
            return Ok(None);
        };
        let chunk = chunk as u64;
        let mut file = BufWriter::new(File::create(path)?);
        file.write_all(b"SPHITS\0\x02")?;
        for value in [size, 0, window as u64, chunk] {
            file.write_all(&value.to_le_bytes())?;
        }
        Ok(Some(Self {
            chunk,
            output: Mutex::new((file, 0, Ok(()))),
        }))
    }

    pub(super) fn record(&self, batch: &HitBuffer, start: u64) {
        if batch.is_empty() {
            return;
        }
        let owner = u32::try_from(start / self.chunk);
        let hits = batch.iter();
        let (file, count, status) = &mut *self.output.lock().unwrap();
        if status.is_err() {
            return;
        }
        *status = (|| {
            let owner = owner.map_err(io::Error::other)?.to_le_bytes();
            for hit in hits {
                let mut record = [0_u8; 16];
                record[..8].copy_from_slice(&hit.offset().to_le_bytes());
                record[8] = hit.pattern;
                record[12..].copy_from_slice(&owner);
                file.write_all(&record)?;
                *count += 1;
            }
            Ok(())
        })();
    }

    pub(super) fn finish(self) -> io::Result<()> {
        let (mut file, count, status) = self.output.into_inner().unwrap();
        status?;
        file.seek(SeekFrom::Start(16))?;
        file.write_all(&count.to_le_bytes())?;
        file.flush()
    }
}
