// Instrumentation only: appended to an isolated copy of embedded.rs.
// Records the actual post-filter matcher output before prepare/encoding.
struct BenchmarkCapture {
    file: std::fs::File,
    count: u64,
}
static BENCHMARK_CAPTURE: std::sync::Mutex<Option<BenchmarkCapture>> = std::sync::Mutex::new(None);
fn benchmark_capture_batch(
    batch: &HitBuffer,
    start: u64,
    size: u64,
    chunk: usize,
) -> std::io::Result<()> {
    use std::io::Write;
    let Some(path) = std::env::var_os("SUNPACK_BENCH_HIT_TRACE") else {
        return Ok(());
    };
    let mut state = BENCHMARK_CAPTURE
        .lock()
        .map_err(|_| std::io::Error::other("trace lock"))?;
    if state.is_none() {
        let mut file = std::fs::File::create(path)?;
        file.write_all(b"SPHITS\0\0")?;
        for value in [size, 0u64, 0u64, chunk as u64] {
            file.write_all(&value.to_le_bytes())?;
        }
        *state = Some(BenchmarkCapture { file, count: 0 });
    }
    let state = state.as_mut().unwrap();
    let owner = u32::try_from(start / chunk as u64).map_err(std::io::Error::other)?;
    let mut bytes = Vec::with_capacity(batch.hits.len() * 16);
    for hit in &batch.hits {
        let hit = hit.unpack(batch.base);
        bytes.extend_from_slice(&hit.offset().to_le_bytes());
        bytes.push(hit.pattern);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&owner.to_le_bytes());
    }
    state.file.write_all(&bytes)?;
    state.count += batch.hits.len() as u64;
    Ok(())
}
fn benchmark_capture_finish() -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut lock = BENCHMARK_CAPTURE
        .lock()
        .map_err(|_| std::io::Error::other("trace lock"))?;
    if let Some(mut state) = lock.take() {
        state.file.seek(SeekFrom::Start(16))?;
        state.file.write_all(&state.count.to_le_bytes())?;
        state.file.flush()?;
    }
    Ok(())
}
