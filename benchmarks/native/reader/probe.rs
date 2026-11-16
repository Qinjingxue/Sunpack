//! Measurements around the production reader entry points.
use crate::benchmark_process_memory::process_memory;
use crate::io::archive_state::ArchiveInput;
use crate::io::reader::NativeArchiveSession;
use crate::scan::embedded::scan_embedded_path;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufReader};
use std::sync::Arc;
use std::time::Instant;

#[derive(Deserialize)]
struct Input {
    path: String,
    #[serde(default)]
    format: String,
    #[serde(default)]
    passwords: Vec<Arc<str>>,
    runs: usize,
}

fn request() -> Result<Input, serde_json::Error> {
    serde_json::from_reader(BufReader::new(io::stdin().lock()))
}

fn measure<T>(
    mut run: impl FnMut() -> io::Result<(f64, T)>,
    runs: usize,
    report: impl FnOnce(T) -> Value,
) -> io::Result<()> {
    let before = process_memory()?;
    let mut rows = Vec::new();
    let mut result = None;
    for _ in 0..runs {
        drop(result.take());
        let (seconds, output) = run()?;
        let after = process_memory()?;
        rows.push(json!({
            "seconds": seconds,
            "peak_working_set_bytes": after.peak_working_set,
            "peak_commit_bytes": after.peak_commit,
        }));
        result = Some(output);
    }
    println!(
        "SUNPACK_BENCH {}",
        json!({
            "before_working_set_bytes": before.working_set,
            "before_commit_bytes": before.commit,
            "rows": rows, "result": result.map(report),
        })
    );
    Ok(())
}

#[test]
#[ignore = "run through benchmarks password probe-matrix"]
fn password() -> Result<(), Box<dyn std::error::Error>> {
    let args = request()?;
    let session = NativeArchiveSession::new(args.path.clone())?;
    let input = ArchiveInput::file(args.path, args.format, String::new());
    measure(
        || {
            let started = Instant::now();
            let found = crate::password::verify(
                &input,
                &args.passwords,
                std::slice::from_ref(&session),
                None,
            )?;
            Ok((started.elapsed().as_secs_f64(), found))
        },
        args.runs,
        |found| {
            json!({"status": found.status, "matched_index": found.matched_index,
                       "matched_indices": found.matched_indices, "attempts": found.attempts})
        },
    )?;
    Ok(())
}

#[test]
#[ignore = "run through benchmarks scan embedded or scan hit-index"]
fn embedded() -> Result<(), Box<dyn std::error::Error>> {
    let args = request()?;
    measure(
        || {
            let started = Instant::now();
            let scan = scan_embedded_path(&args.path, 1)?;
            Ok((started.elapsed().as_secs_f64(), scan))
        },
        args.runs,
        |scan| {
            let candidates: Vec<_> = scan
                .candidates()
                .iter()
                .filter(|item| item.is_logical_archive())
                .map(|item| (item.format, item.offset, item.end_offset))
                .collect();
            json!({"file_bytes": scan.file_size(), "candidates": candidates})
        },
    )?;
    Ok(())
}
