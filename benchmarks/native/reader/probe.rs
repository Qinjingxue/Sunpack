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
    #[serde(default = "default_kdf_threads")]
    kdf_threads: usize,
    #[serde(default)]
    candidate_count: usize,
    #[serde(default)]
    correct_index: Option<usize>,
    #[serde(default)]
    correct_password: Option<Arc<str>>,
}

fn default_kdf_threads() -> usize { 4 }

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
    let mut preparation = crate::password::context::Preparation::default();
    measure(
        || {
            let started = Instant::now();
            let found = crate::password::verify(
                &mut preparation,
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

fn cpu_seconds() -> io::Result<f64> {
    use windows_sys::Win32::{Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetProcessTimes}};
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    if unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited,
        &mut kernel, &mut user) } == 0 { return Err(io::Error::last_os_error()); }
    let ticks = |t: FILETIME| ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64;
    Ok((ticks(kernel) + ticks(user)) as f64 / 10_000_000.0)
}
fn memory() -> io::Result<Value> {
    let m = process_memory()?;
    Ok(json!({"working_set_bytes":m.working_set,"commit_bytes":m.commit,
        "peak_working_set_bytes":m.peak_working_set,"peak_commit_bytes":m.peak_commit}))
}

// Opt-in phase accounting: [] constructs the same immutable context without
// candidate KDF work; the complete list then uses the ordinary verifier.
// Windows high-water marks are process-lifetime values, not per-phase peaks.
#[test]
#[ignore = "run through the password study harness"]
fn password_phases() -> Result<(), Box<dyn std::error::Error>> {
    let args = request()?;
    let session = NativeArchiveSession::new(args.path.clone())?;
    let input = ArchiveInput::file(args.path, args.format, String::new());
    let mut rows = Vec::new();
    for _ in 0..args.runs {
        let before = memory()?;
        let mut preparation = crate::password::context::Preparation::default();
        let cpu = cpu_seconds()?;
        let started = Instant::now();
        let prepared = crate::password::verify(&mut preparation, &input, &[],
            std::slice::from_ref(&session), None)?;
        let prepare_seconds = started.elapsed().as_secs_f64();
        let prepare_cpu_seconds = cpu_seconds()? - cpu;
        let after_prepare = memory()?;
        let cpu = cpu_seconds()?;
        let started = Instant::now();
        let found = crate::password::verify(&mut preparation, &input, &args.passwords,
            std::slice::from_ref(&session), None)?;
        let candidates_seconds = started.elapsed().as_secs_f64();
        let candidates_cpu_seconds = cpu_seconds()? - cpu;
        let after_candidates = memory()?;
        drop(preparation);
        let after_drop = memory()?;
        rows.push(json!({"prepare_seconds":prepare_seconds,"prepare_cpu_seconds":prepare_cpu_seconds,
            "candidates_seconds":candidates_seconds,"candidates_cpu_seconds":candidates_cpu_seconds,
            "before":before,"after_prepare":after_prepare,"after_candidates":after_candidates,
            "after_drop":after_drop,"prepare_status":prepared.status,
            "result":{"status":found.status,"matched_index":found.matched_index,
                "matched_indices":found.matched_indices,"attempts":found.attempts,
                "final_confirmation_required":found.final_confirmation_required,
                "match_evidence":found.match_evidence}}));
    }
    println!("SUNPACK_BENCH {}", json!({"rows":rows}));
    Ok(())
}

// Test-build-only policy experiment: fixed six candidate workers, one reusable
// Argon2 arena each. KDF lanes remain part of the format; only scheduling changes.
#[test]
#[ignore = "run through the ENC password scheduling study"]
fn enc_scheduling() -> Result<(), Box<dyn std::error::Error>> {
    use rayon::prelude::*;
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use sunpack_enc::{PasswordProbe, Workspace};
    const WORKERS: usize = 6;
    let args = request()?;
    if !matches!(args.kdf_threads, 1 | 2 | 4) {
        return Err(io::Error::other("kdf_threads must be 1, 2, or 4").into());
    }
    let mut candidates = args.passwords;
    if candidates.is_empty() {
        candidates = (0..args.candidate_count)
            .map(|i| Arc::<str>::from(format!("enc-study-wrong-{i}")))
            .collect();
    } else if args.candidate_count != 0 && args.candidate_count != candidates.len() {
        return Err(io::Error::other("candidate_count disagrees with passwords length").into());
    }
    match (args.correct_index, args.correct_password) {
        (Some(index), Some(password)) if index < candidates.len() => candidates[index] = password,
        (None, None) => (),
        _ => return Err(io::Error::other("correct_index and correct_password must be supplied together, with an in-range index").into()),
    }
    let mut file = std::fs::File::open(args.path)?;
    let length = file.metadata()?.len();
    let mut header = [0u8; 72];
    file.read_exact(&mut header)?;
    let probe = PasswordProbe::parse(&header, length)
        .map_err(|e| io::Error::other(format!("ENC header: {e:?}")))?;
    if probe.workspace_bytes() * WORKERS > 64 * 1024 * 1024 {
        return Err(io::Error::other("six ENC workspaces exceed the 64 MiB study budget").into());
    }
    // Initialize the common executor outside timing, identically for every mode.
    let executor_threads = rayon::current_num_threads();
    let mut rows = Vec::new();
    for _ in 0..args.runs {
        let before = memory()?;
        let next = AtomicUsize::new(0);
        let earliest = AtomicUsize::new(candidates.len());
        let evaluated = AtomicUsize::new(0);
        let cpu = cpu_seconds()?;
        let started = Instant::now();
        let found = (0..WORKERS).into_par_iter().filter_map(|_| {
            let mut workspace = Workspace::with_threads(args.kdf_threads);
            let mut utf16 = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= earliest.load(Ordering::Relaxed) { break; }
                utf16.clear();
                utf16.extend(candidates[index].encode_utf16());
                evaluated.fetch_add(1, Ordering::Relaxed);
                match probe.matches(&utf16, &mut workspace) {
                    Ok(false) => (),
                    outcome => {
                        earliest.fetch_min(index, Ordering::Relaxed);
                        return Some((index, outcome));
                    }
                }
            }
            None
        }).min_by_key(|(index, _)| *index);
        // All worker arenas have been wiped/dropped before recording this time.
        let seconds = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()? - cpu;
        let actual_attempts = evaluated.load(Ordering::Relaxed);
        let matched_index = match found {
            Some((index, Ok(true))) => Some(index),
            Some((_, Err(e))) => return Err(io::Error::other(format!("ENC probe: {e:?}")).into()),
            _ => None,
        };
        rows.push(json!({"seconds":seconds,"cpu_seconds":cpu,
            "attempts":matched_index.map_or(candidates.len(), |i| i + 1),
            "evaluated_candidates":actual_attempts,
            "candidates_per_second":actual_attempts as f64 / seconds,
            "matched_index":matched_index,"before":before,"after_drop":memory()?}));
    }
    println!("SUNPACK_BENCH {}", json!({"rows":rows,
        "kdf_threads":args.kdf_threads,"workers":WORKERS,
        "executor_threads":executor_threads,"candidate_count":candidates.len(),
        "workspace_bytes":probe.workspace_bytes(),
        "max_workspace_bytes":probe.workspace_bytes() * WORKERS}));
    Ok(())
}
