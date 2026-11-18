//! ENC password-stage and scheduling measurements, compiled only by cargo test.
use super::*;

/// Standalone, test-build-only probe. Run with --ignored --nocapture; each JSON
/// line reports overlapping worker wall intervals, not summed CPU time.
#[test]
#[ignore]
fn enc_study_phases() {
    #[cfg(windows)]
    fn memory_json() -> String {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            faults: u32,
            peak_rss: usize,
            rss: usize,
            peak_paged: usize,
            paged: usize,
            peak_nonpaged: usize,
            nonpaged: usize,
            commit: usize,
            peak_commit: usize,
            private: usize,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn K32GetProcessMemoryInfo(
                process: *mut std::ffi::c_void,
                counters: *mut Counters,
                cb: u32,
            ) -> i32;
        }
        let mut counters = Counters::default();
        counters.cb = std::mem::size_of::<Counters>() as u32;
        let cb = counters.cb;
        // The current process and a correctly sized writable EX structure.
        if unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb) } == 0 {
            return "null".into();
        }
        format!(
            "{{\"rss\":{},\"private\":{},\"peak_rss\":{},\"peak_commit\":{}}}",
            counters.rss, counters.private, counters.peak_rss, counters.peak_commit
        )
    }
    #[cfg(not(windows))]
    fn memory_json() -> String {
        "null".into()
    }

    #[cfg(windows)]
    fn cpu_seconds() -> Option<f64> {
        #[repr(C)]
        #[derive(Default)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn GetProcessTimes(
                process: *mut std::ffi::c_void,
                creation: *mut FileTime,
                exit: *mut FileTime,
                kernel: *mut FileTime,
                user: *mut FileTime,
            ) -> i32;
        }
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        // Valid current-process handle and writable FILETIME outputs.
        if unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return None;
        }
        let ticks = |time: FileTime| (u64::from(time.high) << 32) | u64::from(time.low);
        Some((ticks(kernel) + ticks(user)) as f64 / 10_000_000.0)
    }
    #[cfg(not(windows))]
    fn cpu_seconds() -> Option<f64> {
        None
    }
    use rayon::prelude::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;
    let number = |name: &str, default: usize| {
        std::env::var(format!("ENC_STUDY_{name}"))
            .map(|value| value.parse::<usize>().expect("numeric ENC_STUDY parameter"))
            .unwrap_or(default)
    };
    let count = number("CANDIDATES", 256);
    let workers = number("WORKERS", 3);
    let threads = number("THREADS", 1);
    let runs = number("RUNS", 3);
    let pool_threads = number(
        "POOL_THREADS",
        std::thread::available_parallelism().unwrap().get(),
    );
    assert!(pool_threads >= workers);
    assert!((1..=16).contains(&workers));
    assert!([1, 2, 4].contains(&threads));
    assert!(count > 0 && runs > 0);
    let correct = std::env::var("ENC_STUDY_CORRECT_INDEX")
        .map(|value| value.parse::<isize>().expect("numeric correct index"))
        .ok()
        .and_then(|index| usize::try_from(index).ok())
        .unwrap_or(count);
    let password = std::env::var("ENC_STUDY_PASSWORD")
        .or_else(|_| std::env::var("ENC_PASSWORD"))
        .unwrap_or_else(|_| "sunpack-test".into());
    let path = std::env::var("ENC_STUDY_PATH").expect("set ENC_STUDY_PATH to an ENC v4 fixture");
    let mut input = std::fs::File::open(path).unwrap();
    let length = input.metadata().unwrap().len();
    let probe = PasswordProbe::read(&mut input, length).unwrap();
    let parameters = probe.header.params().unwrap();
    let candidates: Vec<Vec<u16>> = (0..count)
        .map(|index| {
            if index == correct {
                password.encode_utf16().collect()
            } else {
                format!("wrong-password-{index:08}")
                    .encode_utf16()
                    .collect()
            }
        })
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(pool_threads)
        .build()
        .unwrap();
    pool.broadcast(|_| ());
    for run in 0..runs {
        let next = AtomicUsize::new(0);
        let best = AtomicUsize::new(count);
        let cpu_before = cpu_seconds();
        let started = Instant::now();
        let results: Vec<_> = pool.install(|| {
            (0..workers)
                .into_par_iter()
                .map(|_| {
                    let mut workspace = Workspace::with_threads(threads);
                    let mut evaluated = 0;
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= best.load(Ordering::Relaxed) || index >= count {
                            break;
                        }
                        if probe.matches(&candidates[index], &mut workspace).unwrap() {
                            best.fetch_min(index, Ordering::Relaxed);
                        }
                        evaluated += 1;
                    }
                    let phases = workspace.study_seconds;
                    let arena_bytes = workspace.memory.len() * std::mem::size_of::<Block>();
                    let drop_start = Instant::now();
                    drop(workspace);
                    (
                        evaluated,
                        phases,
                        arena_bytes,
                        drop_start.elapsed().as_secs_f64(),
                    )
                })
                .collect()
        });
        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()
            .zip(cpu_before)
            .map(|(end, start)| format!("{:.9}", end - start))
            .unwrap_or_else(|| "null".into());
        let mut phases = [0.0f64; 5];
        let mut evaluated = 0;
        let mut arena_bytes = 0;
        let mut drop_seconds = 0.0;
        for (tested, times, bytes, drop_time) in results {
            evaluated += tested;
            arena_bytes += bytes;
            drop_seconds += drop_time;
            for (sum, time) in phases.iter_mut().zip(times) {
                *sum += time;
            }
        }
        let found = best.load(Ordering::Relaxed);
        assert_eq!(
            found,
            correct.min(count),
            "candidate result differs from requested fixture password"
        );
        println!(concat!("ENC_STUDY_JSON {{\"run\":{},\"candidates\":{},\"workers\":{},\"threads_per_candidate\":{},",
            "\"pool_threads\":{},\"argon_lanes\":{},\"memory_blocks\":{},\"backend\":\"{:?}\",",
            "\"wall_seconds\":{:.9},\"cpu_seconds\":{},\"evaluated\":{},\"matched_index\":{},\"workspace_bytes_each\":{},",
            "\"allocated_workspace_bytes_sum\":{},\"phase_wall_seconds_sum\":{{\"master\":{:.9},",
            "\"arena_init\":{:.9},\"argon2\":{:.9},\"post_hkdf\":{:.9},\"quick_cipher\":{:.9},\"drop\":{:.9}}},",
            "\"phase_sums_overlap\":true,\"argon2_scope\":\"worker_wall_sum\",\"wall_includes_workspace_drop\":true,\"memory_after_drop\":{}}}"),
            run, count, workers, threads, pool_threads, parameters.lanes(), parameters.memory_blocks(),
            argon2_rust::__internal::backend(), elapsed, cpu, evaluated,
            if found == count { -1 } else { found as i64 }, probe.workspace_bytes(), arena_bytes,
            phases[0], phases[1], phases[2], phases[3], phases[4], drop_seconds, memory_json());
    }
}
