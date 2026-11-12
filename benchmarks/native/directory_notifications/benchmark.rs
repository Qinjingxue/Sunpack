//! Native ReadDirectoryChangesW buffer A/B workload; no Sunpack service involved.
//! Compile: rustc -O --edition=2021 benchmark.rs -o <output.exe>
use std::{
    collections::HashSet,
    ffi::c_void,
    fs, io,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    ptr::null_mut,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
type H = *mut c_void;
#[repr(C)]
#[derive(Default)]
struct Ov {
    internal: usize,
    high: usize,
    offset: u32,
    offset_high: u32,
    event: H,
}
#[repr(C)]
#[derive(Default)]
struct Ft {
    lo: u32,
    hi: u32,
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(p: *const u16, a: u32, s: u32, x: H, d: u32, f: u32, t: H) -> H;
    fn CreateEventW(x: H, m: i32, i: i32, n: *const u16) -> H;
    fn SetEvent(h: H) -> i32;
    fn CloseHandle(h: H) -> i32;
    fn ReadDirectoryChangesW(
        h: H,
        b: H,
        n: u32,
        r: i32,
        f: u32,
        z: *mut u32,
        o: *mut Ov,
        c: H,
    ) -> i32;
    fn GetOverlappedResult(h: H, o: *mut Ov, n: *mut u32, w: i32) -> i32;
    fn CancelIoEx(h: H, o: *mut Ov) -> i32;
    fn WaitForMultipleObjects(n: u32, h: *const H, a: i32, t: u32) -> u32;
    fn GetCurrentProcess() -> H;
    fn GetCurrentThread() -> H;
    fn GetThreadTimes(h: H, c: *mut Ft, e: *mut Ft, k: *mut Ft, u: *mut Ft) -> i32;
    fn GetProcessTimes(h: H, c: *mut Ft, e: *mut Ft, k: *mut Ft, u: *mut Ft) -> i32;
}
#[repr(C)]
#[derive(Default)]
struct Mem {
    cb: u32,
    faults: u32,
    peak_ws: usize,
    ws: usize,
    peak_paged: usize,
    paged: usize,
    peak_nonpaged: usize,
    nonpaged: usize,
    pagefile: usize,
    peak_pagefile: usize,
    private: usize,
}
#[link(name = "psapi")]
extern "system" {
    fn GetProcessMemoryInfo(h: H, m: *mut Mem, n: u32) -> i32;
}
fn private_bytes() -> usize {
    let mut m = Mem::default();
    m.cb = std::mem::size_of::<Mem>() as u32;
    unsafe {
        assert_ne!(GetProcessMemoryInfo(GetCurrentProcess(), &mut m, m.cb), 0);
    }
    m.private
}
fn cpu_ms() -> f64 {
    unsafe {
        let (mut c, mut e, mut k, mut u) =
            (Ft::default(), Ft::default(), Ft::default(), Ft::default());
        assert_ne!(
            GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u),
            0
        );
        (((k.hi as u64) << 32 | k.lo as u64) + ((u.hi as u64) << 32 | u.lo as u64)) as f64 / 10000.0
    }
}
fn arm(h: H, buf: &mut [u32], ov: &mut Ov) {
    unsafe {
        let ok = ReadDirectoryChangesW(
            h,
            buf.as_mut_ptr().cast(),
            (buf.len() * 4) as u32,
            1,
            0x17f,
            null_mut(),
            ov,
            null_mut(),
        );
        if ok == 0 {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(997));
        }
    }
}
fn thread_cpu_ms() -> f64 {
    unsafe {
        let (mut c, mut e, mut k, mut u) =
            (Ft::default(), Ft::default(), Ft::default(), Ft::default());
        assert_ne!(
            GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u),
            0
        );
        (((k.hi as u64) << 32 | k.lo as u64) + ((u.hi as u64) << 32 | u.lo as u64)) as f64 / 10000.0
    }
}
#[derive(Default)]
struct Stats {
    observer_cpu_ms: f64,
    calls: usize,
    overflow: usize,
    records: usize,
    recovered: usize,
    recovery_ms: f64,
    latencies: Vec<f64>,
    seen: HashSet<usize>,
}
fn parse(buf: &[u32], len: usize) -> Vec<usize> {
    let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len) };
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        let next = u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(b[p + 8..p + 12].try_into().unwrap()) as usize;
        let w: Vec<u16> = b[p + 12..p + 12 + n]
            .chunks_exact(2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect();
        let s = String::from_utf16_lossy(&w);
        if let Some(i) = s
            .strip_prefix("arrival_")
            .and_then(|x| x.get(..8))
            .and_then(|x| x.parse().ok())
        {
            out.push(i);
        }
        if next == 0 {
            break;
        }
        p += next;
    }
    out
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 6, "root bytes count callback_us pace_us");
    let root = PathBuf::from(&a[1]);
    let bytes: usize = a[2].parse().unwrap();
    let count: usize = a[3].parse().unwrap();
    let delay: u64 = a[4].parse().unwrap();
    let pace: u64 = a[5].parse().unwrap();
    assert!(!root.exists(), "use a fresh benchmark directory");
    fs::create_dir_all(&root).unwrap();
    let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
    wide.push(0);
    let h = unsafe { CreateFileW(wide.as_ptr(), 1, 7, null_mut(), 3, 0x42000000, null_mut()) };
    assert_ne!(h as isize, -1);
    let stop = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
    assert!(!stop.is_null());
    let times = Arc::new(Mutex::new(vec![None; count]));
    let tt = times.clone();
    let rr = root.clone();
    let (ready, rx) = mpsc::channel();
    let (done, drx) = mpsc::channel();
    let initial_private = private_bytes();
    let hs = h as usize;
    let ss = stop as usize;
    let start = Instant::now();
    let cpu = cpu_ms();
    let watcher = thread::spawn(move || {
        let observer_cpu = thread_cpu_ms();
        let h = hs as H;
        let stop = ss as H;
        let ev = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        let mut ov = Ov {
            event: ev,
            ..Ov::default()
        };
        let mut buf = vec![0u32; bytes / 4];
        let mut stats = Stats::default();
        let mut announced = false;
        arm(h, &mut buf, &mut ov);
        ready.send(()).unwrap();
        loop {
            let handles = [stop, ev];
            let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) };
            if wait == 0 {
                unsafe {
                    CancelIoEx(h, &mut ov);
                    let mut n = 0;
                    GetOverlappedResult(h, &mut ov, &mut n, 1);
                }
                break;
            }
            assert_eq!(wait, 1);
            let mut n = 0;
            let ok = unsafe { GetOverlappedResult(h, &mut ov, &mut n, 0) };
            if ok == 0 {
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1022));
                n = 0;
            }
            stats.calls += 1;
            let ids = if n == 0 {
                stats.overflow += 1;
                Vec::new()
            } else {
                parse(&buf, n as usize)
            };
            stats.records += ids.len();
            arm(h, &mut buf, &mut ov);
            let ids = if n == 0 {
                let t = Instant::now();
                let v: Vec<usize> = fs::read_dir(&rr)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .filter_map(|s| {
                        s.strip_prefix("arrival_")
                            .and_then(|x| x.get(..8))
                            .and_then(|x| x.parse().ok())
                    })
                    .collect();
                stats.recovery_ms += t.elapsed().as_secs_f64() * 1000.;
                stats.recovered += v.len();
                v
            } else {
                ids
            };
            let now = Instant::now();
            let ts = tt.lock().unwrap();
            for i in ids {
                if stats.seen.insert(i) {
                    if let Some(t) = ts[i] {
                        stats
                            .latencies
                            .push(now.duration_since(t).as_secs_f64() * 1000.);
                    }
                }
            }
            drop(ts);
            if stats.seen.len() == count && !announced {
                let _ = done.send(());
                announced = true;
            }
            if delay > 0 {
                thread::sleep(Duration::from_micros(delay));
            }
        }
        unsafe {
            CloseHandle(ev);
            CloseHandle(h);
        }
        stats.observer_cpu_ms = thread_cpu_ms() - observer_cpu;
        stats
    });
    rx.recv().unwrap();
    let armed_private_delta = private_bytes().saturating_sub(initial_private);
    let produce = Instant::now();
    if count == 0 {
        thread::sleep(Duration::from_secs(1));
    } else {
        for i in 0..count {
            times.lock().unwrap()[i] = Some(Instant::now());
            fs::write(
                root.join(format!("arrival_{i:08}_{}", "x".repeat(100))),
                [0u8],
            )
            .unwrap();
            if pace > 0 {
                thread::sleep(Duration::from_micros(pace));
            }
        }
    }
    let producer_ms = produce.elapsed().as_secs_f64() * 1000.;
    let tail = Instant::now();
    let complete = if count == 0 {
        true
    } else {
        drx.recv_timeout(Duration::from_secs(30)).is_ok()
    };
    unsafe {
        SetEvent(stop);
    }
    let mut s = watcher.join().unwrap();
    unsafe {
        CloseHandle(stop);
    }
    let wall_ms = start.elapsed().as_secs_f64() * 1000.;
    let cpu = cpu_ms() - cpu;
    s.latencies.sort_by(f64::total_cmp);
    let q = |p: f64| {
        s.latencies
            .get(((s.latencies.len().saturating_sub(1)) as f64 * p) as usize)
            .copied()
            .unwrap_or(0.)
    };
    println!("{{\"bytes\":{bytes},\"files\":{count},\"callback_us\":{delay},\"pace_us\":{pace},\"complete\":{complete},\"armed_private_delta\":{armed_private_delta},\"seen\":{},\"calls\":{},\"overflow\":{},\"records\":{},\"recovery_entries\":{},\"recovery_ms\":{:.3},\"producer_ms\":{producer_ms:.3},\"wall_ms\":{wall_ms:.3},\"tail_ms\":{:.3},\"cpu_ms\":{cpu:.3},\"observer_cpu_ms\":{:.3},\"p50_ms\":{:.3},\"p95_ms\":{:.3},\"p99_ms\":{:.3}}}",s.seen.len(),s.calls,s.overflow,s.records,s.recovered,s.recovery_ms,tail.elapsed().as_secs_f64()*1000.,s.observer_cpu_ms,q(0.5),q(0.95),q(0.99));
    assert!(complete,"benchmark did not converge within operator safety budget; preserve directory for diagnosis");
    // This freshly-created, unique root is the only path this benchmark removes.
    fs::remove_dir_all(root).unwrap();
}
