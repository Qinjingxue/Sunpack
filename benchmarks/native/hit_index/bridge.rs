// Appended inside an otherwise unchanged copy of production hit_storage.rs.
// No extraction/format-analysis logic is implemented by this adapter.
use std::time::Instant;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProbeHit {
    pub offset: u64,
    pub pattern: u8,
    pub padding: [u8; 3],
    pub owner: u32,
}
#[repr(C)]
#[derive(Default)]
pub struct ProbeStats {
    pub bytes: u64,
    pub capacity: u64,
    pub heap: u64,
    pub mapped: u64,
    pub prepare_ns: u64,
    pub collect_ns: u64,
    pub finish_ns: u64,
}
struct Probe {
    store: HitStorage,
    stats: ProbeStats,
}
fn blob_info(blob: &Blob) -> (u64, u64, u64, u64) {
    match blob {
        Blob::Memory(v) => (v.len() as u64, v.capacity() as u64, v.capacity() as u64, 0),
        Blob::Mapped(m) => (m.len() as u64, m.len() as u64, 0, m.len() as u64),
    }
}
fn probe_stats(store: &HitStorage) -> ProbeStats {
    let mut s = ProbeStats::default();
    for blob in [&store.data, &store.dirs[0], &store.dirs[1]] {
        let (a, b, c, d) = blob_info(blob);
        s.bytes += a;
        s.capacity += b;
        s.heap += c;
        s.mapped += d;
    }
    s
}
fn codec_probe(input: &[ProbeHit]) -> io::Result<Probe> {
    let mut data = Vec::new();
    let mut dir = Vec::new();
    let mut end = 0u64;
    let mut at = 0;
    while at < input.len() {
        let base = input[at].offset;
        let mut next = at + 1;
        while next < input.len() && input[next].offset - base < (1 << 28) {
            next += 1;
        }
        let hits = input[at..next]
            .iter()
            .map(|h| PackedHit::new((h.offset - base) as u32, h.pattern))
            .collect();
        if let Some(e) = encode(hits) {
            let payload = data.len().next_multiple_of(64);
            data.resize(payload, 0);
            end += e.count as u64;
            let seg = Segment {
                base,
                end,
                count: e.count as u64,
                payload: payload as u64,
                last: base + e.last as u64,
                control: e.control as u64,
            };
            if data.is_empty() {
                data = e.data;
            } else {
                data.extend_from_slice(&e.data);
            }
            dir.extend_from_slice(&seg.bytes());
        }
        at = next;
    }
    let store = HitStorage {
        data: Blob::Memory(data),
        dirs: [Blob::Memory(dir), Blob::Memory(Vec::new())],
    };
    let stats = probe_stats(&store);
    Ok(Probe { store, stats })
}
fn builder_probe(
    input: &[ProbeHit],
    size: u64,
    chunk: usize,
    window: usize,
    order: u32,
) -> io::Result<Probe> {
    // Input is canonical replay data grouped by matching-job owner. Its full
    // source/oracle allocation is excluded from all algorithms' internal timing.
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < input.len() {
        let owner = input[at].owner;
        let mut end = at + 1;
        while end < input.len() && input[end].owner == owner {
            end += 1;
        }
        ranges.push((owner, at, end));
        at = end;
    }
    if order == 1 {
        ranges.reverse();
    }
    let mut builder = Builder::new(size, chunk, window)?;
    let mut stats = ProbeStats::default();
    for group in ranges.chunks(window.max(1)) {
        let start = Instant::now();
        let mut prepared: Vec<_> = group
            .par_iter()
            .map(|&(owner, a, b)| {
                let start = owner as u64 * chunk as u64;
                let base = start.saturating_sub(HIT_LOOKBEHIND + 11);
                let hits = input[a..b]
                    .iter()
                    .map(|h| PackedHit::new((h.offset - base) as u32, h.pattern))
                    .collect();
                prepare(
                    HitBuffer { base, hits },
                    start,
                    (start + chunk as u64).min(size),
                    11,
                    start + chunk as u64 >= size,
                )
            })
            .collect();
        stats.prepare_ns += start.elapsed().as_nanos() as u64;
        if order == 2 {
            prepared.reverse();
        }
        let start = Instant::now();
        for batch in prepared {
            builder.push(batch)?;
        }
        stats.collect_ns += start.elapsed().as_nanos() as u64;
    }
    let start = Instant::now();
    let store = builder.finish()?;
    stats.finish_ns = start.elapsed().as_nanos() as u64;
    let mut measured = probe_stats(&store);
    measured.prepare_ns = stats.prepare_ns;
    measured.collect_ns = stats.collect_ns;
    measured.finish_ns = stats.finish_ns;
    Ok(Probe {
        store,
        stats: measured,
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_build(
    p: *const ProbeHit,
    n: usize,
    mode: u32,
    size: u64,
    chunk: usize,
    window: usize,
    order: u32,
) -> *mut std::ffi::c_void {
    let input = if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    };
    let result = std::panic::catch_unwind(|| {
        if mode == 0 {
            codec_probe(input)
        } else {
            builder_probe(input, size, chunk, window, order)
        }
    });
    match result {
        Ok(Ok(probe)) => Box::into_raw(Box::new(probe)).cast(),
        Ok(Err(e)) => {
            eprintln!("SunPack index probe: {e}");
            std::ptr::null_mut()
        }
        Err(_) => std::ptr::null_mut(),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_stats(p: *mut std::ffi::c_void, out: *mut ProbeStats) {
    let x = &*p.cast::<Probe>();
    std::ptr::copy_nonoverlapping(&x.stats, out, 1);
}
fn joined_dump(store: &HitStorage) -> Vec<RawHit> {
    let a: Vec<_> = store.view(0).iter().collect();
    let b: Vec<_> = store.view(1).iter().collect();
    for items in [&a, &b] {
        assert!(
            items
                .windows(2)
                .all(|p| (p[0].offset(), p[0].hit_name()) <= (p[1].offset(), p[1].hit_name())),
            "index stream order"
        );
    }
    let (mut ai, mut bi) = (a.into_iter().peekable(), b.into_iter().peekable());
    let mut out = Vec::new();
    while ai.peek().is_some() || bi.peek().is_some() {
        let take_a = match (ai.peek(), bi.peek()) {
            (Some(x), Some(y)) => (x.offset(), x.hit_name()) <= (y.offset(), y.hit_name()),
            (Some(_), None) => true,
            _ => false,
        };
        out.push(if take_a {
            ai.next().unwrap()
        } else {
            bi.next().unwrap()
        });
    }
    out
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_dump(p: *mut std::ffi::c_void, out: *mut ProbeHit) -> usize {
    let x = &*p.cast::<Probe>();
    let hits = joined_dump(&x.store);
    for (i, h) in hits.iter().enumerate() {
        out.add(i).write(ProbeHit {
            offset: h.offset(),
            pattern: h.pattern,
            padding: [0; 3],
            owner: 0,
        });
    }
    hits.len()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_seq(p: *mut std::ffi::c_void, tags: u16) -> u64 {
    let x = &*p.cast::<Probe>();
    x.store
        .view(0)
        .iter_mask(tags)
        .chain(x.store.view(1).iter_mask(tags))
        .fold(0u64, |a, h| {
            a.wrapping_add(h.offset().wrapping_mul(17) + h.pattern as u64)
        })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_get(
    p: *mut std::ffi::c_void,
    ranks: *const u64,
    n: usize,
    out: *mut ProbeHit,
) {
    let x = &*p.cast::<Probe>();
    let view = x.store.view(0);
    for (i, &rank) in (if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ranks, n)
    })
    .iter()
    .enumerate()
    {
        let h = view.get(rank as usize).expect("valid rank");
        out.add(i).write(ProbeHit {
            offset: h.offset(),
            pattern: h.pattern,
            padding: [0; 3],
            owner: 0,
        });
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_lower(
    p: *mut std::ffi::c_void,
    targets: *const u64,
    n: usize,
    out: *mut u64,
) {
    let view = (&*p.cast::<Probe>()).store.view(0);
    for (i, &t) in (if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(targets, n)
    })
    .iter()
    .enumerate()
    {
        out.add(i).write(view.lower_bound(t) as u64);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_seek(
    p: *mut std::ffi::c_void,
    targets: *const u64,
    n: usize,
    tags: u16,
) -> u64 {
    let x = &*p.cast::<Probe>();
    let mut c = x.store.view(0).iter_mask(tags);
    let mut sum = 0u64;
    for &t in if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(targets, n)
    } {
        c.seek_ge(t);
        if let Some(h) = c.next() {
            sum = sum.wrapping_add(h.offset().wrapping_mul(17) + h.pattern as u64);
        }
    }
    sum
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_free(p: *mut std::ffi::c_void) {
    drop(Box::from_raw(p.cast::<Probe>()));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_mask_dump(
    p: *mut std::ffi::c_void,
    tags: u16,
    out: *mut ProbeHit,
) -> usize {
    let x = &*p.cast::<Probe>();
    let mut n = 0;
    for h in x
        .store
        .view(0)
        .iter_mask(tags)
        .chain(x.store.view(1).iter_mask(tags))
    {
        out.add(n).write(ProbeHit {
            offset: h.offset(),
            pattern: h.pattern,
            padding: [0; 3],
            owner: 0,
        });
        n += 1;
    }
    n
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sp_seek_dump(
    p: *mut std::ffi::c_void,
    targets: *const u64,
    n: usize,
    tags: u16,
    out: *mut ProbeHit,
) -> usize {
    let x = &*p.cast::<Probe>();
    let mut c = x.store.view(0).iter_mask(tags);
    let mut written = 0;
    for &t in if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(targets, n)
    } {
        c.seek_ge(t);
        if let Some(h) = c.next() {
            out.add(written).write(ProbeHit {
                offset: h.offset(),
                pattern: h.pattern,
                padding: [0; 3],
                owner: 0,
            });
            written += 1;
        }
    }
    written
}
#[unsafe(no_mangle)]
pub extern "C" fn sp_allocator(reset: bool) -> u64 {
    if reset {
        crate::PEAK.store(
            crate::LIVE.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    crate::PEAK.load(std::sync::atomic::Ordering::Relaxed) as u64
}
