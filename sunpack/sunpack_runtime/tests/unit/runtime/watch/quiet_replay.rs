//! Offline input adapter for the real Watch capture and admission methods.
use super::*;
use std::cell::RefCell;
use std::io::{BufRead, Write};

#[derive(Deserialize)]
struct Mutation {
    at: f64,
    size: u64,
    mtime: f64,
    usn: i64,
    operation: String,
    change_reasons: u32,
}

#[derive(Deserialize)]
struct File {
    visible_at: f64,
    mutations: Vec<Mutation>,
    blocked: Vec<(f64, f64)>,
}

#[derive(Deserialize)]
struct Replay {
    horizon: f64,
    files: Vec<File>,
    observations: Vec<(f64, usize, bool)>,
    observation_first: bool,
}

#[derive(Default, serde::Serialize)]
struct Metrics {
    metadata_probes: usize,
    readiness_probes: usize,
    scheduled_deadlines: usize,
    peak_live_estimators: usize,
}

struct VirtualFiles {
    epoch: Instant,
    at: Instant,
    files: Vec<File>,
    indices: HashMap<String, usize>,
    identities: Vec<Vec<usize>>,
    metrics: Metrics,
}

thread_local! {
    static VIRTUAL: RefCell<Option<VirtualFiles>> = const { RefCell::new(None) };
}

pub(super) fn now() -> Option<Instant> {
    VIRTUAL.with_borrow(|state| state.as_ref().map(|state| state.at))
}

pub(super) fn probe(
    path: &Path,
    since: Option<i64>,
) -> Option<(Option<WatchCandidateRow>, Instant, f64)> {
    snapshot(path, since, true)
}

pub(super) fn relative_time() -> Option<f64> {
    VIRTUAL.with_borrow(|state| state.as_ref().map(|state| state.at.duration_since(state.epoch).as_secs_f64()))
}

pub(super) fn sealed(path: &Path, since: Option<i64>) -> Option<WatchCandidateRow> {
    snapshot(path, since, false)?.0
}

fn snapshot(path: &Path, since: Option<i64>, loose: bool) -> Option<(Option<WatchCandidateRow>, Instant, f64)> {
    VIRTUAL.with_borrow_mut(|state| {
        let state = state.as_mut()?;
        let path = path.to_str().unwrap();
        let index = state.indices[&watch_path_key(path)];
        state.metrics.metadata_probes += usize::from(loose);
        let at = state.at.duration_since(state.epoch).as_secs_f64();
        let file = &state.files[index];
        let end = file
            .mutations
            .partition_point(|item| quiet::after(state.epoch, item.at) <= state.at);
        let candidate = if quiet::after(state.epoch, file.visible_at) <= state.at && end > 0 {
            let current = &file.mutations[end - 1];
            let change_reasons = since.map(|usn| {
                let mut reasons = sunpack_usn_core::ChangeReasons {
                    all: 0,
                    without_close: 0,
                };
                let start = file.mutations[..end].partition_point(|item| item.usn <= usn);
                for item in &file.mutations[start..end] {
                    reasons.all |= item.change_reasons;
                    if item.change_reasons & 0x8000_0000 == 0 {
                        reasons.without_close |= item.change_reasons;
                    }
                }
                reasons
            });
            Some(WatchCandidateRow {
                path: path.to_owned(),
                size: current.size,
                mtime: current.mtime,
                observation: filesystem::WatchFileObservation {
                    file_id: format!("{index}/{}", state.identities[index][end - 1]),
                    change_usn: current.usn,
                    change_reasons,
                },
            })
        } else {
            None
        };
        Some((candidate, state.at, at))
    })
}

pub(super) fn readable(path: &str) -> Option<bool> {
    VIRTUAL.with_borrow_mut(|state| {
        let state = state.as_mut()?;
        state.metrics.readiness_probes += 1;
        let id = watch_path_key(path);
        let file = &state.files[state.indices[&id]];
        Some(!file.blocked.iter().any(|&(start, end)| {
            quiet::after(state.epoch, start) <= state.at
                && state.at < quiet::after(state.epoch, end)
        }))
    })
}

fn thread_cpu_ns() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let result = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    assert_ne!(result, 0, "{}", io::Error::last_os_error());
    let ticks =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    (ticks(kernel) + ticks(user)) * 100
}

fn replay(base: &Path, input: Replay) -> Value {
    let mut scheduler = admission_tests::audit_scheduler(base, base.join("unused-worker.exe"));
    let (root, (_, scope)) = scheduler.roots.first_key_value().unwrap();
    let root = root.clone();
    let paths: Vec<_> = (0..input.files.len())
        .map(|index| base.join("input").join(format!("file-{index}.opaque")))
        .collect();
    // Real catalog rows retain learned cadence across tracker retirement.
    scheduler
        .options
        .as_ref()
        .unwrap()
        .catalog_update(&scheduler.catalog, scope, None)
        .unwrap();
    let indices = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (key(path), index))
        .collect();
    let identities = input
        .files
        .iter()
        .map(|file| {
            file.mutations
                .iter()
                .scan(0, |identity, item| {
                    *identity += usize::from(item.operation == "replace");
                    Some(*identity)
                })
                .collect()
        })
        .collect();
    let epoch = Instant::now();
    VIRTUAL.with_borrow_mut(|state| {
        *state = Some(VirtualFiles {
            epoch,
            at: epoch,
            files: input.files,
            indices,
            identities,
            metrics: Metrics::default(),
        })
    });
    let horizon = quiet::after(epoch, input.horizon);
    let mut proposals = vec![Vec::<f64>::new(); paths.len()];
    let mut events = input.observations.into_iter().peekable();
    let cpu_start = thread_cpu_ns();
    let started = Instant::now();
    loop {
        let delivery = events.peek().map(|event| quiet::after(epoch, event.0));
        let deadline = scheduler.due.first_key_value().map(|((at, _), _)| *at);
        let Some(at) = delivery
            .into_iter()
            .chain(deadline)
            .min()
            .filter(|at| *at <= horizon)
        else {
            break;
        };
        VIRTUAL.with_borrow_mut(|state| {
            let state = state.as_mut().unwrap();
            state.at = at;
        });
        if delivery == Some(at) && (deadline != Some(at) || input.observation_first) {
            let (_, index, directory) = events.next().unwrap();
            let path = &paths[index];
            let path_text = path.to_str().unwrap();
            let mut activity = None;
            let mut captured = None;
            if directory {
                let id = key(path);
                let tracker = scheduler.hub.activities.bind(&id, || {
                    scheduler
                        .catalog
                        .observation(path_text)
                        .as_ref()
                        .map_or_else(quiet::Activity::default, quiet::Activity::saved)
                });
                captured = tracker.capture(path, &scheduler.hub.claims, &id).unwrap();
                activity = Some(tracker);
            }
            scheduler
                .observe_candidate_with_event(
                    &root,
                    path_text.to_owned(),
                    CandidateAdmission::Observe,
                    None,
                    None,
                    activity,
                    None,
                    captured,
                )
                .unwrap();
        } else {
            VIRTUAL
                .with_borrow_mut(|state| state.as_mut().unwrap().metrics.scheduled_deadlines += 1);
            for (id, pending) in scheduler.prepare_ready_blocking(at, usize::MAX).unwrap() {
                let index = VIRTUAL.with_borrow(|state| state.as_ref().unwrap().indices[&id]);
                proposals[index].push(at.duration_since(epoch).as_secs_f64());
                scheduler.retire_admitted_observation(&id, &pending);
                scheduler.unpublished.remove(&id);
            }
        }
        VIRTUAL.with_borrow_mut(|state| {
            let metrics = &mut state.as_mut().unwrap().metrics;
            metrics.peak_live_estimators =
                metrics.peak_live_estimators.max(scheduler.pending.len());
        });
    }
    let elapsed = started.elapsed();
    let cpu_ns = thread_cpu_ns() - cpu_start;
    let pending_deadlines: Vec<_> = paths
        .iter()
        .map(|path| {
            scheduler
                .pending
                .get(&key(path))
                .map(|pending| pending.due.duration_since(epoch).as_secs_f64())
        })
        .collect();
    let state = VIRTUAL.with_borrow_mut(|state| state.take().unwrap());
    json!({"proposals": proposals, "pending_deadlines": pending_deadlines, "metrics": state.metrics,
        "replay_elapsed_ns": elapsed.as_nanos(), "replay_cpu_ns": cpu_ns})
}

#[test]
#[ignore = "driven by python -m benchmarks watch quiet-corpus"]
fn replay_corpus() {
    let base = PathBuf::from(std::env::var_os("SUNPACK_QUIET_REPLAY_WORK").unwrap());
    fs::create_dir_all(base.join("input")).unwrap();
    for index in 0..64 {
        fs::File::create(base.join("input").join(format!("file-{index}.opaque"))).unwrap();
    }
    for line in io::stdin().lock().lines() {
        let input = serde_json::from_str(&line.unwrap()).unwrap();
        let output = replay(&base, input);
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "QUIET_REPLAY {output}").unwrap();
        stdout.flush().unwrap();
    }
}
