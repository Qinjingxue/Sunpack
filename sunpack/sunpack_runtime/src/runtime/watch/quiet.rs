use crate::postprocess::WatchCandidateRow;
use crate::scan::catalog::NativeWatchObservation;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;


// The observer and scheduler share one bounded tracker. Notifications may be
// coalesced for wakeup/catalog work, never for cadence learning.
#[derive(Default)]
pub(super) struct Activities(std::sync::Mutex<std::collections::HashMap<Arc<str>, std::sync::Weak<ActivityInner>>>);

#[derive(Clone)]
pub(super) struct Activity(std::sync::Arc<ActivityInner>);

pub(super) struct Observation {
    pub(super) candidate: WatchCandidateRow,
    pub(super) now: Instant,
    pub(super) at: f64,
    pub(super) since_usn: Option<i64>,
}

struct ActivityInner {
    state: std::sync::Mutex<ActivityState>,
    registration: std::sync::OnceLock<(Arc<str>, std::sync::Weak<Activities>)>,
}

#[derive(Default)]
struct ActivityState {
    quiet: Quiet,
    baseline: Option<(u64, f64, String, i64)>,
    due: Option<Instant>,
    observed: Option<Instant>,
}

impl Drop for ActivityInner {
    fn drop(&mut self) {
        if let Some((key, registry)) = self.registration.get() {
            if let Some(registry) = registry.upgrade() {
                let mut entries = registry.0.lock().unwrap();
                if entries.get(key).is_some_and(|value| std::ptr::eq(value.as_ptr(), self)) {
                    entries.remove(key);
                    crate::collections::trim_map(&mut entries);
                }
            }
        }
    }
}

impl Activities {
    pub(super) fn bind(self: &Arc<Self>, key: &str, make: impl FnOnce() -> Activity) -> Activity {
        let mut entries = self.0.lock().unwrap();
        if let Some(inner) = entries.get(key).and_then(std::sync::Weak::upgrade) {
            return Activity(inner);
        }
        let activity = make();
        let key = Arc::<str>::from(key);
        activity.0.registration.get_or_init(|| (Arc::clone(&key), Arc::downgrade(self)));
        entries.insert(key, std::sync::Arc::downgrade(&activity.0));
        activity
    }
}

impl Default for Activity {
    fn default() -> Self { Self::from_state(ActivityState::default()) }
}

impl Activity {
    fn from_state(state: ActivityState) -> Self {
        Self(std::sync::Arc::new(ActivityInner {
            state: std::sync::Mutex::new(state), registration: std::sync::OnceLock::new(),
        }))
    }

    pub(super) fn saved(value: &NativeWatchObservation) -> Self {
        Self::from_state(ActivityState {
            quiet: Quiet::saved(value),
            baseline: Some((value.size, value.mtime, value.file_id(), value.change_usn)),
            due: None, observed: None,
        })
    }

    // Probe and timestamp on the collection thread, before WAL/catalog work.
    // Serializing this small per-path operation also prevents an older probe
    // from replacing a newer sample collected by the scheduler.
    pub(super) fn capture(&self, path: &std::path::Path, claims: &std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<str>>>, key: &str) -> std::io::Result<Option<Observation>> {
        let mut state = self.0.state.lock().unwrap();
        let since_usn = state.baseline.as_ref().map(|value| value.3);
        let real_probe = || -> std::io::Result<_> {
            Ok(crate::postprocess::watch_candidate_for_path(path, since_usn)?
                .map(|candidate| (candidate, Instant::now(), super::windows::monotonic_seconds())))
        };
        #[cfg(not(test))]
        let snapshot = real_probe()?;
        #[cfg(test)]
        let snapshot = match super::quiet_replay::probe(path, since_usn) {
            Some((candidate, now, at)) => candidate.map(|candidate| (candidate, now, at)),
            None => real_probe()?,
        };
        if let Some((candidate, now, at)) = snapshot {
            let claims = claims.lock().unwrap();
            if claims.contains_key(key) { return Ok(None); }
            state.record(&candidate, now, at, false, None);
            return Ok(Some(Observation { candidate, now, at, since_usn }));
        }
        Ok(None)
    }

    pub(super) fn probe(&self, path: &std::path::Path, baseline: Option<i64>)
        -> std::io::Result<(Option<WatchCandidateRow>, Instant, f64)> {
        let _state = self.0.state.lock().unwrap();
        probe_candidate(path, baseline)
    }

    pub(super) fn content_deadline(&self, candidate: &WatchCandidateRow, now: Instant,
        at: f64, reset: bool, retry_unchanged: bool, forced_content_change: Option<bool>) -> Instant {
        let mut state = self.0.state.lock().unwrap();
        if retry_unchanged {
            if state.observed.is_some_and(|previous| previous > now) {
                return state.due.unwrap_or(now);
            }
            state.due = Some(now);
            return now;
        }
        // A native capture may already have timed this generation.
        state.record(candidate, now, at, reset, forced_content_change);
        state.due.unwrap_or(now)
    }

    pub(super) fn observation(&self, candidate: &WatchCandidateRow) -> (bool, Option<Instant>) {
        let state = self.0.state.lock().unwrap();
        (state.baseline.as_ref().is_some_and(|(size, mtime, id, usn)|
            *size == candidate.size && *mtime == candidate.mtime && *id == candidate.observation.file_id
                && *usn == candidate.observation.change_usn), state.due)
    }

    // Linearize admission with native captures, after the readability check.
    // Reuse the probe timestamp: even a replacement with identical metadata
    // must not admit observations published after that probe.
    pub(super) fn admit(&self, probed: Instant, now: Instant) -> Result<(), Instant> {
        let state = self.0.state.lock().unwrap();
        if state.observed.is_some_and(|observed| observed > probed) {
            Err(state.due.unwrap_or(now).max(now))
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(super) fn sample_count(&self) -> usize {
        self.0.state.lock().unwrap().quiet.samples.as_ref().map_or(0, |samples| samples.len())
    }

    #[cfg(test)]
    pub(super) fn observed_size(&self) -> Option<u64> {
        self.0.state.lock().unwrap().baseline.as_ref().map(|baseline| baseline.0)
    }
    pub(super) fn deadline(&self) -> Option<Instant> { self.0.state.lock().unwrap().due }
    pub(super) fn summary(&self) -> (f64, Option<f64>, f64, f64) {
        let state = self.0.state.lock().unwrap();
        (state.quiet.seconds, state.quiet.last, state.quiet.cadence, state.quiet.tentative)
    }
    pub(super) fn boundary_deadline(&self, now: Instant, confirmation: f64) -> Instant {
        self.0.state.lock().unwrap().quiet.boundary_deadline(now, confirmation)
    }
    pub(super) fn accelerate(&self, observed: Instant, due: Instant) {
        let mut state = self.0.state.lock().unwrap();
        if state.observed.is_none_or(|current| current <= observed) { state.due = Some(due); }
    }
    pub(super) fn metadata(&self, candidate: &WatchCandidateRow, now: Instant) {
        let mut state = self.0.state.lock().unwrap();
        if state.observed.is_some_and(|previous| previous > now) { return; }
        state.observed = Some(now);
        if is_boundary(candidate) { state.quiet.end_phase(); }
        state.baseline = Some((candidate.size, candidate.mtime,
            candidate.observation.file_id.clone(), candidate.observation.change_usn));
    }
    pub(super) fn boundary_observation(&self, candidate: &WatchCandidateRow,
        now: Instant, at: f64, confirmation: f64) {
        let mut state = self.0.state.lock().unwrap();
        if state.observed.is_some_and(|previous| previous > now) { return; }
        let reset = state.baseline.as_ref().is_some_and(|(size, _, id, _)|
            *size > candidate.size || *id != candidate.observation.file_id);
        state.quiet.observe(at, is_boundary(candidate), reset, false);
        state.observed = Some(now);
        state.baseline = Some((candidate.size, candidate.mtime,
            candidate.observation.file_id.clone(), candidate.observation.change_usn));
        state.due = Some(state.quiet.boundary_deadline(now, confirmation));
    }
    #[cfg(test)]
    pub(super) fn end_phase(&self) { self.0.state.lock().unwrap().quiet.end_phase(); }
    #[cfg(test)]
    pub(super) fn observe(&self, now: f64, boundary: bool, reset: bool, learn: bool) {
        self.0.state.lock().unwrap().quiet.observe(now, boundary, reset, learn);
    }
    #[cfg(test)]
    pub(super) fn set_seconds(&self, seconds: f64) { self.0.state.lock().unwrap().quiet.seconds = seconds; }
}

impl ActivityState {
    fn record(&mut self, candidate: &WatchCandidateRow, now: Instant, at: f64, reset: bool,
        forced_content_change: Option<bool>) {
        if self.observed.is_some_and(|previous| previous > now) { return; }
        self.observed = Some(now);
        let changed = forced_content_change.unwrap_or_else(||
            self.baseline.as_ref().is_none_or(|(size, mtime, id, usn)|
                content_changed(*size, *mtime, id, *usn, candidate)));
        let reset = self.baseline.as_ref().map_or(reset, |(size, _, id, _)|
            *size > candidate.size || *id != candidate.observation.file_id);
        let boundary = is_boundary(candidate);
        if changed {
            self.quiet.observe(at, boundary, reset, true);
        } else if boundary {
            self.quiet.end_phase();
        }
        if changed || forced_content_change.is_some() {
            self.due = Some(after(now, self.quiet.content_wait(changed && boundary)));
        }
        self.baseline = Some((candidate.size, candidate.mtime,
            candidate.observation.file_id.clone(), candidate.observation.change_usn));
    }
}

#[inline]
fn probe_candidate(path: &std::path::Path, since_usn: Option<i64>)
    -> std::io::Result<(Option<WatchCandidateRow>, Instant, f64)> {
    #[cfg(test)]
    if let Some(result) = super::quiet_replay::probe(path, since_usn) { return Ok(result); }
    let candidate = crate::postprocess::watch_candidate_for_observation(path, since_usn)?;
    Ok((candidate, Instant::now(), super::windows::monotonic_seconds()))
}

const WINDOW: usize = 12;
const CLOSE: u32 = 0x8000_0000;
const CONTENT_CLOSE_QUIET_CAP_SECONDS: f64 = 1.0;

pub(super) fn is_boundary(candidate: &WatchCandidateRow) -> bool {
    candidate.observation.change_reasons.is_some_and(|reasons| reasons.all & CLOSE != 0)
}

#[derive(Default)]
pub(super) struct Quiet {
    pub(super) seconds: f64,
    pub(super) cadence: f64,
    pub(super) tentative: f64,
    pub(super) last: Option<f64>,
    samples: Option<Box<VecDeque<(f64, f64)>>>,
}

impl Quiet {
    pub(super) fn saved(value: &NativeWatchObservation) -> Self {
        Self {
            seconds: value.quiet_seconds,
            cadence: value.cadence_seconds,
            tentative: value.pending_interval_seconds,
            last: value.last_content_event_at,
            samples: None,
        }
    }

    #[cfg(test)]
    pub(super) fn content_deadline(
        &mut self, now: Instant, observed_at: f64, boundary: bool, reset: bool,
        retry_unchanged: bool,
    ) -> Instant {
        if retry_unchanged { return now; }
        self.observe(observed_at, boundary, reset, true);
        after(now, self.content_wait(boundary))
    }

    #[inline]
    fn content_wait(&self, content_close: bool) -> f64 {
        // A CLOSE folded into a new content observation ends the handle
        // epoch, not the download. Cap this deadline without altering the
        // learned cadence or bypassing the strict readiness check.
        if content_close { self.seconds.min(CONTENT_CLOSE_QUIET_CAP_SECONDS) } else { self.seconds }
    }

    pub(super) fn boundary_deadline(&self, now: Instant, confirmation: f64) -> Instant {
        // A fresh/reset tracker has no learned quiet window. Main keeps its
        // boundary retry immediately eligible, including a busy-file recheck.
        after(now, self.seconds.min(confirmation))
    }

    pub(super) fn observe(&mut self, now: f64, boundary: bool, reset: bool, learn: bool) {
        if reset {
            *self = Self::default();
        }
        if boundary {
            self.end_phase();
            return;
        }
        if !learn {
            self.tentative = 0.0;
            self.last = Some(now);
            return;
        }
        if let Some(last) = self.last.replace(now) {
            let interval = now - last;
            if interval > 0.0 && interval.is_finite() {
                self.interval(interval, last, now);
            }
        }
    }

    pub(super) fn end_phase(&mut self) {
        self.tentative = 0.0;
        self.last = None;
    }

    fn interval(&mut self, value: f64, last: f64, now: f64) {
        let new_phase = self.cadence == 0.0 || value > 8.0 * self.cadence;
        if new_phase
            && (self.tentative == 0.0
                || value.max(self.tentative) > 2.0 * value.min(self.tentative))
        {
            self.tentative = value;
            return;
        }
        let samples = self
            .samples
            .get_or_insert_with(|| Box::new(VecDeque::with_capacity(WINDOW)));
        if new_phase {
            samples.clear();
            samples.push_back((self.tentative, last));
        }
        self.tentative = 0.0;
        if samples.len() == WINDOW {
            samples.pop_front();
        }
        samples.push_back((value, now));
        self.cadence = quantile(samples, now);
        let scaled = self.cadence / 0.84;
        self.seconds = 1.52 * (0.5 * scaled + 0.5 * scaled.ln_1p()).ln_1p();
    }
}

fn quantile(samples: &VecDeque<(f64, f64)>, now: f64) -> f64 {
    let mut recent = [0.0_f64; 3];
    let n = recent.len().min(samples.len());
    for (index, (value, _)) in samples.iter().rev().take(n).enumerate() {
        recent[index] = *value;
    }
    recent[..n].sort_unstable_by(f64::total_cmp);
    let scale = if n == 2 {
        recent[0] + (recent[1] - recent[0]) / 2.0
    } else {
        recent[n / 2]
    };
    let mut weighted = [(0.0_f64, 0.0_f64); WINDOW];
    let mut total = 0.0;
    for (index, &(interval, at)) in samples.iter().enumerate() {
        let weight = 0.5_f64.powf((now - at) / scale / 2.0);
        weighted[index] = (interval, weight);
        total += weight;
    }
    weighted[..samples.len()].sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
    let mut cumulative = 0.0;
    for &(interval, weight) in &weighted[..samples.len()] {
        cumulative += weight;
        if weight > 0.0 && cumulative >= 0.9 * total {
            return interval;
        }
    }
    weighted[samples.len() - 1].0
}

pub(super) use crate::postprocess::watch_content_changed as content_changed;

pub(super) fn changed(previous: &WatchCandidateRow, current: &WatchCandidateRow) -> bool {
    content_changed(
        previous.size,
        previous.mtime,
        &previous.observation.file_id,
        previous.observation.change_usn,
        current,
    )
}

pub(super) fn observation_changed(previous: &WatchCandidateRow, current: &WatchCandidateRow) -> bool {
    previous.size != current.size || previous.mtime != current.mtime
        || previous.observation.file_id != current.observation.file_id
        || previous.observation.change_usn != current.observation.change_usn
}

pub(super) fn duration(seconds: f64) -> std::time::Duration {
    std::time::Duration::try_from_secs_f64(seconds).unwrap_or_default()
}

pub(super) fn after(now: Instant, seconds: f64) -> Instant {
    now.checked_add(duration(seconds)).unwrap_or(now)
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/quiet/tests.rs"]
mod tests;
