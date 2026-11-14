use crate::postprocess::WatchCandidateRow;
use crate::scan::catalog::NativeWatchObservation;
use std::collections::VecDeque;
use std::time::Instant;


// The observer and scheduler share one bounded tracker. Notifications may be
// coalesced for wakeup/catalog work, never for cadence learning.
#[derive(Default)]
pub(super) struct Activities(std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<ActivityInner>>>);

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
    registration: std::sync::OnceLock<(String, std::sync::Weak<Activities>)>,
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
                    if entries.is_empty() { entries.shrink_to_fit(); }
                }
            }
        }
    }
}

impl Activities {
    pub(super) fn bind(self: &std::sync::Arc<Self>, key: String, make: impl FnOnce() -> Activity) -> Activity {
        let mut entries = self.0.lock().unwrap();
        if let Some(inner) = entries.get(&key).and_then(std::sync::Weak::upgrade) {
            return Activity(inner);
        }
        let activity = make();
        activity.0.registration.get_or_init(|| (key.clone(), std::sync::Arc::downgrade(self)));
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
        if let Some(candidate) = crate::postprocess::watch_candidate_for_path(path, since_usn)? {
            let now = Instant::now();
            let at = super::windows::monotonic_seconds();
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
        let candidate = crate::postprocess::watch_candidate_for_path(path, baseline)?;
        Ok((candidate, Instant::now(), super::windows::monotonic_seconds()))
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
            self.due = Some(after(now, self.quiet.seconds));
        }
        self.baseline = Some((candidate.size, candidate.mtime,
            candidate.observation.file_id.clone(), candidate.observation.change_usn));
    }
}

const WINDOW: usize = 12;
const CLOSE: u32 = 0x8000_0000;

pub(super) fn is_boundary(candidate: &WatchCandidateRow) -> bool {
    candidate.observation.change_reasons_known && candidate.observation.change_reasons & CLOSE != 0
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
        // CLOSE ends the handle epoch, not the download. Content observations
        // keep the learned quiet window; metadata-only CLOSE acceleration and
        // admission boundary confirmation are handled separately by Watch.
        after(now, self.seconds)
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

pub(super) fn content_changed(
    size: u64,
    mtime: f64,
    id: &str,
    usn: i64,
    current: &WatchCandidateRow,
) -> bool {
    if id != current.observation.file_id || size != current.size {
        return true;
    }
    if usn == current.observation.change_usn {
        return false;
    }
    if current.observation.change_reasons_known {
        return current.observation.change_reasons_without_close & 7 != 0;
    }
    current.mtime >= mtime - 2.0
}

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
mod tests {
    use super::*;

    #[test]
    fn shared_samples_survive_coalescing_and_retire_with_the_last_owner() {
        use std::sync::Arc;
        let registry = Arc::new(Activities::default());
        let owner = registry.bind("path".into(), Activity::default);
        let signal = registry.bind("path".into(), Activity::default);
        let now = Instant::now();
        let mut candidate = WatchCandidateRow {
            path: "path".into(), size: 100, mtime: 0.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: "one".into(), change_usn: 1, change_reasons: 1,
                change_reasons_without_close: 1, change_reasons_known: true,
                change_reason_error: String::new(),
            },
        };
        for index in 0..20 {
            candidate.size += 1;
            candidate.mtime = index as f64 * 0.2;
            candidate.observation.change_usn += 1;
            signal.0.state.lock().unwrap().record(&candidate,
                after(now, candidate.mtime), candidate.mtime, false, None);
        }
        let before = owner.summary();
        assert!((before.0 - 0.30950540136780874).abs() < 1e-9);
        assert_eq!(owner.sample_count(), WINDOW);
        let deadline = owner.deadline().unwrap();
        assert_eq!(owner.content_deadline(&candidate, after(now, 100.0), 100.0,
            false, false, None), deadline);
        assert_eq!(owner.summary(), before); // scheduler drain does not relearn
        // An older scheduler probe cannot overwrite a newer callback sample.
        candidate.size -= 1;
        candidate.observation.change_usn -= 1;
        owner.content_deadline(&candidate, now, 0.0, false, false, None);
        assert_eq!(owner.summary(), before);
        candidate.observation.change_reasons = CLOSE;
        owner.metadata(&candidate, now);
        owner.boundary_observation(&candidate, now, 0.0, 0.5);
        assert_eq!(owner.summary(), before); // delayed CLOSE/probe cannot reset newer samples
        // Metadata-only CLOSE may shorten an existing content deadline, but
        // cannot erase a later write observed while the readiness probe ran.
        owner.metadata(&candidate, after(now, 101.0));
        owner.accelerate(after(now, 101.0), after(now, 101.0));
        assert_eq!(owner.deadline(), Some(after(now, 101.0)));
        candidate.size += 2;
        candidate.observation.change_usn += 2;
        candidate.observation.change_reasons = 1;
        owner.content_deadline(&candidate, after(now, 102.0), 102.0, false, false, None);
        let latest = owner.deadline();
        owner.accelerate(after(now, 101.0), after(now, 101.0));
        assert_eq!(owner.deadline(), latest);
        let cadence = owner.summary();
        assert_eq!(owner.content_deadline(&candidate, after(now, 103.0), 103.0,
            false, true, Some(true)), after(now, 103.0));
        assert_eq!(owner.deadline(), Some(after(now, 103.0)));
        assert_eq!(owner.summary(), cadence);
        drop(signal);
        assert_eq!(registry.0.lock().unwrap().len(), 1);
        drop(owner);
        assert!(registry.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unchanged_retries_do_not_change_saved_or_future_cadence() {
        let now = Instant::now();
        let mut expected = Quiet::default();
        let mut actual = Quiet::default();
        for at in [0.0, 1.0, 2.0, 20.0] {
            expected.content_deadline(now, at, false, false, false);
            actual.content_deadline(now, at, false, false, false);
        }
        for boundary in [false, true] {
            assert_eq!(actual.content_deadline(now, 21.0, boundary, true, true), now);
            assert_eq!((actual.seconds, actual.cadence, actual.tentative, actual.last),
                (expected.seconds, expected.cadence, expected.tentative, expected.last));
        }
        for at in [22.0, 24.0, 26.0] {
            assert_eq!(actual.content_deadline(now, at, false, false, false),
                expected.content_deadline(now, at, false, false, false));
        }
    }

    #[test]
    fn admission_boundary_preserves_zero_quiet_and_caps_learned_windows() {
        let mut quiet = Quiet::default();
        let now = Instant::now();
        // First activity and boundary-only/busy retries do not learn a delay.
        quiet.observe(1.0, false, false, true);
        assert_eq!(quiet.boundary_deadline(now, 0.5), now);
        quiet.observe(2.0, false, false, false);
        assert_eq!(quiet.boundary_deadline(now, 0.5), now);
        quiet.seconds = 2.0;
        assert_eq!(quiet.boundary_deadline(now, 0.5), after(now, 0.5));
        quiet.seconds = 0.2;
        assert_eq!(quiet.boundary_deadline(now, 0.5), after(now, 0.2));
        quiet.observe(3.0, true, true, false);
        assert_eq!(quiet.boundary_deadline(now, 0.5), now);
    }

    #[test]
    fn content_close_preserves_learned_quiet_and_unchanged_retry_is_immediate() {
        let mut quiet = Quiet::default();
        let now = Instant::now();
        for at in [0.0, 1.0, 2.0] {
            quiet.content_deadline(now, at, false, false, false);
        }
        let learned = quiet.seconds;
        assert!(learned > 1.0);
        let due = quiet.content_deadline(now, 3.0, true, false, false);
        assert_eq!(due, after(now, learned));
        assert!(due > after(now, 0.8)); // the next write precedes admission
        assert!(quiet.last.is_none()); // CLOSE still ends cadence learning
        assert_eq!(quiet.content_deadline(now, 4.0, true, false, true), now);
        assert_eq!(quiet.content_deadline(now, 5.0, true, true, false), now);
        assert_eq!(quiet.seconds, 0.0); // a replaced/truncated file starts anew
    }
}
