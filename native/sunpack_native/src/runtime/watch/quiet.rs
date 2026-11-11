use crate::postprocess::WatchCandidateRow;
use crate::scan::catalog::NativeWatchObservation;
use std::collections::VecDeque;
use std::time::Instant;

const WINDOW: usize = 12;
pub(super) const CLOSE: u32 = 0x8000_0000;

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

    pub(super) fn observe(&mut self, now: f64, boundary: bool, reset: bool, learn: bool) {
        if reset {
            *self = Self::default();
        }
        if boundary || !learn {
            self.tentative = 0.0;
            self.last = (!boundary).then_some(now);
            return;
        }
        if let Some(last) = self.last.replace(now) {
            let interval = now - last;
            if interval > 0.0 && interval.is_finite() {
                self.interval(interval, last, now);
            }
        }
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

pub(super) fn duration(seconds: f64) -> std::time::Duration {
    std::time::Duration::try_from_secs_f64(seconds).unwrap_or_default()
}

pub(super) fn after(now: Instant, seconds: f64) -> Instant {
    now.checked_add(duration(seconds)).unwrap_or(now)
}
