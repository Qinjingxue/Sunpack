use crate::postprocess::WatchCandidateRow;
use crate::scan::catalog::NativeWatchObservation;
use std::collections::VecDeque;
use std::time::Instant;

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

    pub(super) fn content_deadline(
        &mut self, now: Instant, observed_at: f64, boundary: bool, reset: bool,
        retry_unchanged: bool,
    ) -> Instant {
        self.observe(observed_at, boundary, reset, true);
        // CLOSE ends the handle epoch, not the download. Content observations
        // keep the learned quiet window; metadata-only CLOSE acceleration and
        // admission boundary confirmation are handled separately by Watch.
        after(now, if retry_unchanged { 0.0 } else { self.seconds })
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
