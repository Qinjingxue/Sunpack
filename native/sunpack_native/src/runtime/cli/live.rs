//! Event-driven terminal panel. The cursor stays immediately below the live rows.

use super::{tree_edge, Session, Stream};
use crate::core::i18n::Language;
use crate::pipeline::{Event, ResourceWait, TaskId, TaskCompletion, TaskStatus};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Phase {
    Queued,
    Preparing,
    Working,
    ResolvingVolumes,
    Finished(TaskStatus),
}

struct TaskRow {
    path: PathBuf,
    offset: Option<u64>,
    parent: Option<TaskId>,
    children: BTreeSet<TaskId>,
    label: String,
    carrier: bool,
    retain_display: bool,
    phase: Phase,
    wait: ResourceWait,
    progress: Option<(u64, u64)>,
    result: Option<TaskCompletion>,
    detail: Option<String>,
}

struct Row {
    id: Option<TaskId>,
    text: String,
}

struct Frame {
    size: (usize, usize),
    rows: Vec<Row>,
}

#[derive(Default)]
pub(super) struct Panel {
    tasks: HashMap<TaskId, TaskRow>,
    roots: BTreeSet<TaskId>,
    frame: Option<Frame>,
    cursor_unknown: bool,
    last_render: Option<Instant>,
    verbose: bool,
    // Outer None is immediate mode; inner None means a batch has no redraw yet.
    batch_redraw: Option<Option<bool>>,
}

impl Panel {
    pub(super) fn new(verbose: bool) -> Self { Self { verbose, ..Self::default() } }

    pub(super) fn relocate_outputs(&mut self, old: &std::path::Path, new: &std::path::Path) {
        for task in self.tasks.values_mut() {
            if let Some(result) = &mut task.result {
                result.relocate_output(old, new);
            }
        }
    }

    pub(super) fn update(
        &mut self,
        session: &dyn Session,
        language: Language,
        event: Event,
        prompting: bool,
    ) {
        let (id, phase) = match event {
            Event::Queued {
                id,
                parent,
                path,
                segment,
                ..
            } => {
                self.register(language, id, parent, path, segment);
                (id, None)
            }
            Event::Replanned { id, path } => {
                let Some(parent) = self.tasks.get(&id).map(|task| task.parent) else { return; };
                self.remove(id);
                self.register(language, id, parent, path, None);
                (id, Some(Phase::Preparing))
            }
            Event::Started { id, .. } => (id, Some(Phase::Preparing)),
            Event::Waiting { id } => (id, Some(Phase::Queued)),
            Event::Working { id } => (id, Some(Phase::Working)),
            Event::Extracting { id } => {
                if self.verbose {
                    if let Some(task) = self.tasks.get_mut(&id) {
                        task.detail = Some(language.translate("extract.log.start", &[("archive", &task.path.to_string_lossy())]).trim().to_owned());
                    }
                }
                (id, None)
            }
            Event::ResolvingVolumes { id } => {
                if let Some(task) = self.tasks.get_mut(&id) { task.detail = None; }
                (id, Some(Phase::ResolvingVolumes))
            }
            // main keeps the current row until the execution result is known.
            Event::Finalizing { .. } => return,
            Event::Finished { id, result, .. } => {
                let status = result.status;
                if status == TaskStatus::Skipped {
                    let mut ancestor = Some(id);
                    while let Some(id) = ancestor {
                        let Some(task) = self.tasks.get_mut(&id) else { break; };
                        task.retain_display = true;
                        ancestor = task.parent;
                    }
                }
                if let Some(task) = self.tasks.get_mut(&id) {
                    if status == TaskStatus::Complete { task.progress = Some((1, 1)); }
                    task.result = Some(result);
                    task.detail = None;
                }
                (id, Some(Phase::Finished(status)))
            },
            Event::Progress {
                id,
                completed_bytes,
                total_bytes,
                ..
            } => {
                let Some(task) = self.tasks.get_mut(&id) else { return; };
                if matches!(task.phase, Phase::Finished(_)) { return; }
                let render = !prompting && session.interactive();
                let old_percent = if render {
                    task.progress.map(|(completed, total)| (progress_ratio(completed, total) * 100.0) as usize)
                } else { None };
                task.progress = (total_bytes != 0).then_some((completed_bytes, total_bytes));
                if task.wait.disk || task.wait.memory { return; }
                let changed_phase = !matches!(task.phase, Phase::Working);
                task.phase = Phase::Working;
                if render {
                    let percent = task.progress.map(|(completed, total)| (progress_ratio(completed, total) * 100.0) as usize);
                    // main avoids even viewport traversal when the visible
                    // percent and phase have not changed.
                    if changed_phase || old_percent != percent {
                        self.redraw(session, language, false);
                    }
                }
                return;
            }
            Event::ResourceWait { id, state, .. } => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    task.wait = state;
                }
                if !prompting {
                    self.redraw(session, language, self.should_show(id));
                }
                return;
            }
            Event::Skipped { id } => {
                let visible = self.should_show(id);
                self.remove(id);
                if !prompting {
                    self.redraw(session, language, visible);
                }
                return;
            }
        };
        if let Some((phase, task)) = phase.zip(self.tasks.get_mut(&id)) {
            task.phase = phase;
            task.wait = ResourceWait::default();
            if matches!(phase, Phase::Preparing | Phase::Working | Phase::ResolvingVolumes) {
                task.progress = None;
            }
        }
        if !prompting {
            self.redraw(session, language, phase.is_some() && self.should_show(id));
        }
    }

    fn register(&mut self, language: Language, id: TaskId, parent: Option<TaskId>,
        path: PathBuf, segment: Option<crate::pipeline::Segment>) {
        let is_segment = segment.is_some();
        let offset = segment.as_ref().map(|segment| segment.offset);
        let label = if let Some(segment) = segment {
            let label = language
                .translate("cli.scan.segment", &[("index", &segment.index.to_string())]);
            let end = segment
                .end_offset
                .map_or_else(|| "?".into(), |end| end.to_string());
            format!("{label} ({}) [{}, {end})", segment.format, segment.offset)
        } else {
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned()
        };
        let parent = parent.filter(|parent| self.tasks.contains_key(parent));
        if let Some(parent) = parent {
            let parent = self.tasks.get_mut(&parent).unwrap();
            parent.children.insert(id);
            parent.carrier |= is_segment;
        } else {
            self.roots.insert(id);
        }
        self.tasks.insert(
            id,
            TaskRow {
                path, offset,
                parent,
                label,
                children: BTreeSet::new(),
                carrier: false,
                retain_display: false,
                phase: Phase::Queued,
                wait: ResourceWait::default(),
                progress: None,
                result: None,
                detail: None,
            },
        );
    }

    fn should_show(&self, id: TaskId) -> bool {
        // Semantic batches correspond to main's forced task update. Avoid a
        // viewport scan for each registered segment; render the batch once.
        if self.batch_redraw.is_some() { return true; }
        self.frame.as_ref().is_some_and(|frame| {
            frame.rows.last().is_none_or(|row| row.id.is_some())
                || frame.rows.iter().any(|row| row.id == Some(id))
        })
    }

    pub(super) fn disk_waiting(&self, id: TaskId, episode: u64) -> bool {
        self.tasks.get(&id).is_some_and(|row| row.wait.disk && row.wait.disk_episode == episode)
    }

    pub(super) fn scope_progress(&self, id: TaskId) -> HashMap<(PathBuf, Option<u64>), (u64, u64)> {
        let mut progress = HashMap::new();
        let mut pending = vec![id];
        while let Some(id) = pending.pop() {
            if let Some(row) = self.tasks.get(&id) {
                pending.extend(row.children.iter().copied());
                if !row.carrier {
                    if let Some(value) = row.progress {
                        progress.insert((row.path.clone(), row.offset), value);
                    }
                }
            }
        }
        progress
    }

    pub(super) fn remove(&mut self, id: TaskId) {
        let Some(row) = self.tasks.remove(&id) else {
            return;
        };
        if let Some(parent) = row.parent {
            if let Some(parent) = self.tasks.get_mut(&parent) {
                parent.children.remove(&id);
            }
        } else {
            self.roots.remove(&id);
        }
        let mut children: Vec<_> = row.children.into_iter().collect();
        while let Some(id) = children.pop() {
            if let Some(row) = self.tasks.remove(&id) {
                children.extend(row.children);
            }
        }
        crate::collections::trim_map(&mut self.tasks);
    }

    pub(super) fn clear(&mut self, session: &dyn Session) -> io::Result<()> {
        let mut output = String::new();
        self.clear_output(session.terminal_size(), &mut output);
        self.frame = None;
        self.write(session, &output)
    }

    fn clear_output(&self, size: (usize, usize), output: &mut String) {
        if self.cursor_unknown {
            output.push_str("\x18\r\n");
        } else if let Some(frame) = self.frame.as_ref().filter(|frame| !frame.rows.is_empty()) {
            if frame.size == size {
                let _ = write!(output, "\x1b[{}A\r\x1b[J", frame.rows.len());
            } else {
                // Reflow can move the old panel's origin. Keep its snapshot.
                output.push_str("\r\n");
            }
        }
    }

    fn write(&mut self, session: &dyn Session, output: &str) -> io::Result<()> {
        if output.is_empty() {
            return Ok(());
        }
        let result = session.write(Stream::Out, output.as_bytes());
        self.cursor_unknown = result.is_err();
        result
    }

    pub(super) fn begin_batch(&mut self) { self.batch_redraw = Some(None); }

    pub(super) fn end_batch(&mut self, session: &dyn Session, language: Language, render: bool) {
        if let Some(force) = self.batch_redraw.take().flatten().filter(|_| render) {
            self.redraw(session, language, force);
        }
    }

    pub(super) fn redraw(&mut self, session: &dyn Session, language: Language, force: bool) {
        if let Some(pending) = &mut self.batch_redraw {
            *pending = Some(force || pending.unwrap_or(false));
            return;
        }
        if !session.interactive() { return; }
        let now = Instant::now();
        if !force
            && self
                .last_render
                .is_some_and(|last| now.duration_since(last) < Duration::from_millis(80))
        {
            return;
        }
        self.last_render = Some(now);
        let size = session.terminal_size();
        let rows = self.rows(size, session.unicode(), language);
        let mut output = String::new();
        if let Some(frame) = self
            .frame
            .as_ref()
            .filter(|frame| frame.size == size && frame.rows.len() == rows.len())
        {
            let Some(start) = frame
                .rows
                .iter()
                .zip(&rows)
                .position(|(old, new)| old.text != new.text)
            else {
                // Row identities can change even when their labels look the same.
                self.frame = Some(Frame { size, rows });
                return;
            };
            let unchanged_tail = frame
                .rows
                .iter()
                .zip(&rows)
                .rev()
                .take_while(|(old, new)| old.text == new.text)
                .count();
            let end = rows.len() - unchanged_tail;
            let _ = write!(output, "\x1b[{}A", rows.len() - start);
            for row in &rows[start..end] {
                let _ = write!(output, "\r\x1b[2K{}\r\n", row.text);
            }
            if unchanged_tail > 0 {
                let _ = write!(output, "\x1b[{unchanged_tail}B\r");
            }
        } else {
            self.clear_output(size, &mut output);
            for row in &rows {
                output.push_str(&row.text);
                output.push_str("\r\n");
            }
        }
        self.frame = self
            .write(session, &output)
            .is_ok()
            .then_some(Frame { size, rows });
    }

    pub(super) fn retains_scope(&self, id: TaskId) -> bool {
        self.roots.contains(&id) && self.tasks.get(&id).is_some_and(|task| task.retain_display)
    }

    pub(super) fn write_scope(&self, id: TaskId, unicode: bool, language: Language, writer: &mut impl io::Write) -> io::Result<()> {
        self.rows_scope((usize::MAX, usize::MAX), unicode, language, Some(id), Some(writer))?;
        Ok(())
    }

    fn rows(&self, size: (usize, usize), unicode: bool, language: Language) -> Vec<Row> {
        self.rows_scope(size, unicode, language, None, None).expect("viewport collection cannot fail")
    }

    fn rows_scope(
        &self,
        (columns, lines): (usize, usize),
        unicode: bool,
        language: Language,
        scope: Option<TaskId>,
        mut writer: Option<&mut dyn io::Write>,
    ) -> io::Result<Vec<Row>> {
        let (width, height) = (columns.saturating_sub(1), lines.saturating_sub(1));
        let mut rows = Vec::new();
        if height == 0 || width == 0 || self.roots.is_empty() {
            return Ok(rows);
        }
        let mut prefix = String::new();
        use std::ops::Bound::{Included, Unbounded};
        let bounds = scope.map_or((Unbounded, Unbounded), |id| (Included(id), Included(id)));
        let mut stack = vec![(self.roots.range(bounds).peekable(), 0, true)];
        while let Some((siblings, prefix_len, is_root)) = stack.last_mut() {
            let Some(&id) = siblings.next() else {
                stack.pop();
                continue;
            };
            let task = &self.tasks[&id];
            if rows.len() == height {
                rows.pop();
                emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
                break;
            }
            prefix.truncate(*prefix_len);
            let (edge, continuation) = if *is_root {
                ("", "")
            } else {
                tree_edge(unicode, siblings.peek().is_none())
            };
            let label = if writer.is_some() { super::single_line(&task.label) }
                else { std::borrow::Cow::Borrowed(task.label.as_str()) };
            emit_row(&mut rows, &mut writer, Some(id), width, unicode, format_args!("{prefix}{edge}{label}"))?;
            let detail_prefix = format!("{prefix}{continuation}  ");
            if !task.carrier || matches!(task.phase, Phase::Finished(TaskStatus::Failed)) {
                if rows.len() == height {
                    rows.pop();
                    emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
                    return Ok(rows);
                }
                emit_row(&mut rows, &mut writer, Some(id), width, unicode, format_args!("{detail_prefix}{}", row_status(
                    task, width.saturating_sub(display_width(&detail_prefix)), language,
                )))?;
                if let Some(result) = &task.result {
                    let detail = super::task_detail(result.status, result.failure.as_ref(), result.discovery.map(|source| (source, task.path.as_path())), task.offset.is_some(), self.verbose, language);
                    let output = result.output.as_ref().filter(|_| self.verbose).map(|output| language.translate(
                        "report.detail.output", &[("output", &output.to_string_lossy())],
                    ));
                    for (text, normalize) in detail.as_deref().map(|text| (text, true)).into_iter()
                        .chain(output.as_deref().map(|text| (text, false))) {
                        if rows.len() == height {
                            rows.pop();
                            emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
                            return Ok(rows);
                        }
                        let text = if normalize && writer.is_some() { super::single_line(text) }
                            else { std::borrow::Cow::Borrowed(text) };
                        emit_row(&mut rows, &mut writer, Some(id), width, unicode, format_args!("{detail_prefix}{text}"))?;
                    }
                } else if let Some(detail) = &task.detail {
                    if rows.len() == height {
                        rows.pop();
                        emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
                        return Ok(rows);
                    }
                    emit_row(&mut rows, &mut writer, Some(id), width, unicode, format_args!("{detail_prefix}{detail}"))?;
                }
            }
            if !task.children.is_empty() {
                prefix.push_str(continuation);
                stack.push((task.children.range(..).peekable(), prefix.len(), false));
            }
        }
        if writer.is_none() && rows.len() == height {
            rows.pop();
            emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
        }
        Ok(rows)
    }
}

fn emit_row(
    rows: &mut Vec<Row>, writer: &mut Option<&mut dyn io::Write>, id: Option<TaskId>,
    width: usize, unicode: bool, text: std::fmt::Arguments<'_>,
) -> io::Result<()> {
    if let Some(writer) = writer { writeln!(writer, "{text}") }
    else { rows.push(Row { id, text: clipped(text.to_string(), width, unicode) }); Ok(()) }
}

pub(super) fn wait_status(state: ResourceWait, language: Language) -> (&'static str, String) {
    let (status, hint) = match (state.disk, state.memory) {
        (true, true) => (
            "report.status.resources_paused",
            "report.status.resources_resume_hint",
        ),
        (true, false) => (
            "report.status.disk_paused",
            "report.status.disk_resume_hint",
        ),
        (false, true) => (
            "report.status.memory_paused",
            "report.status.memory_resume_hint",
        ),
        (false, false) => ("report.status.extracting", ""),
    };
    let hint = match state.volume_error {
        Some(error) => language.translate(
            "report.status.disk_unavailable",
            &[("error", &error.to_string())],
        ),
        None => language.text(hint).into(),
    };
    (language.text(status), hint)
}

// Python's int/int division rounds the exact quotient once. Casting both
// operands first can change percent boundaries above the exact-integer range.
fn progress_ratio(completed: u64, total: u64) -> f64 {
    if completed >= total { return 1.0; }
    if completed == 0 { return 0.0; }
    if total <= (1_u64 << 53) { return completed as f64 / total as f64; }
    let mut exponent = total.leading_zeros() as i32 - completed.leading_zeros() as i32;
    if (completed as u128) << (-exponent as u32) < total as u128 { exponent -= 1; }
    let numerator = (completed as u128) << (52 - exponent) as u32;
    let divisor = total as u128;
    let mut significand = numerator / divisor;
    let remainder = numerator % divisor;
    if remainder * 2 > divisor || (remainder * 2 == divisor && significand & 1 != 0) {
        significand += 1;
    }
    if significand == (1_u128 << 53) {
        significand >>= 1;
        exponent += 1;
    }
    f64::from_bits(((exponent + 1023) as u64) << 52 | (significand as u64 - (1_u64 << 52)))
}

fn append_progress(text: &mut String, progress: Option<(u64, u64)>, bar: bool) {
    let ratio = progress.filter(|&(_, total)| total != 0)
        .map(|(completed, total)| progress_ratio(completed, total));
    if bar {
        let filled = (ratio.unwrap_or(0.0) * 20.0) as usize;
        text.push_str(" [");
        text.push_str(&"####################"[..filled]);
        text.push_str(&"--------------------"[..20 - filled]);
        text.push(']');
    }
    match ratio {
        Some(ratio) => { let _ = write!(text, " {:3}%", (ratio * 100.0) as usize); }
        None => text.push_str("  --%"),
    }
}

fn row_status(task: &TaskRow, available: usize, language: Language) -> String {
    if matches!(task.phase, Phase::Finished(TaskStatus::Skipped)) {
        // main never gives skipped rows a progress bar or a known percentage.
        return status_text(language.text("report.status.skipped"), None, "", Some(0));
    }
    let (status, hint) = if task.wait.disk || task.wait.memory {
        wait_status(task.wait, language)
    } else {
        let status = match task.phase {
            Phase::Queued => "report.status.waiting",
            Phase::Preparing => "report.status.preparing",
            Phase::Working => "report.status.extracting",
            Phase::ResolvingVolumes => "report.status.resolving_volumes",
            Phase::Finished(status) => super::task_status_key(status),
        };
        (language.text(status), String::new())
    };
    status_text(status, task.progress, &hint, Some(available))
}

// The live panel and settled tree use the same status layout. Only the live
// viewport constrains its width; titles occupy their own row in both views.
pub(super) fn status_text(
    status: &str, progress: Option<(u64, u64)>, hint: &str, available: Option<usize>,
) -> String {
    let bar = available.is_none_or(|width| display_width(status) + 30 <= width);
    let mut state = String::with_capacity(status.len() + 2 + if bar { 28 } else { 5 } + hint.len() + usize::from(!hint.is_empty()));
    state.push('[');
    state.push_str(status);
    state.push(']');
    append_progress(&mut state, progress, bar);
    if !hint.is_empty() {
        state.push(' ');
        state.push_str(hint);
    }
    state
}

fn ellipsis(unicode: bool) -> &'static str {
    if unicode {
        "…"
    } else {
        "..."
    }
}

fn cell_width(ch: char) -> usize {
    if ch as u32 <= 0xff || matches!(ch, '├' | '─' | '└' | '│' | '…') {
        1
    } else {
        2
    }
}

fn display_width(text: &str) -> usize {
    if text.is_ascii() {
        text.len()
    } else {
        text.chars().map(cell_width).sum()
    }
}

fn clipped(text: String, max: usize, unicode: bool) -> String {
    if text.len() <= max && !text.chars().any(char::is_control) { return text; }
    let marker = if unicode {
        if max == 0 {
            ""
        } else {
            "…"
        }
    } else {
        &"..."[..max.min(3)]
    };
    let mut output = String::with_capacity(text.len().min(max.saturating_mul(3)));
    let mut width = 0;
    for ch in text.chars() {
        // Control characters in a path must not move the cursor or escape the panel.
        let ch = if ch.is_control() { ' ' } else { ch };
        width += cell_width(ch);
        if width > max {
            width -= cell_width(ch);
            while width + marker.chars().count() > max {
                width -= cell_width(output.pop().unwrap());
            }
            output.push_str(marker);
            break;
        }
        output.push(ch);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Segment;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct Terminal {
        size: (usize, usize),
        output: Mutex<Vec<u8>>,
    }

    impl Session for Terminal {
        fn write(&self, _: Stream, data: &[u8]) -> io::Result<()> {
            self.output.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        fn read_line(&self, _: &str) -> io::Result<Option<String>> {
            unreachable!()
        }
        fn interactive(&self) -> bool {
            true
        }
        fn unicode(&self) -> bool {
            true
        }
        fn terminal_size(&self) -> (usize, usize) {
            self.size
        }
    }

    fn queued(id: TaskId, parent: Option<TaskId>, path: &str, segment: Option<Segment>) -> Event {
        Event::Queued {
            id,
            parent,
            path: path.into(),
            depth: if id == 5 { 2 } else { 1 },
            segment,
        }
    }

    #[test]
    fn physical_replan_replaces_rows_without_carrying_old_progress_or_waits() {
        let terminal = Terminal { size: (80, 30), output: Mutex::default() };
        let mut panel = Panel::new(true);
        panel.update(&terminal, Language::En, queued(1, None, "outer.zip", None), true);
        panel.update(&terminal, Language::En, queued(2, Some(1), "old.002", None), true);
        panel.update(&terminal, Language::En, Event::Extracting { id: 2 }, true);
        assert_eq!(panel.tasks[&2].detail.as_deref(), Some("[EXTRACT] Start: old.002"));
        panel.update(&terminal, Language::En, queued(3, Some(2), "old segment", None), true);
        panel.update(&terminal, Language::En, Event::Progress {
            id: 2, path: "old.002".into(), completed_bytes: 90, total_bytes: 100,
        }, true);
        panel.update(&terminal, Language::En, Event::ResourceWait {
            id: 2, path: "old.002".into(), state: ResourceWait { disk: true, ..Default::default() },
        }, true);
        panel.update(&terminal, Language::En, Event::ResolvingVolumes { id: 2 }, true);
        assert!(row_status(&panel.tasks[&2], 80, Language::En).contains("Resolving split volumes"));
        assert!(panel.tasks[&2].progress.is_none());
        panel.update(&terminal, Language::En, Event::Replanned { id: 2, path: "new.001".into() }, true);
        let row = &panel.tasks[&2];
        assert_eq!(row.label, "new.001");
        assert_eq!(row.parent, Some(1));
        assert!(row.children.is_empty());
        assert!(row.progress.is_none() && row.result.is_none());
        assert!(!row.wait.disk && !row.wait.memory);
        assert!(matches!(row.phase, Phase::Preparing));
        assert!(!panel.tasks.contains_key(&3));
        assert_eq!(panel.tasks[&1].children.iter().copied().collect::<Vec<_>>(), vec![2]);
        assert_eq!(panel.roots.iter().copied().collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn progress_rounding_and_post_worker_phase_match_main() {
        assert_eq!(status_text("X", Some((29, 100)), "", Some(10)), "[X]  28%");
        assert_eq!(status_text("X", Some((58, 100)), "", None), "[X] [###########---------]  57%");
        assert_eq!(status_text("X", Some((101, 100)), "", None), "[X] [####################] 100%");
        assert_eq!(status_text("X", Some((1, 0)), "", Some(10)), "[X]  --%");
        // Golden ratios from Python's integer true division, including values
        // that would round differently if each operand were converted first.
        for (completed, total, expected) in [
            (9_007_199_254_740_991, 9_007_199_254_740_993, 0.9999999999999998),
            (2_612_087_783_874_887, 9_007_199_254_740_993, 0.28999999999999987),
            (5_349_555_781_375_769_968, u64::MAX, 0.29),
            (1, u64::MAX, 5.421010862427522e-20),
        ] {
            assert_eq!(progress_ratio(completed, total), expected);
        }
        let terminal = Terminal { size: (80, 30), output: Mutex::default() };
        let mut panel = Panel::default();
        panel.update(&terminal, Language::En, queued(1, None, "archive.zip", None), true);
        panel.update(&terminal, Language::En, Event::Working { id: 1 }, true);
        panel.update(&terminal, Language::En, Event::Progress {
            id: 1, path: "archive.zip".into(), completed_bytes: 29, total_bytes: 100,
        }, true);
        let before = row_status(&panel.tasks[&1], 80, Language::En);
        panel.update(&terminal, Language::En, Event::Finalizing { id: 1 }, true);
        assert_eq!(row_status(&panel.tasks[&1], 80, Language::En), before);
        assert!(terminal.output.lock().unwrap().is_empty());
        panel.last_render = None;
        panel.update(&terminal, Language::En, Event::Progress {
            id: 1, path: "archive.zip".into(), completed_bytes: 290, total_bytes: 1000,
        }, false);
        assert!(panel.last_render.is_none(), "unchanged percent must not traverse the viewport");
        assert_eq!(panel.tasks[&1].progress, Some((290, 1000)));
    }

    #[test]
    fn live_titles_and_status_share_settled_layout_across_widths_and_resize() {
        let mut terminal = Terminal { size: (80, 30), output: Mutex::default() };
        for language in [Language::En, Language::Zh] {
            for name in ["a-very-long-archive-title-with-important-suffix.zip",
                         "一个很长的压缩包文件名需要保持完整标题以便辨认归档.zip"] {
                let mut panel = Panel::default();
                panel.update(&terminal, language, queued(1, None, name, None), false);
                for columns in [50, 80] {
                    terminal.size = (columns, 30);
                    panel.update(&terminal, language, Event::ResourceWait {
                        id: 1, path: name.into(), state: ResourceWait {
                            disk: true, memory: true, ..ResourceWait::default()
                        },
                    }, true);
                    // Prompt suspension changes state without touching the terminal.
                    terminal.output.lock().unwrap().clear();
                    panel.update(&terminal, language, Event::Progress {
                        id: 1, path: name.into(), completed_bytes: 60, total_bytes: 100,
                    }, true);
                    assert!(terminal.output.lock().unwrap().is_empty());
                    panel.redraw(&terminal, language, true);
                    let rows = &panel.frame.as_ref().unwrap().rows;
                    assert_eq!(rows.len(), 2);
                    assert_eq!(rows[0].text, clipped(name.to_owned(), columns - 1, true));
                    let (status, hint) = wait_status(panel.tasks[&1].wait, language);
                    let expected = status_text(status, Some((60, 100)), &hint, Some(columns - 3));
                    assert_eq!(rows[1].text, clipped(format!("  {expected}"), columns - 1, true));
                    assert!(rows.iter().all(|row| display_width(&row.text) < columns));
                    assert!(rows[1].text.contains("60%"));
                    // Resize must preserve old history instead of moving up by a stale height.
                    let bytes = terminal.output.lock().unwrap();
                    assert!(bytes.starts_with(b"\r\n"));
                }
            }
        }
        // Narrow fallback follows main: omit only the bar, not the title or percent.
        assert_eq!(status_text("Extracting", Some((60, 100)), "", Some(20)), "[Extracting]  60%");
    }

    #[test]
    fn flatten_relocates_visible_and_buffered_descendant_outputs() {
        use super::super::reporting::Reports;
        let terminal = Terminal { size: (140, 40), output: Mutex::default() };
        let mut panel = Panel::new(true);
        let reports = Reports::default();
        for (id, parent) in [(1, None), (2, Some(1)), (3, Some(2)), (4, Some(1)), (5, None)] {
            panel.update(&terminal, Language::En, queued(id, parent, "nested.zip", None), false);
        }
        // A nested descendant is already visible, another is still coalesced,
        // a segment owns the wrapper, and an unrelated root must stay intact.
        for (id, path) in [(3, "root/wrapper/leaf/nested/deep"),
                           (4, "root/wrapper"), (5, "elsewhere/output")] {
            panel.update(&terminal, Language::En, Event::Finished {
                id, path: "nested.zip".into(), depth: 1,
                result: TaskCompletion { discovery: None, status: TaskStatus::Complete, failure: None, output: Some(path.into()) },
            }, false);
        }
        reports.notify(Event::Finished {
            id: 2, path: "nested.zip".into(), depth: 1,
            result: TaskCompletion { discovery: None, status: TaskStatus::Complete, failure: None,
                output: Some("root/wrapper/leaf/nested".into()) },
        });
        let (old, new) = (std::path::Path::new("root/wrapper/leaf"), std::path::Path::new("root"));
        reports.relocate_outputs(old, new);
        panel.relocate_outputs(old, new);
        for event in reports.take_events() {
            panel.update(&terminal, Language::En, event, false);
        }
        for (id, expected) in [(2, "root/nested"), (3, "root/nested/deep"),
                               (4, "root"), (5, "elsewhere/output")] {
            assert_eq!(panel.tasks[&id].result.as_ref().unwrap().output.as_deref(), Some(std::path::Path::new(expected)));
        }
        let rows = panel.rows(terminal.size, true, Language::En);
        assert!(rows.iter().all(|row| !row.text.contains("wrapper")));
        assert!(rows.iter().any(|row| row.text.contains("elsewhere")));
    }

    #[test]
    fn event_batch_renders_once_without_rebuilding_intermediate_viewports() {
        let terminal = Terminal { size: (140, 40), output: Mutex::default() };
        let mut panel = Panel::new(false);
        panel.begin_batch();
        for id in 1..=5 {
            panel.update(&terminal, Language::En, queued(id, None, "archive.zip", None), false);
            panel.update(&terminal, Language::En, Event::Started { id, path: "archive.zip".into(), depth: 1 }, false);
        }
        assert!(terminal.output.lock().unwrap().is_empty());
        assert!(panel.frame.is_none());
        panel.end_batch(&terminal, Language::En, true);
        assert!(!terminal.output.lock().unwrap().is_empty());
        assert_eq!(panel.frame.as_ref().unwrap().rows.len(), 10);
        // Normal completed scopes keep the established ScopeReport path.
        assert!(!panel.retains_scope(1));
    }

    #[test]
    fn task_preflight_keeps_failed_segments_and_marks_unexecuted_rows_skipped() {
        use crate::pipeline::{Failure, FailureKind};
        let terminal = Terminal { size: (140, 40), output: Mutex::default() };
        let mut panel = Panel::new(false);
        panel.update(&terminal, Language::En, queued(1, None, "carrier.bin", None), true);
        for id in [2, 3] {
            panel.update(&terminal, Language::En, queued(id, Some(1), "carrier.bin", Some(Segment {
                format: "zip".into(), index: id as usize - 1, count: 2,
                offset: 0, end_offset: None,
            })), true);
            let result = if id == 2 {
                TaskCompletion::failed(&Failure::new(FailureKind::Damaged, "damaged"))
            } else { TaskCompletion { discovery: None, status: TaskStatus::Skipped, failure: None, output: None } };
            panel.update(&terminal, Language::En, Event::Finished {
                id, path: "carrier.bin".into(), depth: 1, result,
            }, true);
        }
        panel.update(&terminal, Language::En, Event::Finished {
            id: 1, path: "carrier.bin".into(), depth: 1,
            result: TaskCompletion::failed(&Failure::new(FailureKind::MissingVolume, "missing volume")),
        }, true);
        let rows = panel.rows(terminal.size, true, Language::En);
        assert!(rows.iter().any(|row| row.id == Some(2) && row.text.contains(Language::En.text("failure.damaged"))));
        let skipped: Vec<_> = rows.iter().filter(|row| row.id == Some(3)).collect();
        assert_eq!(skipped.len(), 2);
        assert!(skipped[1].text.ends_with("[Skipped]  --%"));
        assert!(!skipped[1].text.contains("----"));
        let mut settled = Vec::new();
        panel.write_scope(1, true, Language::En, &mut settled).unwrap();
        assert!(String::from_utf8(settled).unwrap().lines().any(|line| line.ends_with("[Skipped]  --%")));
        panel.tasks.get_mut(&1).unwrap().label = "carrier\r\nname".into();
        panel.tasks.get_mut(&2).unwrap().result = Some(TaskCompletion::failed(
            &Failure::new(FailureKind::FilesystemError, "first\nsecond")));
        let mut text = Vec::new();
        panel.write_scope(1, true, Language::En, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.starts_with("carrier  name\n"));
        assert!(text.contains("first second"));
        assert!(!text.contains('\r'));
        let failure = Failure::new(FailureKind::PasswordRequired, "password")
            .with_context(crate::pipeline::FailureContext::Discovery {
                discovery: crate::pipeline::DiscoverySource::Embedded,
                reason: "needs_password".into(), path: "carrier.bin".into(), error: String::new(),
            });
        panel.update(&terminal, Language::En, Event::Finished {
            id: 2, path: "carrier.bin".into(), depth: 1, result: TaskCompletion::failed(&failure),
        }, true);
        assert!(panel.rows(terminal.size, true, Language::En).iter().any(|row|
            row.id == Some(2) && row.text.contains(&format!("carrier.bin: {}", Language::En.text("failure.password_not_in_list")))));
        // Ordinary input aggregation does not repeat segment details at the carrier.
        panel.update(&terminal, Language::En, Event::Finished {
            id: 1, path: "carrier.bin".into(), depth: 1,
            result: TaskCompletion { discovery: None, status: TaskStatus::Failed, failure: None, output: None },
        }, true);
        assert_eq!(panel.rows(terminal.size, true, Language::En).iter().filter(|row| row.id == Some(1)).count(), 2);
        // Parent task_finished formats an otherwise empty password error;
        // only executor segment rows retain the no-detail password convention.
        panel.update(&terminal, Language::En, Event::Finished {
            id: 1, path: "carrier.bin".into(), depth: 1,
            result: TaskCompletion::failed(&Failure::new(FailureKind::WrongPassword, "password")),
        }, true);
        assert!(panel.rows(terminal.size, true, Language::En).iter().any(|row|
            row.id == Some(1) && row.text.contains(Language::En.text("failure.password_not_in_list"))));
    }

    #[test]
    fn finished_rows_project_results_while_other_work_is_running() {
        use crate::pipeline::{Failure, FailureKind};
        let terminal = Terminal { size: (140, 40), output: Mutex::default() };
        for verbose in [false, true] {
            let mut panel = Panel::new(verbose);
            for (id, path) in [(1, "carrier"), (2, "slow.zip"), (3, "cancelled.zip")] {
                panel.update(&terminal, Language::En, queued(id, None, path, None), false);
            }
            for (id, status) in [(4, TaskStatus::Partial), (5, TaskStatus::Complete)] {
                panel.update(&terminal, Language::En, queued(id, Some(1), "carrier", Some(Segment {
                    format: "zip".into(), index: (id - 3) as usize, count: 2,
                    offset: id * 100, end_offset: Some(id * 100 + 50),
                })), false);
                panel.update(&terminal, Language::En, Event::Progress {
                    id, path: "carrier".into(), completed_bytes: 6, total_bytes: 10,
                }, false);
                panel.update(&terminal, Language::En, Event::Finished {
                    id, path: "carrier".into(), depth: 1,
                    result: TaskCompletion { discovery: None, status,
                        failure: (status == TaskStatus::Partial).then(|| Failure::new(FailureKind::Damaged, "raw")),
                        output: Some(format!("output-{id}").into()),
                    },
                }, false);
            }
            panel.update(&terminal, Language::En, Event::Finished {
                id: 3, path: "cancelled.zip".into(), depth: 1,
                result: TaskCompletion { discovery: None, status: TaskStatus::Failed,
                    failure: Some(Failure::new(FailureKind::Cancelled, "raw")), output: None },
            }, false);
            let rows = panel.rows(terminal.size, true, Language::En);
            let text = rows.iter().map(|row| row.text.as_str()).collect::<Vec<_>>().join("\n");
            assert!(text.contains(Language::En.text("report.status.partial")));
            assert!(rows.iter().any(|row| row.id == Some(4) && row.text.contains("60%")));
            assert!(rows.iter().any(|row| row.id == Some(5) && row.text.contains("100%")));
            assert!(text.contains(Language::En.text("failure.user_interrupted")));
            assert_eq!(text.contains(Language::En.text("failure.damaged")), verbose);
            assert_eq!(text.contains("output-4"), verbose);
            assert_eq!(text.contains("output-5"), verbose);
            assert!(text.contains("slow.zip"));
            // Authoritative carrier finalization can change a segment's output.
            panel.update(&terminal, Language::En, Event::Finished {
                id: 4, path: "carrier".into(), depth: 1,
                result: TaskCompletion { discovery: None, status: TaskStatus::Failed,
                    failure: Some(Failure::new(FailureKind::Damaged, "raw")), output: None },
            }, false);
            let text = panel.rows(terminal.size, true, Language::En).into_iter()
                .map(|row| row.text).collect::<Vec<_>>().join("\n");
            assert!(!text.contains("output-4"));
            assert!(text.contains(Language::En.text("failure.damaged")));
            panel.remove(1);
            assert!(!panel.tasks.contains_key(&4));
            assert!(!panel.tasks.contains_key(&5));
            assert!(panel.tasks.contains_key(&2));
        }
    }

    #[test]
    fn live_frame_keeps_same_path_segments_and_sibling_archives_independent() {
        // The final-tree tests cannot find a live update overwriting another
        // archive or a same-path segment. Replay concurrent events with no
        // worker or sleeps, and verify the visible tree survives root retirement.
        let terminal = Terminal {
            size: (100, 15),
            output: Mutex::default(),
        };
        let mut panel = Panel::default();
        let carrier = PathBuf::from("carrier.dat");
        let mut update = |event| panel.update(&terminal, Language::En, event, false);
        update(queued(1, None, "carrier.dat", None));
        update(queued(2, None, "other.zip", None));
        for index in 1..=2 {
            update(queued(
                2 + index as TaskId,
                Some(1),
                "carrier.dat",
                Some(Segment {
                    format: "zip".into(),
                    index,
                    count: 2,
                    offset: 100 * index as u64,
                    end_offset: Some(100 * index as u64 + 50),
                }),
            ));
        }
        update(Event::Working { id: 2 });
        update(Event::Working { id: 3 });
        update(Event::Progress {
            id: 3,
            path: carrier.clone(),
            completed_bytes: 6,
            total_bytes: 10,
        });
        update(Event::ResourceWait {
            id: 3,
            path: carrier,
            state: ResourceWait {
                disk: true,
                ..ResourceWait::default()
            },
        });
        update(queued(5, Some(4), "nested.zip", None));
        update(Event::Started {
            id: 5,
            path: "nested.zip".into(),
            depth: 2,
        });

        let rows: Vec<_> = panel
            .frame
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .map(|row| row.text.as_str())
            .collect();
        assert_eq!(rows.len(), 9);
        assert_eq!(rows[1], "├─ Segment 1 (zip) [100, 150)");
        assert!(rows[2].starts_with("│    [Disk full] [############--------]  60%"));
        assert_eq!(rows[3], "└─ Segment 2 (zip) [200, 250)");
        assert!(rows[4].starts_with("     [Waiting]"));
        assert_eq!(rows[5], "   └─ nested.zip");
        assert!(rows[6].starts_with("        [Preparing]"));
        assert_eq!(rows[7], "other.zip");
        assert_eq!(rows[8], "  [Extracting] [--------------------]  --%");
        assert!(String::from_utf8_lossy(&terminal.output.lock().unwrap())
            .contains("   └─ nested.zip\r\n"));

        panel.remove(2);
        panel.redraw(&terminal, Language::En, true);
        assert_eq!(panel.frame.as_ref().unwrap().rows.len(), 7);
        assert!(panel.frame.as_ref().unwrap().rows[2]
            .text
            .contains("Disk full"));
    }
}
