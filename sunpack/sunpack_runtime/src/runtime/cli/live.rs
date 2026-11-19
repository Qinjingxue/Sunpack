//! Event-driven terminal panel. The cursor stays immediately below the live rows.

use super::{tree_edge, Session, Stream};
use crate::core::i18n::Language;
use crate::pipeline::{Event, ResourceWait, TaskId, TaskCompletion, TaskStatus};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

enum Phase {
    Queued,
    Preparing,
    Working,
    ResolvingVolumes,
    Finished(TaskCompletion),
}

struct TaskRow {
    path: PathBuf,
    segment: bool,
    parent: Option<TaskId>,
    children: BTreeSet<TaskId>,
    label: String,
    carrier: bool,
    phase: Phase,
    wait: ResourceWait,
    progress: Option<(u64, u64)>,
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

    fn relocate_outputs(&mut self, id: TaskId, root: &std::path::Path, old: &std::path::Path, new: &std::path::Path) {
        let mut pending = vec![id];
        while let Some(id) = pending.pop() {
            if let Some(task) = self.tasks.get_mut(&id) {
                pending.extend(task.children.iter().copied());
                if let Phase::Finished(result) = &mut task.phase { result.relocate_output(root, old, new); }
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
            Event::OutputsRelocated { id, root, old, new } => {
                self.relocate_outputs(id, &root, &old, &new);
                if !prompting { self.redraw(session, language, true); }
                return;
            }
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
            Event::Finished { id, result, .. } => (id, Some(Phase::Finished(result))),
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
        let phase_changed = phase.is_some();
        if let Some((phase, task)) = phase.zip(self.tasks.get_mut(&id)) {
            task.wait = ResourceWait::default();
            match &phase {
                Phase::Preparing | Phase::Working | Phase::ResolvingVolumes => task.progress = None,
                Phase::Finished(result) => {
                    if result.status == TaskStatus::Complete { task.progress = Some((1, 1)); }
                    task.detail = None;
                }
                Phase::Queued => {}
            }
            task.phase = phase;
        }
        if !prompting {
            self.redraw(session, language, phase_changed && self.should_show(id));
        }
    }

    fn register(&mut self, language: Language, id: TaskId, parent: Option<TaskId>,
        path: PathBuf, segment: Option<crate::pipeline::Segment>) {
        let is_segment = segment.is_some();
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
                path, segment: is_segment,
                parent,
                label,
                children: BTreeSet::new(),
                carrier: false,
                phase: Phase::Queued,
                wait: ResourceWait::default(),
                progress: None,
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

    pub(super) fn take_scope_output(&mut self, id: TaskId) -> Option<PathBuf> {
        let Phase::Finished(result) = &mut self.tasks.get_mut(&id)?.phase else { return None; };
        result.output.take()
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
            if !task.carrier || matches!(&task.phase, Phase::Finished(result) if result.status == TaskStatus::Failed) {
                if rows.len() == height {
                    rows.pop();
                    emit_row(&mut rows, &mut writer, None, width, unicode, format_args!("{}", ellipsis(unicode)))?;
                    return Ok(rows);
                }
                emit_row(&mut rows, &mut writer, Some(id), width, unicode, format_args!("{detail_prefix}{}", row_status(
                    task, width.saturating_sub(display_width(&detail_prefix)), language,
                )))?;
                if let Phase::Finished(result) = &task.phase {
                    let detail = super::task_detail(result.status, result.failure.as_ref(), result.discovery.map(|source| (source, task.path.as_path())), task.segment, self.verbose, language);
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

fn progress_ratio(completed: u64, total: u64) -> f64 {
    if completed >= total { 1.0 } else { completed as f64 / total as f64 }
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
    if matches!(&task.phase, Phase::Finished(result) if result.status == TaskStatus::Skipped) {
        // main never gives skipped rows a progress bar or a known percentage.
        return status_text(language.text("report.status.skipped"), None, "", Some(0));
    }
    let (status, hint) = if task.wait.disk || task.wait.memory {
        wait_status(task.wait, language)
    } else {
        let status = match &task.phase {
            Phase::Queued => "report.status.waiting",
            Phase::Preparing => "report.status.preparing",
            Phase::Working => "report.status.extracting",
            Phase::ResolvingVolumes => "report.status.resolving_volumes",
            Phase::Finished(result) => super::task_status_key(result.status),
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
#[path = "../../../tests/unit/runtime/cli/live/tests.rs"]
mod tests;
