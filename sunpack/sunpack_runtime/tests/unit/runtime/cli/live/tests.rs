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
        id: 2, completed_bytes: 90, total_bytes: 100,
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
    assert!(row.progress.is_none());
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
    // Huge logical byte counts remain bounded and monotonic without
    // reproducing another language's integer-division rounding.
    let half = progress_ratio(u64::MAX / 2, u64::MAX);
    assert!(half > 0.0 && half < 1.0);
    assert!(progress_ratio(1, u64::MAX) <= half);
    assert_eq!(progress_ratio(u64::MAX, u64::MAX), 1.0);
    let terminal = Terminal { size: (80, 30), output: Mutex::default() };
    let mut panel = Panel::default();
    panel.update(&terminal, Language::En, queued(1, None, "archive.zip", None), true);
    panel.update(&terminal, Language::En, Event::Working { id: 1 }, true);
    panel.update(&terminal, Language::En, Event::Progress {
        id: 1, completed_bytes: 29, total_bytes: 100,
    }, true);
    let before = row_status(&panel.tasks[&1], 80, Language::En);
    panel.update(&terminal, Language::En, Event::Finalizing { id: 1 }, true);
    assert_eq!(row_status(&panel.tasks[&1], 80, Language::En), before);
    assert!(terminal.output.lock().unwrap().is_empty());
    panel.last_render = None;
    panel.update(&terminal, Language::En, Event::Progress {
        id: 1, completed_bytes: 290, total_bytes: 1000,
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
                    id: 1, completed_bytes: 60, total_bytes: 100,
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
            id,
            result: TaskCompletion { status: TaskStatus::Complete, failure: None, output: Some(path.into()) },
        }, false);
    }
    reports.notify(queued(6, Some(1), "queued.zip", None));
    reports.notify(Event::Finished {
        id: 6,
        result: TaskCompletion { status: TaskStatus::Complete, failure: None,
            output: Some("root/wrapper/leaf/queued".into()) },
    });
    reports.notify(Event::Finished {
        id: 2,
        result: TaskCompletion { status: TaskStatus::Complete, failure: None,
            output: Some("root/wrapper/leaf/nested".into()) },
    });
    let root = std::path::Path::new("root");
    let (old, new) = (std::path::Path::new("root/wrapper/leaf"), std::path::Path::new("leaf"));
    reports.notify(Event::OutputsRelocated { id: 1, root: root.to_owned(), old: old.to_owned(), new: new.to_owned() });
    for event in reports.take_events() {
        panel.update(&terminal, Language::En, event, false);
    }
    for (id, expected) in [(2, "leaf/nested"), (3, "leaf/nested/deep"),
                           (4, "leaf"), (5, "elsewhere/output"), (6, "leaf/queued")] {
        let Phase::Finished(result) = &panel.tasks[&id].phase else { panic!("expected completion for {id}"); };
        assert_eq!(result.output.as_deref(), Some(std::path::Path::new(expected)));
    }
    // Task topology, not the number of unrelated rows or even their path
    // spelling, determines the relocation's visit set.
    let Phase::Finished(result) = &mut panel.tasks.get_mut(&5).unwrap().phase else { panic!("expected completion"); };
    result.output = Some("root/wrapper/leaf/unrelated".into());
    panel.relocate_outputs(1, root, old, new);
    let Phase::Finished(result) = &mut panel.tasks.get_mut(&5).unwrap().phase else { panic!("expected completion"); };
    assert_eq!(result.output.as_deref(),
        Some(std::path::Path::new("root/wrapper/leaf/unrelated")));
    result.output = Some("elsewhere/output".into());
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
        panel.update(&terminal, Language::En, Event::Started { id }, false);
    }
    assert!(terminal.output.lock().unwrap().is_empty());
    assert!(panel.frame.is_none());
    panel.end_batch(&terminal, Language::En, true);
    assert!(!terminal.output.lock().unwrap().is_empty());
    assert_eq!(panel.frame.as_ref().unwrap().rows.len(), 10);
}

#[test]
fn task_preflight_keeps_failed_segments_and_marks_unexecuted_rows_skipped() {
    use crate::pipeline::{Failure, FailureKind};
    let terminal = Terminal { size: (140, 40), output: Mutex::default() };
    let mut panel = Panel::new(false);
    panel.update(&terminal, Language::En, queued(1, None, "carrier.bin", None), true);
    for id in [2, 3] {
        panel.update(&terminal, Language::En, queued(id, Some(1), "carrier.bin", Some(Segment {
            format: "zip".into(), index: id as usize - 1,
            offset: 0, end_offset: None,
        })), true);
        let result = if id == 2 {
            TaskCompletion::failed(&Failure::new(FailureKind::Damaged, "damaged"))
        } else { TaskCompletion { status: TaskStatus::Skipped, failure: None, output: None } };
        panel.update(&terminal, Language::En, Event::Finished {
            id, result,
        }, true);
    }
    panel.update(&terminal, Language::En, Event::Finished {
        id: 1,
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
    panel.tasks.get_mut(&2).unwrap().phase = Phase::Finished(TaskCompletion::failed(
        &Failure::new(FailureKind::FilesystemError, "first\nsecond")));
    let mut text = Vec::new();
    panel.write_scope(1, true, Language::En, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.starts_with("carrier  name\n"));
    assert!(text.contains("first second"));
    assert!(!text.contains('\r'));
    let failure = Failure::new(FailureKind::WrongPassword, "password")
        .with_context(crate::pipeline::FailureContext::Discovery {
            discovery: crate::pipeline::DiscoverySource::Embedded,
            reason: "needs_password".into(), path: "carrier.bin".into(),
        });
    panel.update(&terminal, Language::En, Event::Finished {
        id: 2, result: TaskCompletion::failed(&failure),
    }, true);
    assert!(panel.rows(terminal.size, true, Language::En).iter().any(|row|
        row.id == Some(2) && row.text.contains(&format!("carrier.bin: {}", Language::En.text("failure.password_not_in_list")))));
    // Ordinary input aggregation does not repeat segment details at the carrier.
    panel.update(&terminal, Language::En, Event::Finished {
        id: 1,
        result: TaskCompletion { status: TaskStatus::Failed, failure: None, output: None },
    }, true);
    assert_eq!(panel.rows(terminal.size, true, Language::En).iter().filter(|row| row.id == Some(1)).count(), 2);
    // Parent task_finished formats an otherwise empty password error;
    // only executor segment rows retain the no-detail password convention.
    panel.update(&terminal, Language::En, Event::Finished {
        id: 1,
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
                format: "zip".into(), index: (id - 3) as usize,
                offset: id * 100, end_offset: Some(id * 100 + 50),
            })), false);
            panel.update(&terminal, Language::En, Event::Progress {
                id, completed_bytes: 6, total_bytes: 10,
            }, false);
            panel.update(&terminal, Language::En, Event::Finished {
                id,
                result: TaskCompletion { status,
                    failure: (status == TaskStatus::Partial).then(|| Failure::new(FailureKind::Damaged, "raw")),
                    output: Some(format!("output-{id}").into()),
                },
            }, false);
        }
        panel.update(&terminal, Language::En, Event::Finished {
            id: 3,
            result: TaskCompletion { status: TaskStatus::Failed,
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
            id: 4,
            result: TaskCompletion { status: TaskStatus::Failed,
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
                offset: 100 * index as u64,
                end_offset: Some(100 * index as u64 + 50),
            }),
        ));
    }
    update(Event::Working { id: 2 });
    update(Event::Working { id: 3 });
    update(Event::Progress {
        id: 3,
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
