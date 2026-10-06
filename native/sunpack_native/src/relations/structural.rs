use super::*;
use crate::analysis_native::volume_anchor::{upgrade_relation_rar_end, upgrade_relation_zip_tail};
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VolumeRole {
    First,
    Middle,
    Terminal,
    FirstAndTerminal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SfxRole {
    None,
    ArchiveBearingFirst,
    LauncherCompanion,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NumberingStyle {
    RarPart,
    RarOldStyle,
}

#[derive(Debug, Clone)]
pub(super) struct StructuralFacts {
    pub exact_slot: Option<u32>,
    pub role: VolumeRole,
    pub has_previous: Option<bool>,
    pub has_next: Option<bool>,
    pub numbering_style: Option<NumberingStyle>,
    pub sfx_role: SfxRole,
    pub owned: bool,
}

impl StructuralFacts {
    pub fn from_row(row: &RelationInput, format: &str) -> Self {
        let anchor = row.anchor.as_ref().filter(|a| a.format == format);
        let first = anchor.is_some_and(|a| match format {
            "zip" => a.evidence.contains(&"zip:split_marker"),
            _ => a.internal_volume_number == Some(1) || a.anchor_roles.contains(&"first"),
        });
        let terminal = anchor.is_some_and(|a| a.anchor_roles.contains(&"terminal"));
        let exact_slot = anchor.and_then(|a| {
            if format == "zip"
                && !a.evidence.contains(&"zip:split_marker")
                && !a.evidence.contains(&"zip:eocd_split_terminal")
            {
                None
            } else {
                a.internal_volume_number.or(first.then_some(1))
            }
        });
        let has_previous = anchor.and_then(|a| {
            if first {
                Some(false)
            } else if a.continuation_from_previous
                || a.internal_volume_number.is_some_and(|n| n > 1)
            {
                Some(true)
            } else {
                None
            }
        });
        let has_next = anchor.and_then(|a| {
            a.relation_has_next
                .or(terminal.then_some(false))
                .or(a.continuation_to_next.then_some(true))
        });
        let role = match (first, terminal, has_previous, has_next) {
            (true, true, _, _) => VolumeRole::FirstAndTerminal,
            (true, _, _, _) => VolumeRole::First,
            (_, true, _, _) => VolumeRole::Terminal,
            (_, _, Some(true), Some(true)) => VolumeRole::Middle,
            _ => VolumeRole::Unknown,
        };
        let numbering_style = anchor.and_then(|a| {
            if a.evidence.contains(&"rar4:old_volume_naming") {
                Some(NumberingStyle::RarOldStyle)
            } else if a.evidence.contains(&"rar4:new_volume_naming")
                || a.evidence.contains(&"rar5:volume_header")
            {
                Some(NumberingStyle::RarPart)
            } else {
                None
            }
        });
        let sfx_role = match row.anchor.as_ref() {
            Some(a) if a.sfx && a.pe_state == PeState::Confirmed && a.format.is_empty() => {
                SfxRole::LauncherCompanion
            }
            Some(a)
                if format == "rar"
                    && a.sfx
                    && a.pe_state == PeState::Confirmed
                    && a.format == format
                    && a.multivolume
                    && first =>
            {
                SfxRole::ArchiveBearingFirst
            }
            Some(a) if a.sfx => SfxRole::Unknown,
            _ => SfxRole::None,
        };
        Self {
            exact_slot,
            role,
            has_previous,
            has_next,
            numbering_style,
            sfx_role,
            owned: anchor.is_some_and(|a| {
                !a.standalone
                    && (a.multivolume
                        || a.needs_password
                        || a.anchor_roles.contains(&"terminal")
                        || a.evidence.contains(&"zip:local_header"))
            }),
        }
    }
}

/// One collection per active bucket. Only encrypted headers and missing tail
/// fields and PE/SFX facts are upgraded. Opaque 7z continuations do no I/O.
pub(super) fn collect(
    py: Python<'_>,
    rows: &mut [RelationInput],
    index: &BucketIndex,
    passwords: Option<&[(String, String)]>,
) -> PyResult<()> {
    let password_map: HashMap<_, _> = passwords
        .into_iter()
        .flatten()
        .map(|(p, password)| (p.to_ascii_lowercase(), password.as_str()))
        .collect();
    let encrypted: Vec<_> = index
        .entries_by_path
        .values()
        .filter_map(|i| {
            let row = &rows[*i];
            (row.anchor
                .as_ref()
                .is_some_and(|a| a.needs_password && a.structure_offset.unwrap_or(0) == 0)
                && password_map.contains_key(&row.path_key))
            .then_some(row.path.clone())
        })
        .collect();
    if !encrypted.is_empty() {
        let upgraded = py.detach(|| probe_volume_anchor_paths_cheap(&encrypted, passwords));
        for anchor in upgraded {
            if let Some(i) = index.entries_by_path.get(&anchor.path.to_ascii_lowercase()) {
                // Embedded SFX headers need their known archive offset.
                if rows[*i]
                    .anchor
                    .as_ref()
                    .is_some_and(|a| a.structure_offset.unwrap_or(0) > 0)
                {
                    continue;
                }
                rows[*i].anchor = Some(anchor);
            }
        }
    }
    for &i in index.entries_by_path.values() {
        if let Some(anchor) = rows[i]
            .anchor
            .as_ref()
            .filter(|a| a.needs_password && a.structure_offset.unwrap_or(0) > 0)
        {
            if let Some(password) = password_map.get(&rows[i].path_key) {
                let mut upgraded = py.detach(|| {
                    probe_volume_anchor_at_offset(
                        &rows[i].path,
                        anchor.structure_offset.unwrap(),
                        &anchor.format,
                        Some(password),
                    )
                });
                upgraded.pe_state = anchor.pe_state;
                upgraded.pe_image_end = anchor.pe_image_end;
                upgraded.sfx = anchor.sfx;
                rows[i].anchor = Some(upgraded);
            }
        }
    }
    let pe_rows: Vec<_> = index
        .entries_by_path
        .values()
        .copied()
        .filter(|i| {
            rows[*i].anchor.as_ref().is_some_and(|a| {
                a.pe_state != PeState::None
                    && !a.sfx
                    && !a.evidence.contains(&"relation:sfx_checked")
            })
        })
        .collect();
    for i in pe_rows {
        if rows[i]
            .anchor
            .as_ref()
            .is_some_and(|a| a.pe_state == PeState::Candidate)
        {
            // Refine only structure facts. Stage ownership and filesystem routes
            // stay unchanged; the native residual retains this refined anchor.
            let probe = py.detach(|| inspect_pe_image_native(&rows[i].path));
            let Ok(probe) = probe else {
                // A transient read error is not evidence against PE identity.
                continue;
            };
            let anchor = rows[i].anchor.as_mut().unwrap();
            anchor.pe_state = probe.state();
            anchor.pe_image_end = probe.image_end();
        }
        if let Some(anchor) = promote_sfx_archive_anchor(py, &rows[i], passwords)? {
            rows[i].anchor = Some(anchor);
        }
        if let Some(anchor) = rows[i].anchor.as_mut() {
            anchor.evidence.push("relation:sfx_checked");
        }
    }
    let mut rar = Vec::new();
    let mut zip = Vec::new();
    for indexes in index.rows_by_stem.values() {
        let zip_bucket = indexes.iter().any(|i| {
            rows[*i]
                .anchor
                .as_ref()
                .is_some_and(|a| a.format == "zip" && !a.standalone)
        });
        for &i in indexes {
            let Some(a) = &rows[i].anchor else {
                continue;
            };
            if !rows[i].relation_member_eligible || a.standalone {
                continue;
            }
            if a.format == "rar"
                && !a.needs_password
                && a.relation_has_next.is_none()
                && !a.evidence.contains(&"relation:rar_end_checked")
            {
                rar.push(i);
            }
            if zip_bucket
                && (a.format == "zip" || a.format.is_empty())
                && !a.sfx
                && !a.anchor_roles.contains(&"terminal")
                && !a.evidence.contains(&"relation:zip_tail_checked")
            {
                zip.push(i);
            }
        }
    }
    let updates = py.detach(|| {
        rar.par_iter()
            .map(|&i| {
                (
                    i,
                    upgrade_relation_rar_end(
                        rows[i].anchor.as_ref().unwrap(),
                        password_map.get(&rows[i].path_key).copied(),
                    ),
                )
            })
            .chain(zip.par_iter().map(|&i| {
                (
                    i,
                    upgrade_relation_zip_tail(rows[i].anchor.as_ref().unwrap()),
                )
            }))
            .collect::<Vec<_>>()
    });
    for (i, anchor) in updates {
        rows[i].anchor = Some(anchor);
    }
    for indexes in index.rows_by_stem.values() {
        let raw_head = indexes.iter().any(|i| {
            rows[*i]
                .anchor
                .as_ref()
                .is_some_and(|a| !a.standalone && a.evidence.contains(&"zip:local_header"))
        });
        if !raw_head {
            for &i in indexes {
                if let Some(a) = rows[i].anchor.as_mut().filter(|a| {
                    a.evidence.contains(&"zip:eocd_head")
                        && a.evidence.contains(&"zip:eocd_single_disk")
                        && a.expected_logical_size == Some(a.size)
                }) {
                    a.standalone = true;
                    a.multivolume = false;
                    a.structure_offset = Some(0);
                    a.anchor_roles.push("standalone");
                }
            }
        }
    }
    Ok(())
}
