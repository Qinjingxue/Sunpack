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
            "zip" => a.has_any(ZIP_SPLIT_START),
            _ => a.internal_volume_number == Some(1) || a.has_any(FIRST),
        });
        let terminal = anchor.is_some_and(|a| a.has_any(TERMINAL));
        let exact_slot = anchor.and_then(|a| {
            if format == "zip"
                && !a.has_any(ZIP_SPLIT_START)
                && !a.has_any(ZIP_SPLIT_END)
                && !a.has_any(ZIP_DIRECTORY_MEMBER)
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
            if a.has_any(RAR_OLD_NUMBERING) {
                Some(NumberingStyle::RarOldStyle)
            } else if a.has_any(RAR_PART_NUMBERING) {
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
                        || a.has_any(TERMINAL)
                        || a.has_any(ZIP_LOCAL_HEADER))
            }),
        }
    }
}

/// One collection per active bucket. Only encrypted headers and missing tail
/// fields and PE/SFX facts are upgraded. ZIP directory and 7z NextHeader
/// constraints are collected before any filename channel is considered.
pub(super) fn collect(
    rows: &mut [RelationInput],
    index: &BucketIndex,
) {
    let pe_rows: Vec<_> = index
        .entries_by_path
        .values()
        .copied()
        .filter(|i| {
            rows[*i].anchor.as_ref().is_some_and(|a| {
                a.pe_state != PeState::None
                    && !a.sfx
                    && !a.has_any(SFX_CHECKED)
            })
        })
        .collect();
    for i in pe_rows {
        // One managed context supplies PE headers, overlay, stub and archive
        // confirmation. Its existing caches/guard live only through this row.
        let Ok(reader) = crate::io::reader::ManagedReader::open(&rows[i].path) else {
            continue;
        };
        if rows[i]
            .anchor
            .as_ref()
            .is_some_and(|a| a.pe_state == PeState::Candidate)
        {
            // Refine only structure facts. Stage ownership and filesystem routes
            // stay unchanged; the native residual retains this refined anchor.
            let probe = inspect_pe_image_reader(&reader);
            let Ok(probe) = probe else {
                // A transient read error is not evidence against PE identity.
                continue;
            };
            let anchor = rows[i].anchor.as_mut().unwrap();
            anchor.pe_state = probe.state();
            anchor.pe_image_end = probe.image_end();
        }
        if let Some(anchor) = promote_sfx_archive_anchor(&rows[i], &reader) {
            rows[i].anchor = Some(anchor);
        }
        if let Some(anchor) = rows[i].anchor.as_mut() {
            anchor.flags |= SFX_CHECKED;
        }
        remember_tail_facts(&rows[i], rows[i].anchor.as_ref().unwrap());
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
                && !a.has_any(RAR_END_CHECKED)
            {
                rar.push(i);
            }
            if zip_bucket
                && (a.format == "zip" || a.format.is_empty())
                && !a.sfx
                && !a.has_any(TERMINAL)
                && a.carrier_limit.is_none()
                && !a.has_any(ZIP_TAIL_CHECKED)
            {
                zip.push(i);
            }
        }
    }
    let updates = rar
        .par_iter()
        .map(|&i| {
            (
                i,
                upgrade_relation_rar_end(rows[i].anchor.as_ref().unwrap()),
            )
        })
        .chain(zip.par_iter().map(|&i| {
            (
                i,
                upgrade_relation_zip_tail(rows[i].anchor.as_ref().unwrap()),
            )
        }))
        .collect::<Vec<_>>();
    for (i, anchor) in updates {
        remember_tail_facts(&rows[i], &anchor);
        rows[i].anchor = Some(anchor);
    }
    for indexes in index.rows_by_stem.values() {
        let zip_bucket = indexes.iter().any(|&i| {
            rows[i]
                .anchor
                .as_ref()
                .is_some_and(|a| a.format == "zip" && !a.standalone)
        });
        let terminal = indexes.iter().any(|&i| {
            rows[i]
                .anchor
                .as_ref()
                .is_some_and(|a| a.format == "zip" && a.has_any(TERMINAL))
        });
        if zip_bucket && !terminal {
            let candidates: Vec<_> = indexes
                .iter()
                .copied()
                .filter(|&i| {
                    rows[i].relation_member_eligible
                        && rows[i].anchor.as_ref().is_some_and(|a| {
                            !a.standalone
                                && a.error.is_empty()
                                && a.carrier_limit.is_none()
                                && (a.format.is_empty() || a.format == "zip")
                        })
                })
                .collect();
            let updates: Vec<_> = candidates
                .par_iter()
                .map(|&i| {
                    (
                        i,
                        crate::analysis_native::volume_anchor::upgrade_relation_zip_carrier_tail(
                            rows[i].anchor.as_ref().unwrap(),
                        ),
                    )
                })
                .collect();
            for (i, anchor) in updates {
                remember_tail_facts(&rows[i], &anchor);
                rows[i].anchor = Some(anchor);
            }
        }
        refine_zip_members(rows, indexes);
        refine_seven_zip_terminal(rows, indexes);
    }
    for indexes in index.rows_by_stem.values() {
        let raw_head = indexes.iter().any(|i| {
            rows[*i]
                .anchor
                .as_ref()
                .is_some_and(|a| !a.standalone && a.has_any(ZIP_LOCAL_HEADER))
        });
        if !raw_head {
            for &i in indexes {
                if let Some(a) = rows[i].anchor.as_mut().filter(|a| {
                    a.has_any(ZIP_EOCD_HEAD)
                        && a.has_any(ZIP_SINGLE_DISK)
                        && a.expected_logical_size == Some(a.size)
                }) {
                    a.standalone = true;
                    a.multivolume = false;
                    a.structure_offset = Some(0);
                }
            }
        }
    }
}

/// Only byte facts enter the existing generation cell, before any peer-based
/// inference. Embedded offsets and decrypted headers must not replace a cheap
/// head, and concurrent requests must never downgrade a more complete tail.
fn remember_tail_facts(row: &RelationInput, anchor: &VolumeAnchor) {
    let checks = SFX_CHECKED | RAR_END_CHECKED | ZIP_TAIL_CHECKED | ZIP_CARRIER_CHECKED;
    if !anchor.error.is_empty()
        || anchor.encrypted
        || anchor.needs_password
        || anchor.carrier_limit.is_some()
        || anchor.has_any(ZIP_DIRECTORY_MEMBER)
        || !anchor.has_any(checks)
    {
        return;
    }
    let Some(cell) = &row.anchor_cell else {
        return;
    };
    let mut cached = cell.lock().unwrap_or_else(|e| e.into_inner());
    let Some(old) = cached.as_ref() else {
        return;
    };
    let negative;
    let old = match old.anchor() {
        Some(anchor) => anchor,
        None => {
            negative = old.materialize(&row.path, row.size.unwrap_or(0));
            &negative
        }
    };
    if old.path != anchor.path
        || old.size != anchor.size
        || old.structure_offset != anchor.structure_offset
        // A tail-only ZIP must remain an opaque filesystem residual until
        // Relations can pair it with a head, including one inside a carrier.
        || old.format != anchor.format
        || old.encrypted
        || old.needs_password
        || (old.standalone && !anchor.standalone)
        || (old.zip_eocd_offset.is_some() && anchor.zip_eocd_offset.is_none())
        || old.flags & checks & !anchor.flags != 0
        || anchor.flags & checks & !old.flags == 0
    {
        return;
    }
    *cached = Some(crate::analysis_native::volume_anchor::CheapAnchor::Full(
        Arc::new(anchor.clone()),
    ));
}

fn refine_zip_members(rows: &mut [RelationInput], indexes: &[usize]) {
    use crate::formats::zip::{relation_local_key, visit_relation_directory, RelationLocalFields};
    let terminals: Vec<_> = indexes
        .iter()
        .filter_map(|&i| {
            rows[i]
                .anchor
                .as_ref()
                .filter(|a| a.error.is_empty())
                .and_then(|a| a.zip_directory.as_ref())
                .filter(|d| d.disk > 0)
                .map(|d| (i, **d))
        })
        .collect();
    if terminals.is_empty() {
        return;
    }
    let unique_directory = terminals.len() == 1;
    let mut local = HashMap::<Vec<u8>, HashMap<RelationLocalFields, Option<usize>>>::new();
    for &i in indexes.iter().filter(|_| unique_directory) {
        let Some(a) = rows[i].anchor.as_ref().filter(|a| {
            a.format == "zip"
                && a.error.is_empty()
                && !a.standalone
                && a.has_any(ZIP_LOCAL_HEADER)
        }) else {
            continue;
        };
        match relation_local_key(&a.path, a.structure_offset.unwrap_or(0)) {
            Ok(Some(mut key)) => {
                local
                    .entry(std::mem::take(&mut key.name))
                    .or_default()
                    .entry(key.fields)
                    .and_modify(|old| *old = None)
                    .or_insert(Some(i));
            }
            // An unreadable competitor cannot be ruled out of a unique match.
            Err(_) => return,
            Ok(None) => {}
        }
    }
    let mut carriers = indexes.iter().copied().filter(|i| {
        rows[*i].anchor.as_ref().is_some_and(|a| {
            a.carrier_limit.is_some()
                || (a.structure_offset.unwrap_or(0) > 0 && !a.has_any(TERMINAL))
        })
    });
    let carrier = match (carriers.next(), carriers.next()) {
        (Some(i), None) if terminals.iter().any(|(_, d)| d.disk == 1 && d.cd_disk == 1) => {
            crate::io::reader::ManagedReader::open(&rows[i].path)
                .ok()
                .map(|reader| (i, reader.probe_reader()))
        }
        _ => None,
    };
    for (terminal, directory) in terminals {
        let mut matches = HashMap::<usize, Option<(u32, u64)>>::new();
        // Two-disk ZIPs may have no intermediate disk to establish split size.
        // Declared member ends minus the continuation on disk two locate the
        // first disk. Keep competing tails' results separate until selection.
        let carrier = carrier
            .as_ref()
            .filter(|_| directory.disk == 1 && directory.cd_disk == 1)
            .map(|(i, reader)| (*i, rows[*i].anchor.as_ref().unwrap(), reader));
        let mut carrier_end = Some(0u64);
        let mut carrier_entries = 0u64;
        let mut all_first_disk = true;
        let complete =
            visit_relation_directory(&rows[terminal].path, directory, |record, values| {
                all_first_disk &= values.disk == 0;
                if values.disk == 0 {
                    if let Some((_, a, reader)) = &carrier {
                        carrier_entries += 1;
                        carrier_end = carrier_end.and_then(|end| {
                            crate::formats::zip::relation_member_end(
                                reader,
                                a.structure_offset.unwrap_or(0),
                                a.carrier_limit.unwrap_or(a.size),
                                record,
                                &values,
                            )
                            .ok()
                            .flatten()
                            .map(|next| end.max(next))
                        });
                    }
                }
                // Competing directories retain their own carrier geometry. They must
                // not promote a conditional disk identity into a shared row fact.
                if !unique_directory {
                    return;
                }
                // A scanned local header may follow carrier padding or continuation
                // data. Directory disk offsets locate the physical disk's real base.
                if record.flags & 0x2000 != 0 {
                    return;
                }
                let Some(candidates) = local.get(record.name) else {
                    return;
                };
                let fields = RelationLocalFields::new(
                    record.method,
                    record.flags,
                    record.crc32,
                    values.compressed,
                    values.uncompressed,
                );
                let Some(&Some(i)) = candidates.get(&fields) else {
                    return;
                };
                let Some(slot) = u32::try_from(values.disk)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                else {
                    return;
                };
                let anchor = rows[i].anchor.as_ref().unwrap();
                let Some(base) = anchor
                    .structure_offset
                    .unwrap_or(0)
                    .checked_sub(values.local_offset)
                else {
                    return;
                };
                if anchor
                    .internal_volume_number
                    .is_some_and(|known| known != slot)
                {
                    return;
                }
                let identity = (slot, base);
                matches
                    .entry(i)
                    .and_modify(|old| {
                        if *old != Some(identity) {
                            *old = None;
                        }
                    })
                    .or_insert(Some(identity));
            });
        if !matches!(complete, Ok(true)) {
            continue;
        }
        let carrier_extent = carrier.and_then(|(i, _, _)| {
            carrier_end
                .filter(|_| carrier_entries > 0 && all_first_disk)
                .and_then(|end| end.checked_sub(directory.offset))
                .filter(|end| {
                    *end > rows[i]
                        .anchor
                        .as_ref()
                        .unwrap()
                        .structure_offset
                        .unwrap_or(0)
                })
                .and_then(|end| {
                    let a = rows[i].anchor.as_ref().unwrap();
                    let size = end - a.structure_offset.unwrap_or(0);
                    validate::spanned_carrier_end(a, std::iter::once(size))
                        .map(|end| (i, end, size))
                })
        });
        if let Some((i, end, size)) = carrier_extent {
            rows[terminal].anchor.as_mut().unwrap().zip_head_size = Some(size);
            if unique_directory {
                rows[i].anchor.as_mut().unwrap().payload_end = Some(end);
            }
        }
        // Terminal directory geometry independently locates its disk base even
        // when that disk begins in the middle of a member's compressed bytes.
        if directory.cd_disk == directory.disk {
            if let Some(base) = directory
                .end
                .checked_sub(directory.size)
                .and_then(|n| n.checked_sub(directory.offset))
            {
                rows[terminal].anchor.as_mut().unwrap().structure_offset = Some(base);
            }
        }
        if !unique_directory {
            continue;
        }
        for (i, slot) in matches {
            if let Some((slot, base)) = slot {
                let a = rows[i].anchor.as_mut().unwrap();
                a.internal_volume_number = Some(slot);
                a.structure_offset = Some(base);
                a.strong = true;
                a.multivolume = true;
                a.continuation_from_previous = slot > 1;
                a.flags |= ZIP_DIRECTORY_MEMBER;
            }
        }
    }
}

fn refine_seven_zip_terminal(rows: &mut [RelationInput], indexes: &[usize]) {
    let heads: Vec<_> = indexes
        .iter()
        .filter_map(|&i| {
            rows[i]
                .anchor
                .as_ref()
                .filter(|a| a.format == "7z" && a.multivolume && a.error.is_empty())
                .and_then(|a| a.seven_zip_next_header.as_ref().map(|h| **h))
        })
        .collect();
    if heads.len() != 1 || heads[0].size == 0 {
        return;
    }
    let descriptor = heads[0];
    let mut terminal = None;
    for &i in indexes {
        let Some(a) = rows[i].anchor.as_ref().filter(|a| {
            a.error.is_empty() && !a.standalone && a.format.is_empty() && a.size >= descriptor.size
        }) else {
            continue;
        };
        match crate::formats::seven_zip::relation_header_crc(
            &a.path,
            a.size - descriptor.size,
            descriptor,
        ) {
            Ok(Some(true)) => {
                if terminal.replace(i).is_some() {
                    return;
                }
            }
            Err(_) => return,
            _ => {}
        }
    }
    if let Some(i) = terminal {
        let a = rows[i].anchor.as_mut().unwrap();
        a.format = "7z";
        a.strong = true;
        a.multivolume = true;
        a.flags |= TERMINAL;
        a.relation_has_next = Some(false);
        a.flags |= SEVEN_ZIP_NEXT_HEADER_CRC;
    }
}
