use super::*;
use crate::analysis_native::volume_anchor::{upgrade_relation_rar_end, upgrade_relation_zip_tail};
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SfxRole {
    None,
    ArchiveBearingFirst,
    LauncherCompanion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NumberingStyle {
    RarPart,
    RarOldStyle,
}

#[derive(Debug, Clone)]
pub(super) struct StructuralFacts {
    pub exact_slot: Option<u32>,
    pub first: bool,
    pub terminal: bool,
    pub continues_from_previous: bool,
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
        let continues_from_previous = !first && anchor.is_some_and(|a| {
            a.continuation_from_previous || a.internal_volume_number.is_some_and(|n| n > 1)
        });
        let has_next = anchor.and_then(|a| {
            a.relation_has_next
                .or(terminal.then_some(false))
                .or(a.continuation_to_next.then_some(true))
        });
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
            _ => SfxRole::None,
        };
        Self {
            exact_slot,
            first,
            terminal,
            continues_from_previous,
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
    mut prepared_zip_scan: Option<&mut Option<crate::scan::embedded::PreparedZipScan>>,
) {
    let pe_rows = {
        let mut pe_rows = Vec::new();
        let mut pending = HashMap::new();
        for indexes in index.rows_by_stem.values() {
            for &i in indexes {
                let row = &rows[i];
                if row.anchor.as_ref().is_some_and(|a| {
                    a.pe_state != PeState::None && !a.sfx && !a.has_any(SFX_CHECKED)
                }) {
                    pending.insert((row.path_key.as_str(), row.anchor.as_ref().and_then(|a|a.view.as_deref())), i);
                } else if !pending.is_empty() {
                    // Slices of one physical path share a stem. Keep the last
                    // row's probe decision, including already resolved slices.
                    pending.remove(&(row.path_key.as_str(), row.anchor.as_ref().and_then(|a|a.view.as_deref())));
                }
            }
            pe_rows.extend(pending.drain().map(|(_, i)| i));
        }
        pe_rows
    };
    for i in pe_rows {
        // One managed context supplies PE headers, overlay, stub and archive
        // confirmation. Its existing caches/guard live only through this row.
        let Ok(reader) = rows[i].anchor.as_ref().unwrap().open() else {
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
            let anchor = rows[i].anchor_mut().unwrap();
            anchor.pe_state = probe.state();
            anchor.pe_image_end = probe.image_end();
        }
        if let Some(anchor) = rows[i].anchor.as_deref().and_then(|a| promote_sfx_archive_anchor(a, &reader)) {
            rows[i].anchor = Some(Arc::new(anchor));
        }
        if let Some(anchor) = rows[i].anchor_mut() {
            anchor.flags |= SFX_CHECKED;
        }
        remember_tail_facts(&rows[i], rows[i].anchor.as_ref().unwrap());
    }
    let mut rar = Vec::new();
    let mut zip = Vec::new();
    let mut mapped = false;
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
            mapped |= a.view.is_some();
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
        rows[i].anchor = Some(Arc::new(anchor));
        remember_tail_facts(&rows[i], rows[i].anchor.as_ref().unwrap());
    }
    for indexes in index.rows_by_stem.values() {
        let anchors = || indexes.iter().filter_map(|&i| rows[i].anchor.as_deref());
        let zip_bucket = anchors().any(|a| a.format == "zip" && !a.standalone);
        let terminal = zip_bucket && anchors().any(|a| a.format == "zip" && a.has_any(TERMINAL));
        let mapped_bucket = mapped && terminal && anchors().any(|a| !a.standalone && a.view.is_some());
        if zip_bucket && (!terminal || mapped_bucket) {
            let possible_tails = || indexes.iter().copied().filter(|&i| {
                rows[i].relation_member_eligible
                    && rows[i].anchor.as_ref().is_some_and(|a| {
                        !a.standalone
                            && a.error.is_empty()
                            && a.carrier_limit.is_none()
                            && !a.has_any(TERMINAL | ZIP_CARRIER_CHECKED)
                            && (a.format.is_empty() || a.format == "zip")
                    })
            });
            let known_offset = |i: usize| rows[i].anchor.as_ref().unwrap().zip_eocd_search
                .as_ref().is_some_and(|e| e.unique_offset.is_some());
            // Another archive's visible tail cannot rule out a buried tail.
            let search = !terminal || possible_tails().any(|i| !known_offset(i))
                && (missing_view_zip_tail(rows, indexes) || !zip_heads_have_directory_proof(rows, indexes));
            let candidates: Vec<_> = possible_tails().filter(|&i| search || known_offset(i)).collect();
            if let (Some(prepared), [i], [_]) =
                (prepared_zip_scan.as_deref_mut(), candidates.as_slice(), indexes.as_slice())
            {
                let anchor = rows[*i].anchor.as_ref().unwrap();
                if let Some(generation) = anchor.zip_carrier_scan_generation() {
                    if let Ok(scan) = crate::scan::embedded::PreparedZipScan::scan(
                        &anchor.path, generation.clone(),
                    ) {
                        if scan.zip_eocd_absent() {
                            let mut out = (**anchor).clone();
                            out.mark_zip_eocd_absent(generation.clone());
                            rows[*i].anchor = Some(Arc::new(out));
                        }
                        // A positive signature still goes through Relations'
                        // exact fallback before any Embedded projection.
                        *prepared = Some(scan);
                    }
                }
            }
            let prepared = prepared_zip_scan.as_deref().and_then(Option::as_ref);
            let updates: Vec<_> = candidates
                .par_iter()
                .map(|&i| {
                    let anchor = rows[i].anchor.as_ref().unwrap();
                    let known_eocd = prepared.and_then(|scan| scan.unique_zip_eocd(&anchor.path));
                    (
                        i,
                        crate::analysis_native::volume_anchor::upgrade_relation_zip_carrier_tail(
                            anchor, known_eocd,
                        ),
                    )
                })
                .collect();
            for (i, anchor) in updates {
                rows[i].anchor = Some(Arc::new(anchor));
                remember_tail_facts(&rows[i], rows[i].anchor.as_ref().unwrap());
            }
        }
        refine_zip_members(rows, indexes, None, |_, _| {});
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
                if rows[i].anchor.as_ref().is_some_and(|a| {
                    a.has_any(ZIP_EOCD_HEAD)
                        && a.has_any(ZIP_SINGLE_DISK)
                        && a.expected_logical_size == Some(a.size)
                }) {
                    let a = rows[i].anchor_mut().unwrap();
                    a.standalone = true;
                    a.multivolume = false;
                    a.structure_offset = Some(0);
                }
            }
        }
    }
}

fn missing_view_zip_tail(rows: &[RelationInput], indexes: &[usize]) -> bool {
    let mut heads = [0usize; 2];
    let mut tails = [0usize; 2];
    let candidates = || indexes.iter().map(|&i| &rows[i]).filter(|row| row.relation_member_eligible);
    for row in candidates() {
        if let Some(directory) = zip_terminal_directory(row) {
            tails[usize::from(directory.disk > 0)] += 1;
        } else if let Some(kind) = row.anchor.as_deref().and_then(zip_head_kind) {
            heads[kind] += 1;
        }
    }
    let exceeds = |heads: [usize; 2], tails: [usize; 2]| {
        heads[1] > tails[1] || heads[0] + heads[1] > tails[0] + tails[1]
    };
    let unique_heads = std::cell::OnceCell::new();
    let missing = |tails| exceeds(heads, tails)
        && exceeds(*unique_heads.get_or_init(|| distinct_zip_heads(rows, indexes)), tails);
    if missing(tails) { return true; }
    let [raw, split] = *unique_heads.get().unwrap_or(&heads);
    if raw + split < 2 { return false; }

    // A directory visible through several views covers only one layout.
    // Count the same physical directory identity used by the assignment.
    let mut distinct = HashSet::new();
    tails = [0; 2];
    for row in candidates() {
        if let Some(&directory) = zip_terminal_directory(row) {
            if distinct.insert(zip_directory_key(row, directory)) {
                tails[usize::from(directory.disk > 0)] += 1;
            }
        }
    }
    missing(tails)
}

fn zip_head_kind(anchor: &VolumeAnchor) -> Option<usize> {
    (anchor.format == "zip" && !anchor.standalone && !anchor.has_any(TERMINAL)
        && anchor.has_any(ZIP_LOCAL_HEADER | ZIP_SPLIT_START))
        .then(|| usize::from(anchor.has_any(ZIP_SPLIT_START)))
}

fn zip_heads_have_directory_proof(rows: &[RelationInput], indexes: &[usize]) -> bool {
    let eligible = || indexes.iter().map(|&i| &rows[i]).filter(|row| row.relation_member_eligible);
    let mut heads = eligible().filter_map(|row| {
        let anchor = row.anchor.as_deref()?;
        (anchor.error.is_empty() && !anchor.continuation_from_previous).then_some(())?;
        zip_head_kind(anchor).map(|kind| (anchor, if kind == 1 { 4u64 } else { 0 }))
    }).peekable();
    if heads.peek().is_none() { return true; }

    let mut seen = HashSet::new();
    let mut first_records = HashSet::new();
    for row in eligible() {
        let Some(&directory) = zip_terminal_directory(row) else { continue; };
        if !seen.insert(zip_directory_key(row, directory)) { continue; }
        let anchor = row.anchor.as_ref().unwrap();
        if let Ok(Some(key)) = anchor.open().and_then(|reader| {
            crate::formats::zip::relation_first_local_key(&reader, directory)
        }) {
            first_records.insert(key);
        }
    }
    !first_records.is_empty() && heads.all(|(head, local)| {
        head.structure_offset.unwrap_or(0).checked_add(local).is_some_and(|at| {
            zip_local_key(head, at, None).is_ok_and(|key| key.is_some_and(|key| first_records.contains(&(local, key))))
        })
    })
}

fn distinct_zip_heads(rows: &[RelationInput], indexes: &[usize]) -> [usize; 2] {
    let mut first = HashMap::<_, &VolumeAnchor>::new();
    let mut count = [0, 0];
    for &i in indexes {
        let row = &rows[i];
        if !row.relation_member_eligible { continue; }
        let Some(anchor) = row.anchor.as_deref() else { continue; };
        let Some(kind) = zip_head_kind(anchor) else { continue; };
        let start = anchor.structure_offset.unwrap_or(0);
        match first.entry((&row.path_key, start, kind)) {
            std::collections::hash_map::Entry::Vacant(entry) => { entry.insert(anchor); }
            std::collections::hash_map::Entry::Occupied(entry) => {
                let other = *entry.get();
                let end = anchor.size.min(other.size);
                let prefix_end = start.saturating_add(512).min(end);
                let ranges = |a: &VolumeAnchor, start, end| {
                    crate::io::archive_state::PhysicalRanges::new(a.view.as_deref(), start, Some(end))
                };
                if prefix_end > start && ranges(anchor, prefix_end, end) == ranges(other, prefix_end, end) {
                    if ranges(anchor, start, prefix_end) == ranges(other, start, prefix_end) {
                        continue;
                    }
                    let prefix = |a: &VolumeAnchor| a.open()?.read_direct_at(start, (prefix_end - start) as usize);
                    if let (Ok(left), Ok(right)) = (prefix(anchor), prefix(other)) {
                        if left == right && left.len() as u64 == prefix_end - start { continue; }
                    }
                }
            }
        }
        count[kind] += 1;
    }
    count
}

/// Only byte facts enter the existing generation cell, before any peer-based
/// inference. Embedded offsets and decrypted headers must not replace a cheap
/// head, and concurrent requests must never downgrade a more complete tail.
fn remember_tail_facts(row: &RelationInput, anchor: &Arc<VolumeAnchor>) {
    let checks = SFX_CHECKED | RAR_END_CHECKED | ZIP_TAIL_CHECKED | ZIP_CARRIER_CHECKED;
    if anchor.view.is_some() || !anchor.error.is_empty()
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
        if anchor.zip_eocd_absent_generation().is_some() {
            *cached = Some(CheapAnchor::Full(Arc::clone(anchor)));
        }
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
    *cached = Some(CheapAnchor::Full(Arc::clone(anchor)));
}

pub(super) type ZipLocalKeys<'a> = HashMap<
    (&'a str, Option<&'a crate::io::view::ReadView>, u64),
    Option<crate::formats::zip::RelationLocalKey>,
>;

pub(super) fn zip_local_key(
    a: &VolumeAnchor, at: u64, cached: Option<&ZipLocalKeys<'_>>,
) -> std::io::Result<Option<crate::formats::zip::RelationLocalKey>> {
    if let Some(key) = cached.and_then(|c| c.get(&(a.path.as_str(), a.view.as_deref(), at))) {
        return Ok(key.clone());
    }
    crate::formats::zip::relation_local_key(&a.path, a.view.as_ref(), at)
}

pub(super) fn zip_terminal_directory(row: &RelationInput) -> Option<&crate::formats::zip::RelationDirectory> {
    let anchor = row.anchor.as_ref()?;
    (row.relation_member_eligible && anchor.format == "zip" && !anchor.standalone
        && !anchor.sfx && anchor.error.is_empty() && anchor.has_any(TERMINAL))
        .then_some(anchor.zip_directory.as_deref()).flatten()
}

pub(super) fn zip_directory_key<'a>(row: &'a RelationInput, directory: crate::formats::zip::RelationDirectory)
    -> (&'a str, crate::formats::zip::RelationDirectory, crate::io::archive_state::PhysicalRanges) {
    let view = row.anchor.as_ref().and_then(|a| a.view.as_deref());
    let start = if directory.cd_disk == directory.disk { directory.end.saturating_sub(directory.size) } else { 0 };
    (row.path_key.as_str(), directory, crate::io::archive_state::PhysicalRanges::new(view, start, Some(directory.end)))
}

pub(super) fn refine_zip_members(rows: &mut [RelationInput], indexes: &[usize], cached: Option<&ZipLocalKeys<'_>>,
    mut interior: impl FnMut(&Arc<VolumeAnchor>, u64)) {
    use crate::formats::zip::{visit_relation_directory, RelationLocalFields};
    let mut terminals: Vec<_> = indexes
        .iter()
        .filter_map(|&i| zip_terminal_directory(&rows[i]).map(|&d| (i, d)))
        .collect();
    let Some(&(first, dir)) = terminals.iter().find(|(_, d)| d.disk > 0) else { return; };
    // Root and embedded probes, or several views of a terminal disk, may
    // reference the exact same directory bytes. Walk that directory once
    // while retaining every disk view as a distinct source for payload reads.
    let first_key = std::cell::OnceCell::new();
    let same = |i: usize, d| i == first || (d == dir
        && rows[i].path_key == rows[first].path_key
        && &zip_directory_key(&rows[i], d)
            == first_key.get_or_init(|| zip_directory_key(&rows[first], dir)));
    // Raw and spanned ZIPs or competing mapped directories are refined in
    // their own assignment scopes, so this pass need not read them first.
    if cached.is_none() && terminals.len() > 1
        && (terminals.iter().any(|(_, d)| d.disk == 0)
            || indexes.iter().any(|&i| rows[i].anchor.as_ref()
                .is_some_and(|a| a.view.is_some() && !a.standalone)))
        && terminals.iter().any(|&(i, d)| !same(i, d))
    { return; }
    terminals.retain(|(_, d)| d.disk > 0);
    let unique_directory = terminals.iter().all(|&(i, d)| same(i, d));
    let mut local = HashMap::<Vec<u8>, HashMap<RelationLocalFields, Vec<usize>>>::new();
    for &i in indexes.iter().filter(|_| unique_directory) {
        let Some(a) = rows[i].anchor.as_ref().filter(|a| {
            a.format == "zip"
                && a.error.is_empty()
                && !a.standalone
                && a.has_any(ZIP_LOCAL_HEADER)
        }) else {
            continue;
        };
        match zip_local_key(a, a.structure_offset.unwrap_or(0), cached) {
            Ok(Some(mut key)) => {
                local
                    .entry(std::mem::take(&mut key.name))
                    .or_default()
                    .entry(key.fields)
                    .or_default().push(i);
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
            rows[i].anchor.as_ref().unwrap().open()
                .ok()
                .map(|reader| (i, reader.probe_reader()))
        }
        _ => None,
    };
    for terminal_entry @ &(terminal, directory) in terminals.iter().take(if unique_directory { 1 } else { terminals.len() }) {
        let copies = if unique_directory { terminals.as_slice() } else { std::slice::from_ref(terminal_entry) };
        let mut matches = HashMap::<usize, Option<(u32, u64)>>::new();
        let mut first_local = None::<(u64, crate::formats::zip::RelationLocalKey)>;
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
        let Ok(reader) = rows[terminal].anchor.as_ref().unwrap().open() else { continue };
        let complete =
            visit_relation_directory(&reader, directory, |record, values| {
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

                let fields = RelationLocalFields::new(
                    record.method,
                    record.flags,
                    record.crc32,
                    values.compressed,
                    values.uncompressed,
                );
                if values.disk == 0 && first_local.as_ref().is_none_or(|(at, _)| values.local_offset < *at) {
                    first_local = Some((values.local_offset, crate::formats::zip::RelationLocalKey {
                        name: record.name.to_vec(), fields,
                    }));
                }
                let Some(candidates) = local.get(record.name).and_then(|records| records.get(&fields)) else {
                    return;
                };
                let Some(slot) = u32::try_from(values.disk)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                else {
                    return;
                };
                // Several views can prove the same member of one physical disk.
                // Identical member names on distinct files remain ambiguous.
                if candidates.iter().skip(1).any(|&i| rows[i].path_key != rows[candidates[0]].path_key) {
                    return;
                }
                for &i in candidates {
                    let anchor = rows[i].anchor.as_ref().unwrap();
                    let Some(base) = anchor
                        .structure_offset
                        .unwrap_or(0)
                        .checked_sub(values.local_offset)
                    else {
                        continue;
                    };
                    if anchor
                        .internal_volume_number
                        .is_some_and(|known| known != slot)
                    {
                        continue;
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
                }
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
            for &(i, _) in copies { rows[i].anchor_mut().unwrap().zip_head_size = Some(size); }
            if unique_directory {
                rows[i].anchor_mut().unwrap().payload_end = Some(end);
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
                for &(i, _) in copies { rows[i].anchor_mut().unwrap().structure_offset = Some(base); }
            }
        }
        if !unique_directory {
            continue;
        }
        for (i, slot) in matches {
            if let Some((slot, base)) = slot {
                // A later local header may survive a changed disk prefix. Before
                // promoting its inferred first disk, check the earlier record
                // that the same central directory requires in this view.
                let a = rows[i].anchor.as_ref().unwrap();
                if slot == 1 && a.structure_offset.is_some_and(|at| at > base) {
                    interior(a, base);
                }
                if slot == 1 && first_local.as_ref().is_some_and(|(offset, key)| base.checked_add(*offset).is_some_and(|at| Some(at) != a.structure_offset
                    && !matches!(zip_local_key(a, at, cached), Ok(actual) if actual.as_ref() == Some(key))))
                {
                    continue;
                }
                let a = rows[i].anchor_mut().unwrap();
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
    let mut heads = indexes.iter().filter_map(|&i| {
        let a = rows[i].anchor.as_ref()?;
        (a.format == "7z" && a.multivolume && a.error.is_empty())
            .then_some((&rows[i].path_key, a.structure_offset, **a.seven_zip_next_header.as_ref()?))
    });
    let Some((path, offset, descriptor)) = heads.next() else { return };
    if descriptor.size == 0 || heads.any(|other| other != (path, offset, descriptor)) { return; }
    let mut terminal_path = None;
    let mut terminals = Vec::new();
    for &i in indexes {
        let Some(a) = rows[i].anchor.as_ref().filter(|a| {
            a.error.is_empty() && !a.standalone && a.format.is_empty() && a.size >= descriptor.size
        }) else {
            continue;
        };
        let Ok(reader) = a.open() else {return};
        match crate::formats::seven_zip::relation_header_crc(
            &reader,
            a.size - descriptor.size,
            descriptor,
        ) {
            Ok(Some(true)) => {
                if terminal_path.is_some_and(|path| path != rows[i].path_key) { return; }
                terminal_path = Some(rows[i].path_key.as_str());
                terminals.push(i);
            }
            Err(_) => return,
            _ => {}
        }
    }
    for i in terminals {
        let a = rows[i].anchor_mut().unwrap();
        a.format = "7z";
        a.strong = true;
        a.multivolume = true;
        a.flags |= TERMINAL;
        a.relation_has_next = Some(false);
        a.flags |= SEVEN_ZIP_NEXT_HEADER_CRC;
    }
}
