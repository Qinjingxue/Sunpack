use super::*;

/// No I/O and no Python conversions: validate the unique mapping against the
/// head/tail/role facts that the collector already acquired.
pub(super) fn validate(validation: &mut ProposalValidation) {
    if validation.reason.is_some() {
        if validation.anchors.values().any(|a| !a.error.is_empty()) {
            validation.status = ProposalStatus::Reject;
            validation.reason = Some(RelationFailureReason::CorruptArchive);
        } else if validation
            .anchors
            .values()
            .any(|a| a.needs_password || a.wrong_password)
        {
            validation.status = ProposalStatus::NeedsPassword;
            validation.reason = Some(RelationFailureReason::NeedsPassword);
        }
        return;
    }
    let proposal = &validation.proposal;
    let anchors = &validation.anchors;
    let get = |path: &str| anchors.get(&path_key(path));
    if proposal
        .volumes
        .iter()
        .any(|p| get(&p.0).is_some_and(|a| !a.error.is_empty()))
    {
        validation.status = ProposalStatus::Reject;
        validation.reason = Some(RelationFailureReason::CorruptArchive);
        return;
    }
    if proposal
        .volumes
        .iter()
        .any(|p| get(&p.0).is_some_and(|a| a.needs_password || a.wrong_password))
    {
        validation.status = ProposalStatus::NeedsPassword;
        validation.reason = Some(RelationFailureReason::NeedsPassword);
        return;
    }
    validation.status = assignment_status(
        &proposal.format,
        proposal.style == "zip_spanned",
        proposal.volumes.iter().map(|p| (p.1, get(&p.0))),
    );
    // A unique filename mapping is still only a hypothesis until the actual
    // NextHeader extent agrees with the CRC stored in the already-read head.
    if proposal.format == "7z" && validation.status == ProposalStatus::Valid {
        match verify_seven_zip_mapping(validation) {
            Ok(Some(true)) => {
                if let Some(head) = validation
                    .anchors
                    .get_mut(&path_key(&proposal.volumes[0].0))
                {
                    head.evidence.push("7z:mapped_next_header_crc");
                }
            }
            Ok(Some(false)) => {
                validation.status = ProposalStatus::Reject;
                validation.reason = Some(RelationFailureReason::StructuralConflict);
                return;
            }
            Err(_) => {
                validation.status = ProposalStatus::Inconclusive;
                validation.reason = Some(RelationFailureReason::MissingVolume);
                return;
            }
            Ok(None) => {}
        }
    }
    validation.reason = match validation.status {
        ProposalStatus::Valid => None,
        ProposalStatus::Inconclusive => Some(RelationFailureReason::MissingVolume),
        ProposalStatus::Reject => Some(RelationFailureReason::StructuralConflict),
        ProposalStatus::NeedsPassword => Some(RelationFailureReason::NeedsPassword),
        ProposalStatus::Unsupported => Some(RelationFailureReason::Unsupported),
    };
}

fn verify_seven_zip_mapping(validation: &ProposalValidation) -> std::io::Result<Option<bool>> {
    use crate::formats::seven_zip::update_relation_crc;
    let Some(first) = validation
        .proposal
        .volumes
        .first()
        .and_then(|p| validation.anchors.get(&path_key(&p.0)))
    else {
        return Ok(None);
    };
    let Some(next) = first.seven_zip_next_header.as_ref() else {
        return Ok(None);
    };
    let start = next.offset;
    let Some(end) = start.checked_add(next.size) else {
        return Ok(Some(false));
    };
    let last = validation
        .proposal
        .volumes
        .last()
        .and_then(|p| validation.anchors.get(&path_key(&p.0)));
    // The structure-only pass has already checked this exact terminal range.
    if last.is_some_and(|a| a.evidence.contains(&"7z:next_header_crc") && a.size >= next.size) {
        return Ok(Some(true));
    }
    let mut crc = crc32fast::Hasher::new();
    let mut logical = 0u64;
    let mut consumed = 0u64;
    for part in &validation.proposal.volumes {
        let Some(anchor) = validation.anchors.get(&path_key(&part.0)) else {
            return Ok(None);
        };
        let base = anchor.structure_offset.unwrap_or(0);
        let Some(stop) = logical.checked_add(anchor.size.saturating_sub(base)) else {
            return Ok(Some(false));
        };
        let begin = start.max(logical);
        let finish = end.min(stop);
        if begin < finish {
            let reader = crate::io::reader::ManagedReader::open(&part.0)?.probe_reader();
            update_relation_crc(&reader, base + begin - logical, finish - begin, &mut crc)?;
            consumed += finish - begin;
        }
        logical = stop;
    }
    Ok(Some(consumed == next.size && crc.finalize() == next.crc))
}

/// Shared with filename tiers to stop as soon as a complete stronger mapping
/// exists. Borrows the collected anchors; no materialization or cloned cache.
pub(super) fn assignment_status<'a>(
    format: &str,
    spanned: bool,
    parts: impl Iterator<Item = (u32, Option<&'a VolumeAnchor>)> + Clone,
) -> ProposalStatus {
    if parts
        .clone()
        .any(|(_, a)| a.is_some_and(|a| !a.error.is_empty()))
    {
        return ProposalStatus::Reject;
    }
    if parts
        .clone()
        .any(|(_, a)| a.is_some_and(|a| a.needs_password || a.wrong_password))
    {
        return ProposalStatus::NeedsPassword;
    }
    let head = parts.clone().find(|(n, _)| *n == 1).and_then(|(_, a)| a);
    let last_part = parts.clone().last();
    let last = last_part.and_then(|(_, a)| a);
    let status = match format {
        "rar" => {
            let conflict = parts.clone().any(|(number, anchor)| {
                anchor.is_some_and(|a| {
                    a.format != "rar"
                        || a.standalone
                        || a.internal_volume_number.is_some_and(|n| n != number)
                })
            });
            if conflict {
                ProposalStatus::Reject
            } else if head.is_some_and(|a| a.anchor_roles.contains(&"first"))
                && last.is_some_and(|a| a.relation_has_next == Some(false))
            {
                ProposalStatus::Valid
            } else {
                ProposalStatus::Inconclusive
            }
        }
        "7z" => {
            if let Some(first) = head.filter(|a| a.format == "7z" && a.confidence == "strong") {
                let actual = parts.clone().try_fold(0u64, |size, (_, a)| {
                    a.and_then(|a| {
                        size.checked_add(a.size.checked_sub(a.structure_offset.unwrap_or(0))?)
                    })
                });
                let expected = first
                    .expected_logical_size
                    .and_then(|end| end.checked_sub(first.structure_offset.unwrap_or(0)));
                match (expected, actual) {
                    (Some(expected), Some(actual)) if actual == expected => ProposalStatus::Valid,
                    (Some(expected), Some(actual)) if actual > expected => ProposalStatus::Reject,
                    _ => ProposalStatus::Inconclusive,
                }
            } else {
                ProposalStatus::Inconclusive
            }
        }
        "zip" => {
            let terminal_count = parts
                .clone()
                .filter(|(_, a)| a.is_some_and(|a| a.anchor_roles.contains(&"terminal")))
                .count();
            if terminal_count != 1 {
                ProposalStatus::Inconclusive
            } else if spanned {
                if head.is_some_and(|a| {
                    a.evidence.contains(&"zip:split_marker")
                        || a.evidence.contains(&"zip:local_header")
                }) && last.is_some_and(|a| {
                    a.evidence.contains(&"zip:eocd_split_terminal")
                        && a.internal_volume_number == last_part.map(|(n, _)| n)
                }) {
                    ProposalStatus::Valid
                } else {
                    ProposalStatus::Inconclusive
                }
            } else if head.is_some_and(|a| a.evidence.contains(&"zip:local_header"))
                && last.is_some_and(|a| {
                    a.evidence
                        .contains(&"zip:eocd_single_disk_without_local_header")
                })
            {
                ProposalStatus::Valid
            } else {
                ProposalStatus::Inconclusive
            }
        }
        _ => ProposalStatus::Unsupported,
    };
    let mut previous = 0u32;
    let gap = parts.clone().any(|(n, _)| {
        let gap = previous.checked_add(1) != Some(n);
        previous = n;
        gap
    });
    if status == ProposalStatus::Valid && gap {
        ProposalStatus::Inconclusive
    } else {
        status
    }
}
