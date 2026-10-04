use super::*;

/// No I/O and no Python conversions: validate the unique mapping against the
/// head/tail/role facts that the collector already acquired.
pub(super) fn validate(validation: &mut ProposalValidation) {
    if validation.reason.is_some() {
        if validation
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
    let get = |path: &str| anchors.get(&path.to_ascii_lowercase());
    if proposal
        .volumes
        .iter()
        .any(|p| get(&p.0).is_some_and(|a| a.needs_password || a.wrong_password))
    {
        validation.status = ProposalStatus::NeedsPassword;
        validation.reason = Some(RelationFailureReason::NeedsPassword);
        return;
    }
    if proposal
        .volumes
        .iter()
        .any(|p| get(&p.0).is_some_and(|a| !a.error.is_empty()))
    {
        validation.status = ProposalStatus::Reject;
        validation.reason = Some(RelationFailureReason::CorruptArchive);
        return;
    }
    validation.status = assignment_status(
        &proposal.format,
        proposal.style == "zip_spanned",
        proposal.volumes.iter().map(|p| (p.1, get(&p.0))),
    );
    validation.reason = match validation.status {
        ProposalStatus::Valid => None,
        ProposalStatus::Inconclusive => Some(RelationFailureReason::MissingVolume),
        ProposalStatus::Reject => Some(RelationFailureReason::StructuralConflict),
        ProposalStatus::NeedsPassword => Some(RelationFailureReason::NeedsPassword),
        ProposalStatus::Unsupported => Some(RelationFailureReason::Unsupported),
    };
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
        .any(|(_, a)| a.is_some_and(|a| a.needs_password || a.wrong_password))
    {
        return ProposalStatus::NeedsPassword;
    }
    if parts
        .clone()
        .any(|(_, a)| a.is_some_and(|a| !a.error.is_empty()))
    {
        return ProposalStatus::Reject;
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
                    a.and_then(|a| size.checked_add(a.size))
                });
                match (first.expected_logical_size, actual) {
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
