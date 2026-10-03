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
    let head = proposal
        .volumes
        .iter()
        .find(|p| p.1 == 1)
        .and_then(|p| get(&p.0));
    let last = proposal.volumes.last().and_then(|p| get(&p.0));
    let status = match proposal.format.as_str() {
        "rar" => {
            let conflict = proposal.volumes.iter().any(|p| {
                get(&p.0).is_some_and(|a| {
                    a.format != "rar"
                        || a.standalone
                        || a.internal_volume_number.is_some_and(|n| n != p.1)
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
                let actual = proposal.volumes.iter().try_fold(0u64, |size, p| {
                    get(&p.0).and_then(|a| size.checked_add(a.size))
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
            let terminal_count = proposal
                .volumes
                .iter()
                .filter(|p| get(&p.0).is_some_and(|a| a.anchor_roles.contains(&"terminal")))
                .count();
            if terminal_count != 1 {
                ProposalStatus::Inconclusive
            } else if proposal.style == "zip_spanned" {
                if head.is_some_and(|a| {
                    a.evidence.contains(&"zip:split_marker")
                        || a.evidence.contains(&"zip:local_header")
                }) && last.is_some_and(|a| {
                    a.evidence.contains(&"zip:eocd_split_terminal")
                        && a.internal_volume_number == proposal.volumes.last().map(|p| p.1)
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
    validation.status = if status == ProposalStatus::Valid && proposal_has_gap(proposal) {
        ProposalStatus::Inconclusive
    } else {
        status
    };
    validation.reason = match validation.status {
        ProposalStatus::Valid => None,
        ProposalStatus::Inconclusive => Some(RelationFailureReason::MissingVolume),
        ProposalStatus::Reject => Some(RelationFailureReason::StructuralConflict),
        ProposalStatus::NeedsPassword => Some(RelationFailureReason::NeedsPassword),
        ProposalStatus::Unsupported => Some(RelationFailureReason::Unsupported),
    };
}
