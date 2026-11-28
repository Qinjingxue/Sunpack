// Format metadata drives reads over shared volume evidence projections.
pub(crate) fn prepare_seven_zip_volume_input(
    head: &InputExtent,
    plan: &Arc<VolumeAttemptPlan>,
    sessions: &[NativeArchiveSession],
) -> Result<PasswordContext, PreparedStatus> {
    // A complete invariant prefix does not depend on inaccessible later parts.
    let prefix = crate::password::input::prefix::common_attempt_prefix(head, plan, sessions);
    use crate::password::input::parse_range_prefix;
    let invariant_start = if !prefix.is_empty() {
        parse_range_prefix(prefix.iter(), sessions, Some(SEVEN_Z_HEADER_SIZE as u64))
            .ok()
            .and_then(|ranges| {
                let mut start = [0; SEVEN_Z_HEADER_SIZE];
                VirtualRangeReader::streaming(&ranges)
                    .read_exact(&mut start)
                    .ok()?;
                let next = RelationNextHeader::parse(&start)?;
                seven_zip_start_header_crc_matches(&start).then_some(next)
            })
    } else {
        None
    };
    if let Some(next) = invariant_start {
        if let Ok(ranges) = parse_range_prefix(prefix.iter(), sessions, Some(next.end())) {
            if VirtualRangeReader::streaming(&ranges).len() == next.end() {
                let evidence = FixedSevenZipEvidence(ranges.into());
                let mut reader = VirtualRangeReader::streaming(&evidence.0);
                return prepare_seven_zip_descriptor(&mut reader, next.end(), next, true, &evidence)
                    .map_err(seven_zip_fixed_input_status)
                    .map(PasswordContext::SevenZip);
            }
        }
    }
    prepare_seven_zip_attempts(head, plan, sessions, invariant_start)
}

fn prepare_seven_zip_attempts(
    head: &InputExtent,
    plan: &Arc<VolumeAttemptPlan>,
    sessions: &[NativeArchiveSession],
    invariant_start: Option<RelationNextHeader>,
) -> Result<PasswordContext, PreparedStatus> {
    use crate::password::input::attempts::{prepare_attempt_evidence_partial, AttemptGeometry};
    let unknown = || {
        PreparedStatus::new(
            "unknown_needs_final_verifier",
            "7z volume password material is unavailable",
        )
    };
    let geometry = if !plan.tail_totals.is_empty() {
        AttemptGeometry::TailTotals
    } else if let Some(total) = plan.head_size_from_total {
        AttemptGeometry::TrimmedHead { total }
    } else {
        AttemptGeometry::Forward {
            logical_limit: invariant_start.map(RelationNextHeader::end),
        }
    };
    let evidence = VolumeEvidence::default();
    let contexts = prepare_attempt_evidence_partial(head, plan, sessions, geometry, |reader| {
        let length = reader.len();
        let (next, supported_start) = match invariant_start {
            Some(next) => (next, true),
            None => {
                let mut start = [0; SEVEN_Z_HEADER_SIZE];
                if length < start.len() as u64 {
                    // The candidate alone does not contain this evidence.
                    return Err(unknown());
                }
                read_exact_field(reader, &mut start, length, "7z.start_header", FieldLocation::Head)?;
                if !start.starts_with(SEVEN_Z_MAGIC) {
                    return Err(unknown());
                }
                if !seven_zip_start_header_crc_matches(&start) {
                    return Ok(None);
                }
                let Some(next) = RelationNextHeader::checked_fields(&start) else {
                    return Ok(None);
                };
                (next, start[6] == 0)
            }
        };
        prepare_seven_zip_descriptor(reader, length, next, supported_start, &evidence)
            .map(Some)
            .or_else(|status| match status {
                PreparedStatus::Status("invalid_volume_evidence", _) => Ok(None),
                status => Err(status),
            })
            .map_err(|status| match status {
                PreparedStatus::Status(_, message) => {
                    PreparedStatus::new("unknown_needs_final_verifier", message)
                }
                status @ PreparedStatus::ReadFault(_) => status,
            })
    })?;
    Ok(contexts.into_context(PasswordContext::SevenZip))
}

use crate::password::input::attempts::{AttemptReader, PackedCrcs};

#[derive(Default)]
struct VolumeEvidence(PackedCrcs);
impl<'a> SevenZipEvidenceReads<AttemptReader<'a>> for VolumeEvidence {
    fn independent<T, E>(
        &self,
        reader: &mut AttemptReader<'a>,
        read: impl FnOnce(&mut AttemptReader<'a>) -> Result<T, E>,
    ) -> Result<T, E> {
        reader.independent_evidence(read)
    }

    fn range_is_ambiguous(&self, reader: &AttemptReader<'a>, start: u64, size: u64) -> bool {
        reader.range_is_ambiguous(start, size)
    }

    fn payload_source(&self, reader: &AttemptReader<'a>) -> Option<SevenZipPayloadSource> {
        Some(SevenZipPayloadSource::Projected(reader.deferred_reads(false)))
    }

    fn has_deferred_source(&self) -> bool {
        true
    }

    fn checks_public_packs(&self) -> bool {
        true
    }

    fn check_packed(
        &self,
        reader: &mut AttemptReader<'a>,
        offset: u64,
        size: u64,
        expected: u32,
    ) -> Result<(), std::borrow::Cow<'static, str>> {
        match reader.packed_matches(offset, size, expected, &self.0) {
            Ok(true) => Ok(()),
            Ok(false) => Err("7z packed stream crc mismatch".into()),
            // Let the preparation reader replay on separated mappings, without
            // reading a password prefix or walking any other descriptor.
            Err(error) => Err(format!("resource_unavailable: {error}").into()),
        }
    }
}
