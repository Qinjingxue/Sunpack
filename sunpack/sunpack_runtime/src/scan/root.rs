//! Root discovery policy for a directory probe or an open logical byte stream.
use crate::analysis_native::volume_anchor::{probe_volume_anchor_prefix, CheapAnchor, VolumeAnchor, ZIP_LOCAL_HEADER};
use crate::formats::StreamFormat;
use crate::io::reader::ManagedReader;
use super::directory::{FILE_ROUTE_DETECTION, FILE_ROUTE_RELATIONS, FILE_ROUTE_RESIDUAL};
use super::embedded::{scan_view_root, NativeScanResult};
use super::pe_overlay::{inspect_pe_image_reader, PeState};
use std::io;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRoute {
    Detection,
    PeImage,
    Complete,
    ArchivePrefix,
    Residual,
}

pub(crate) struct ArchiveRoot {
    pub(crate) anchor: VolumeAnchor,
    pub(crate) scan: Option<NativeScanResult>,
}

impl ArchiveRoot {
    pub(crate) fn read(
        reader: &ManagedReader,
        path: &str,
        selected: bool,
        deep: bool,
        refine_relation: bool,
    ) -> io::Result<Self> {
        let head = reader.read_direct_at(0, 512)?;
        let mut anchor = probe_volume_anchor_prefix(
            VolumeAnchor {
                path: path.to_owned(),
                ..Default::default()
            },
            reader,
            &head,
        );
        if !deep && anchor.pe_state == PeState::Candidate {
            let pe = inspect_pe_image_reader(reader).map_err(|err| err.into_io_error())?;
            anchor.pe_state = pe.state();
            anchor.pe_image_end = pe.image_end();
        }
        let routed = match RootRoute::from_facts(Some(&anchor), None) {
            RootRoute::PeImage => true,
            RootRoute::Detection => selected,
            _ => false,
        };
        let scan = if deep || routed {
            None
        } else {
            let relation = refine_relation.then_some(&mut anchor);
            Some(scan_view_root(reader, &head, relation)?)
        };
        Ok(Self { anchor, scan })
    }

    pub(crate) fn route(&self) -> RootRoute {
        RootRoute::from_facts(Some(&self.anchor), self.scan.as_ref())
    }
}

impl RootRoute {
    pub(crate) fn zip_directory_belongs_to_later_archive(anchor: &VolumeAnchor) -> bool {
        // A leading local record cannot be assigned to a single-disk directory
        // whose recorded offsets put the archive start later in this stream.
        anchor.standalone && anchor.structure_offset == Some(0) && anchor.has_any(ZIP_LOCAL_HEADER)
            && anchor.zip_directory.as_deref().is_some_and(|directory| {
                directory.disk == 0 && directory.cd_disk == 0
                    && directory.offset.checked_add(directory.size)
                        .is_some_and(|end| end < directory.end)
            })
    }

    // A cheap directory snapshot can route a row without opening the source.
    // Only a reader with validated prefix evidence can establish a complete range.
    pub(crate) fn from_facts(anchor: Option<&VolumeAnchor>, scan: Option<&NativeScanResult>) -> Self {
        let Some(anchor) = anchor else { return Self::Residual; };
        if anchor.pe_state == PeState::Confirmed {
            Self::PeImage
        } else if anchor.detection_stream() && scan.is_none() {
            Self::Detection
        } else if scan.is_some_and(|s| s.candidates().iter().any(|c| {
            c.end_offset == Some(anchor.size)
                || (c.offset == 0 && StreamFormat::from_name(c.format).is_some_and(StreamFormat::uses_external_end))
        })) {
            Self::Complete
        } else if anchor.needs_password || anchor.strong && anchor.multivolume
            || scan.is_some_and(NativeScanResult::has_independent_archive)
        {
            Self::ArchivePrefix
        } else {
            Self::Residual
        }
    }

    pub(crate) fn directory_stage(fact: Option<&CheapAnchor>) -> u8 {
        let Some(fact) = fact else { return FILE_ROUTE_RESIDUAL; };
        if let Some(anchor) = fact.anchor() {
            if anchor.pe_state != PeState::None || crate::formats::supports_volume_relations(anchor.format) {
                return FILE_ROUTE_RELATIONS;
            }
            if VolumeAnchor::is_stream_format(anchor.format) { return FILE_ROUTE_DETECTION; }
        }
        if fact.bytes_read() >= 512 && fact.reject_mask() & super::directory::FORMAT_REJECT_TAR == 0 {
            FILE_ROUTE_DETECTION
        } else { FILE_ROUTE_RESIDUAL }
    }
}
