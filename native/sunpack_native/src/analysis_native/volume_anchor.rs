use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;
use std::sync::OnceLock;

use crc32fast::hash as crc32;
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;

use crate::io::reader::ManagedReader;
use crate::password::rar::{rar4_decrypt_header_flags, rar5_decrypt_main_header};
use crate::analysis_native::structure::unified_prefilter_mask_from_head;

const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf'\x1c";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP_EMPTY: &[u8] = b"PK\x05\x06";
const ZIP_SPLIT_MARKER: &[u8] = b"PK\x07\x08";
const DEFAULT_PREFIX_LIMIT: usize = 1024 * 1024;
const DEFAULT_TAIL_LIMIT: usize = 65_557;
const RAR4_MAIN_HEADER_PASSWORD: u16 = 0x0080;
const VOLUME_ANCHOR_PROBE_THREADS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VolumeAnchorProbeDepth {
    Cheap,
    Deep,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeAnchor {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) format: String,
    pub(crate) confidence: String,
    pub(crate) standalone: bool,
    pub(crate) multivolume: bool,
    pub(crate) encrypted: bool,
    pub(crate) needs_password: bool,
    pub(crate) wrong_password: bool,
    pub(crate) anchor_roles: Vec<&'static str>,
    pub(crate) internal_volume_number: Option<u32>,
    pub(crate) structure_offset: Option<u64>,
    pub(crate) expected_logical_size: Option<u64>,
    pub(crate) continuation_from_previous: bool,
    pub(crate) continuation_to_next: bool,
    pub(crate) sfx: bool,
    pub(crate) evidence: Vec<&'static str>,
    pub(crate) error: String,
    pub(crate) bytes_read: u64,
    pub(crate) format_reject_mask: u32,
}

impl VolumeAnchor {
    fn into_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let out = PyDict::new(py);
        out.set_item("path", self.path)?;
        out.set_item("size", self.size)?;
        out.set_item("format", self.format)?;
        out.set_item("confidence", self.confidence)?;
        out.set_item("standalone", self.standalone)?;
        out.set_item("multivolume", self.multivolume)?;
        out.set_item("encrypted", self.encrypted)?;
        out.set_item("needs_password", self.needs_password)?;
        out.set_item("wrong_password", self.wrong_password)?;
        out.set_item("anchor_roles", PyList::new(py, self.anchor_roles)?)?;
        out.set_item("internal_volume_number", self.internal_volume_number)?;
        out.set_item("structure_offset", self.structure_offset)?;
        out.set_item("expected_logical_size", self.expected_logical_size)?;
        out.set_item(
            "continuation_from_previous",
            self.continuation_from_previous,
        )?;
        out.set_item("continuation_to_next", self.continuation_to_next)?;
        out.set_item("sfx", self.sfx)?;
        out.set_item("evidence", PyList::new(py, self.evidence)?)?;
        out.set_item("error", self.error)?;
        out.set_item("bytes_read", self.bytes_read)?;
        Ok(out.unbind())
    }
}

#[pyfunction]
#[pyo3(signature = (paths, prefix_limit=DEFAULT_PREFIX_LIMIT, tail_limit=DEFAULT_TAIL_LIMIT, path_passwords=None))]
pub(crate) fn probe_volume_anchors(
    py: Python<'_>,
    paths: Vec<String>,
    prefix_limit: usize,
    tail_limit: usize,
    path_passwords: Option<Vec<(String, String)>>,
) -> PyResult<Vec<Py<PyDict>>> {
    py.detach(|| {
        probe_volume_anchor_paths(&paths, prefix_limit, tail_limit, path_passwords.as_deref())
    })
        .into_iter()
        .map(|anchor| anchor.into_dict(py))
        .collect()
}

pub(crate) fn probe_volume_anchor_paths(
    paths: &[String],
    prefix_limit: usize,
    tail_limit: usize,
    path_passwords: Option<&[(String, String)]>,
) -> Vec<VolumeAnchor> {
    probe_volume_anchor_paths_with_depth(
        paths,
        prefix_limit,
        tail_limit,
        path_passwords,
        VolumeAnchorProbeDepth::Deep,
    )
}

pub(crate) fn probe_volume_anchor_paths_cheap(
    paths: &[String],
    path_passwords: Option<&[(String, String)]>,
) -> Vec<VolumeAnchor> {
    probe_volume_anchor_paths_with_depth(
        paths,
        512,
        0,
        path_passwords,
        VolumeAnchorProbeDepth::Cheap,
    )
}

pub(crate) fn probe_volume_anchor_paths_deep(
    paths: &[String],
    prefix_limit: usize,
    tail_limit: usize,
    path_passwords: Option<&[(String, String)]>,
) -> Vec<VolumeAnchor> {
    probe_volume_anchor_paths_with_depth(
        paths,
        prefix_limit,
        tail_limit,
        path_passwords,
        VolumeAnchorProbeDepth::Deep,
    )
}

fn probe_volume_anchor_paths_with_depth(
    paths: &[String],
    prefix_limit: usize,
    tail_limit: usize,
    path_passwords: Option<&[(String, String)]>,
    depth: VolumeAnchorProbeDepth,
) -> Vec<VolumeAnchor> {
    let password_map: HashMap<String, &str> = path_passwords
        .map(|items| {
            items
                .iter()
                .map(|(path, password)| (path.to_ascii_lowercase(), password.as_str()))
                .collect()
        })
        .unwrap_or_default();
    volume_anchor_probe_pool().install(|| {
        paths
            .par_iter()
            .map(|path| {
                probe_path(
                    path,
                    prefix_limit,
                    tail_limit,
                    password_map.get(&path.to_ascii_lowercase()).copied(),
                    depth,
                )
            })
            .collect()
    })
}

fn volume_anchor_probe_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(VOLUME_ANCHOR_PROBE_THREADS)
            .build()
            .expect("volume anchor probe pool must build")
    })
}

fn probe_path(
    path: &str,
    prefix_limit: usize,
    tail_limit: usize,
    password: Option<&str>,
    depth: VolumeAnchorProbeDepth,
) -> VolumeAnchor {
    let mut result = VolumeAnchor {
        path: path.to_string(),
        ..VolumeAnchor::default()
    };
    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            result.error = error.to_string();
            return result;
        }
    };
    let size = reader.len();
    let mut file = reader.cursor();
    result.size = size;
    // Most formats put their identifying structure in the first few hundred
    // bytes.  Only a validated PE/SFX candidate gets the larger prefix window.
    // This keeps the ordinary directory-wide pass at roughly 512 B + ZIP tail
    // rather than reading 1 MiB from every candidate.
    let base_prefix_len = size.min(512) as usize;
    let mut prefix_len = base_prefix_len;
    let mut prefix = vec![0u8; base_prefix_len];
    if let Err(error) = file.read_exact(&mut prefix) {
        result.error = error.to_string();
        return result;
    }
    result.bytes_read += prefix.len() as u64;
    result.format_reject_mask = unified_prefilter_mask_from_head(size, &prefix);

    if depth == VolumeAnchorProbeDepth::Cheap {
        // Relation is a split-volume recovery layer, not a general archive
        // detector.  The cheap pass only keeps structure that can itself seed
        // a split suspicion, plus the leading stream facts that prevent a
        // numbered ordinary archive from being mistaken for a volume.
        if let Some(offset) = anchored_signature(&prefix, RAR5, false)
            .or_else(|| anchored_signature(&prefix, RAR4, false))
            .filter(|offset| probe_rar(&prefix, *offset, &mut result, password))
        {
            let _ = offset;
            return result;
        }
        if let Some(offset) = anchored_signature(&prefix, SEVEN_ZIP, false)
            .filter(|offset| probe_seven_zip(&prefix, *offset, size, &mut result))
        {
            let _ = offset;
            return result;
        }
        if probe_zip_split_marker(&prefix, &mut result) {
            return result;
        }
        if probe_zip_local_head(&prefix, &mut result) {
            return result;
        }
        if probe_embedded_zip_local_head(&prefix, &mut result) {
            return result;
        }
        if prefix.starts_with(b"MZ") {
            // An MZ header is only a weak SFX/carrier seed.  Do not scan a
            // larger prefix here: the relation layer may use the filename
            // proposal to authorize one bounded deep probe later.
            result.confidence = "weak".to_string();
            result.sfx = true;
            result.evidence.push("sfx:pe_header");
            return result;
        }
        probe_standalone_stream(&prefix, &mut result);
        return result;
    }

    let allow_embedded = prefix.starts_with(b"MZ");
    let has_rar4_signature = anchored_signature(&prefix, RAR4, allow_embedded).is_some();
    if (allow_embedded || (password.is_some() && has_rar4_signature))
        && prefix_limit > base_prefix_len
    {
        prefix_len = size.min(prefix_limit as u64) as usize;
    }
    if prefix_len > base_prefix_len {
        prefix.resize(prefix_len, 0);
        if file.seek(SeekFrom::Start(base_prefix_len as u64)).is_err()
            || file.read_exact(&mut prefix[base_prefix_len..]).is_err()
        {
            result.error = "sfx_prefix_read_failed".to_string();
            return result;
        }
        result.bytes_read += (prefix_len - base_prefix_len) as u64;
    }

    // RAR and 7z have all relation-seed structure at the head.  Do not pay
    // the ZIP EOCD tail read for a proposal that has already identified one
    // of these formats; ZIP is the only format below that needs the tail.
    if let Some(offset) = anchored_signature(&prefix, RAR5, allow_embedded)
        .or_else(|| anchored_signature(&prefix, RAR4, allow_embedded))
        .filter(|offset| probe_rar(&prefix, *offset, &mut result, password))
    {
        let _ = offset;
        return result;
    }
    if let Some(offset) = anchored_signature(&prefix, SEVEN_ZIP, allow_embedded)
        .filter(|offset| probe_seven_zip(&prefix, *offset, size, &mut result))
    {
        let _ = offset;
        return result;
    }

    let tail_len = size.min(tail_limit as u64) as usize;
    let tail_start = size.saturating_sub(tail_len as u64);
    let tail = if tail_start == 0 {
        let copied = prefix.len().min(tail_len);
        let mut value = prefix[..copied].to_vec();
        value.resize(tail_len, 0);
        if copied < tail_len {
            if file.seek(SeekFrom::Start(copied as u64)).is_err()
                || file.read_exact(&mut value[copied..]).is_err()
            {
                Vec::new()
            } else {
                result.bytes_read += (tail_len - copied) as u64;
                value
            }
        } else {
            value
        }
    } else {
        let mut value = vec![0u8; tail_len];
        if file.seek(SeekFrom::Start(tail_start)).is_err() || file.read_exact(&mut value).is_err() {
            Vec::new()
        } else {
            result.bytes_read += value.len() as u64;
            value
        }
    };

    if probe_zip(&prefix, &tail, tail_start, &mut result) {
        return result;
    }
    probe_standalone_stream(&prefix, &mut result);
    result
}

fn probe_zip_split_marker(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    if !prefix.starts_with(ZIP_SPLIT_MARKER)
        || !plausible_zip_local(prefix, ZIP_SPLIT_MARKER.len())
    {
        return false;
    }
    out.format = "zip".to_string();
    out.confidence = "strong".to_string();
    out.multivolume = true;
    out.continuation_to_next = true;
    out.structure_offset = Some(0);
    out.internal_volume_number = Some(1);
    out.anchor_roles.push("first");
    out.evidence.push("zip:split_marker");
    true
}

fn probe_zip_local_head(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    if !prefix.starts_with(ZIP_LOCAL) || !plausible_zip_local(prefix, 0) {
        return false;
    }
    out.format = "zip".to_string();
    out.confidence = "weak".to_string();
    out.structure_offset = Some(0);
    out.internal_volume_number = Some(1);
    out.anchor_roles.push("first");
    out.evidence.push("zip:local_header");
    true
}

fn probe_embedded_zip_local_head(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    let Some(offset) = find_signature(prefix, ZIP_LOCAL).filter(|offset| *offset > 0) else {
        return false;
    };
    if !plausible_zip_local(prefix, offset) {
        return false;
    }
    out.format = "zip".to_string();
    out.confidence = "strong".to_string();
    out.standalone = true;
    out.structure_offset = Some(offset as u64);
    out.internal_volume_number = Some(1);
    out.anchor_roles.push("standalone");
    out.anchor_roles.push("first");
    out.evidence.push("zip:embedded_local_head");
    true
}

fn probe_rar(
    prefix: &[u8],
    offset: usize,
    out: &mut VolumeAnchor,
    password: Option<&str>,
) -> bool {
    if prefix
        .get(offset..)
        .is_some_and(|value| value.starts_with(RAR5))
    {
        let header_offset = offset + RAR5.len();
        let Some((archive_flags, number)) = rar5_main_volume(prefix, header_offset) else {
            if !rar5_encryption_header(prefix, header_offset) {
                return false;
            }
            initialize_rar_anchor(out, offset);
            out.encrypted = true;
            if let Some(password) = password {
                // Header-encrypted RAR5 keeps the main-volume flags and number
                // behind encryption.  Decrypt the main header with the
                // probed password so the path behaves exactly like an
                // unencrypted archive: real multivolume state, volume number
                // and first/member/terminal roles.
                if let Some((archive_flags, number)) =
                    rar5_decrypt_main_header(&prefix[offset..], password)
                {
                    out.needs_password = false;
                    out.wrong_password = false;
                    out.multivolume = archive_flags & 0x01 != 0;
                    if out.multivolume {
                        out.internal_volume_number =
                            Some(number.unwrap_or(0).saturating_add(1));
                        out.anchor_roles
                            .push(if number.is_none() { "first" } else { "member" });
                        out.evidence.push("rar5:volume_header");
                    } else {
                        out.standalone = true;
                        out.anchor_roles.push("standalone");
                        out.evidence.push("rar5:single_archive_header");
                    }
                    return true;
                }
                out.wrong_password = true;
                out.evidence.push("rar5:wrong_password");
            } else {
                out.evidence.push("rar5:encryption_header");
            }
            out.needs_password = true;
            out.anchor_roles.push("encrypted_volume");
            return true;
        };
        initialize_rar_anchor(out, offset);
        out.multivolume = archive_flags & 0x01 != 0;
        if out.multivolume {
            out.internal_volume_number = Some(number.unwrap_or(0).saturating_add(1));
            out.anchor_roles
                .push(if number.is_none() { "first" } else { "member" });
            out.evidence.push("rar5:volume_header");
        } else {
            out.standalone = true;
            out.anchor_roles.push("standalone");
            out.evidence.push("rar5:single_archive_header");
        }
    } else if let Some(flags) = rar4_main_flags(prefix, offset + RAR4.len()) {
        initialize_rar_anchor(out, offset);
        // RAR4 MHD_VOLUME and MHD_FIRSTVOLUME.
        out.encrypted = flags & RAR4_MAIN_HEADER_PASSWORD != 0;
        if out.encrypted {
            if let Some(password) = password {
                if rar4_decrypt_header_flags(&prefix[offset..], password).is_some() {
                    out.needs_password = false;
                    out.wrong_password = false;
                    out.evidence.push("rar4:decrypted_header");
                } else {
                    out.wrong_password = true;
                    out.needs_password = true;
                    out.evidence.push("rar4:wrong_password");
                }
            } else {
                out.needs_password = true;
                out.evidence.push("rar4:encrypted_header");
            }
        }
        out.multivolume = flags & 0x0001 != 0;
        if out.multivolume {
            out.anchor_roles.push(if flags & 0x0100 != 0 {
                "first"
            } else {
                "member"
            });
            out.internal_volume_number = (flags & 0x0100 != 0).then_some(1);
            out.evidence.push("rar4:volume_header");
        } else {
            out.standalone = true;
            out.anchor_roles.push("standalone");
            out.evidence.push("rar4:single_archive_header");
        }
    } else if let Some(flags) = password
        .and_then(|password| rar4_decrypt_header_flags(&prefix[offset..], password))
    {
        initialize_rar_anchor(out, offset);
        out.encrypted = true;
        out.evidence.push("rar4:decrypted_header");
        out.multivolume = flags & 0x0001 != 0;
        if out.multivolume {
            out.anchor_roles.push(if flags & 0x0100 != 0 {
                "first"
            } else {
                "member"
            });
            out.internal_volume_number = (flags & 0x0100 != 0).then_some(1);
            out.needs_password = false;
        } else {
            out.standalone = true;
            out.anchor_roles.push("standalone");
        }
    } else {
        return false;
    }
    true
}

fn rar5_encryption_header(data: &[u8], offset: usize) -> bool {
    let Some(stored_crc) = u32_le(data, offset) else {
        return false;
    };
    let Some((header_size, after_size)) = read_vint(data, offset + 4) else {
        return false;
    };
    let Some(total) = after_size
        .checked_sub(offset + 4)
        .and_then(|size_len| 4usize.checked_add(size_len))
        .and_then(|prefix| prefix.checked_add(header_size as usize))
    else {
        return false;
    };
    let Some(end) = offset.checked_add(total) else {
        return false;
    };
    let Some(header) = data.get(offset + 4..end) else {
        return false;
    };
    if crc32(header) != stored_crc {
        return false;
    }
    read_vint(data, after_size).is_some_and(|(header_type, _)| header_type == 4)
}

fn initialize_rar_anchor(out: &mut VolumeAnchor, offset: usize) {
    out.format = "rar".to_string();
    out.confidence = "strong".to_string();
    out.structure_offset = Some(offset as u64);
    out.sfx = offset > 0;
    out.evidence.push(if out.sfx {
        "rar:sfx_signature"
    } else {
        "rar:signature"
    });
    out.anchor_roles.push("any_volume");
}

pub(crate) fn rar5_main_volume(data: &[u8], offset: usize) -> Option<(u64, Option<u32>)> {
    let stored_crc = u32_le(data, offset)?;
    let (header_size, after_size) = read_vint(data, offset + 4)?;
    let total = 4usize
        .checked_add(after_size.checked_sub(offset + 4)?)?
        .checked_add(header_size as usize)?;
    let end = offset.checked_add(total)?;
    let header = data.get(offset + 4..end)?;
    if crc32(header) != stored_crc {
        return None;
    }
    let (header_type, cursor) = read_vint(data, after_size)?;
    if header_type != 1 {
        return None;
    }
    let (header_flags, mut cursor) = read_vint(data, cursor)?;
    if header_flags & 0x01 != 0 {
        cursor = read_vint(data, cursor)?.1;
    }
    if header_flags & 0x02 != 0 {
        cursor = read_vint(data, cursor)?.1;
    }
    let (archive_flags, cursor) = read_vint(data, cursor)?;
    let number = if archive_flags & 0x02 != 0 {
        Some(read_vint(data, cursor)?.0 as u32)
    } else {
        None
    };
    Some((archive_flags, number))
}

fn rar4_main_flags(data: &[u8], offset: usize) -> Option<u16> {
    let stored_crc = u16_le(data, offset)?;
    let header_type = *data.get(offset + 2)?;
    if header_type != 0x73 {
        return None;
    }
    let header_size = u16_le(data, offset + 5)? as usize;
    let header = data.get(offset + 2..offset.checked_add(header_size)?)?;
    if (crc32(header) & 0xffff) as u16 != stored_crc {
        return None;
    }
    u16_le(data, offset + 3)
}

fn probe_seven_zip(prefix: &[u8], offset: usize, size: u64, out: &mut VolumeAnchor) -> bool {
    let Some(header) = prefix.get(offset..offset.saturating_add(32)) else {
        return false;
    };
    let stored_crc = u32::from_le_bytes(header[8..12].try_into().unwrap_or_default());
    if crc32(&header[12..32]) != stored_crc {
        return false;
    }
    out.format = "7z".to_string();
    out.structure_offset = Some(offset as u64);
    out.sfx = offset > 0;
    out.anchor_roles.push("first");
    out.internal_volume_number = Some(1);
    out.evidence.push(if out.sfx {
        "7z:sfx_signature"
    } else {
        "7z:start_signature"
    });
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap_or_default());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap_or_default());
    let logical_size = (offset as u64)
        .saturating_add(32)
        .saturating_add(next_offset)
        .saturating_add(next_size);
    out.expected_logical_size = Some(logical_size);
    out.confidence = "strong".to_string();
    out.evidence.push("7z:start_header_crc");
    if logical_size <= size {
        out.standalone = true;
        out.anchor_roles.push("standalone");
    } else {
        out.multivolume = true;
        out.continuation_to_next = true;
        out.evidence.push("7z:logical_size_exceeds_part");
    }
    true
}

fn probe_zip(prefix: &[u8], tail: &[u8], tail_start: u64, out: &mut VolumeAnchor) -> bool {
    let allow_embedded = prefix.starts_with(b"MZ");
    let split_start_offset = prefix
        .starts_with(ZIP_SPLIT_MARKER)
        .then_some(ZIP_SPLIT_MARKER.len())
        .filter(|offset| plausible_zip_local(prefix, *offset));
    let start_offset = split_start_offset.or_else(|| {
        anchored_signature(prefix, ZIP_LOCAL, allow_embedded)
            .filter(|offset| plausible_zip_local(prefix, *offset))
            .or_else(|| anchored_signature(prefix, ZIP_EMPTY, allow_embedded))
    });
    let empty_eocd_start = split_start_offset.is_none()
        && prefix.starts_with(ZIP_EMPTY)
        && !prefix.starts_with(ZIP_LOCAL);
    let eocd_index = memmem::rfind(tail, ZIP_EOCD).filter(|index| {
        tail.get(index + 20..index + 22)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
            .is_some_and(|comment_len| index + 22 + comment_len == tail.len())
    });
    if start_offset.is_none() && eocd_index.is_none() {
        return false;
    }
    out.format = "zip".to_string();
    out.confidence = "strong".to_string();
    if let Some(offset) = start_offset {
        out.structure_offset = Some(offset as u64);
        out.sfx = offset > 0 && split_start_offset.is_none();
        out.anchor_roles.push("first");
        out.internal_volume_number = Some(1);
        out.evidence.push(if split_start_offset.is_some() {
            "zip:split_marker"
        } else if empty_eocd_start {
            "zip:empty_eocd"
        } else if out.sfx {
            "zip:sfx_local_header"
        } else {
            "zip:local_header"
        });
    }
    let mut split_terminal = false;
    if let Some(index) = eocd_index {
        if let Some(record) = tail.get(index..index + 22) {
            let disk = u16::from_le_bytes([record[4], record[5]]);
            let cd_disk = u16::from_le_bytes([record[6], record[7]]);
            if cd_disk > disk {
                out.error = "invalid_zip_multidisk_order".to_string();
                out.confidence = "unsupported".to_string();
                return true;
            }
            split_terminal = disk != 0 || cd_disk != 0;
            out.anchor_roles.push("terminal");
            out.evidence.push(if split_terminal {
                "zip:eocd_split_terminal"
            } else {
                "zip:eocd_single_disk"
            });
            if split_terminal {
                out.internal_volume_number = Some(u32::from(disk).saturating_add(1));
                if empty_eocd_start {
                    out.anchor_roles.retain(|role| *role != "first");
                    out.structure_offset = None;
                    out.sfx = false;
                    out.continuation_to_next = false;
                }
            }
            out.expected_logical_size = Some(
                tail_start
                    + index as u64
                    + 22
                    + u16::from_le_bytes([record[20], record[21]]) as u64,
            );
        }
    }
    let has_first = start_offset.is_some() && !(split_terminal && empty_eocd_start);
    if has_first && eocd_index.is_some() && !split_terminal {
        out.standalone = true;
        out.anchor_roles.push("standalone");
    } else if eocd_index.is_some() && !split_terminal && start_offset.is_none() {
        // A single-disk EOCD without a visible local header is not enough to
        // prove either standalone content or a split terminal.  Keep it
        // non-multivolume so carrier ZIPs do not block watch, while leaving
        // filename-declared `.zip.00N` members available to Relations.
        out.evidence
            .push("zip:eocd_single_disk_without_local_header");
    } else {
        out.multivolume = true;
        out.continuation_from_previous = eocd_index.is_some();
        out.continuation_to_next = has_first;
    }
    true
}

fn probe_standalone_stream(prefix: &[u8], out: &mut VolumeAnchor) {
    let format = if prefix.starts_with(b"\x1f\x8b") {
        "gzip"
    } else if prefix.starts_with(b"BZh") {
        "bzip2"
    } else if prefix.starts_with(b"\xfd7zXZ\x00") {
        "xz"
    } else if prefix.starts_with(b"\x28\xb5\x2f\xfd") {
        "zstd"
    } else if prefix.starts_with(b"\x1f\x9d") {
        "compress"
    } else if prefix.get(257..262) == Some(b"ustar") {
        "tar"
    } else {
        return;
    };
    out.format = format.to_string();
    out.confidence = "strong".to_string();
    out.standalone = true;
    out.anchor_roles.push("standalone");
    out.anchor_roles.push("first");
    out.evidence.push("stream:leading_structure");
}

fn find_signature(data: &[u8], signature: &[u8]) -> Option<usize> {
    memmem::find(data, signature)
}

fn anchored_signature(data: &[u8], signature: &[u8], allow_embedded: bool) -> Option<usize> {
    if data.starts_with(signature) {
        Some(0)
    } else if allow_embedded {
        find_signature(data, signature)
    } else {
        None
    }
}

fn plausible_zip_local(data: &[u8], offset: usize) -> bool {
    let Some(header) = data.get(offset..offset + 30) else {
        return false;
    };
    let version = u16::from_le_bytes([header[4], header[5]]);
    let method = u16::from_le_bytes([header[8], header[9]]);
    let name_len = u16::from_le_bytes([header[26], header[27]]) as usize;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as usize;
    version <= 1000
        && method <= 99
        && name_len > 0
        && offset
            .checked_add(30 + name_len + extra_len)
            .is_some_and(|end| end <= data.len())
}

fn u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_vint(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *data.get(offset)?;
        offset += 1;
        value |= ((byte & 0x7f) as u64).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar4_main_header_requires_its_stored_crc() {
        let mut header = vec![0u8; 13];
        header[2] = 0x73;
        header[3..5].copy_from_slice(&0x0101u16.to_le_bytes());
        let header_len = header.len() as u16;
        header[5..7].copy_from_slice(&header_len.to_le_bytes());
        let stored = (crc32(&header[2..]) & 0xffff) as u16;
        header[..2].copy_from_slice(&stored.to_le_bytes());

        assert_eq!(rar4_main_flags(&header, 0), Some(0x0101));

        header[8] ^= 0x01;
        assert_eq!(rar4_main_flags(&header, 0), None);
    }

    const SINGLE_HP_HEX: &str = "526172211a07010074de7b1c21040000010f7b64253244702e2a32eb93579555a37d38b616cb97898c463d3682920551724ed0c1c974029cc2b8ef8491fc816311daa1b0410f6115608170466e4948a8c6d4f17e28b08c727b4acfc116d3d075ce011963dc0c72e50a803d9036619810e92352e809830c9463ab4a0abdaab61e008218673e9c51409f76b2064bf7982e56d8173f1e387329bd5aca3bac49063545fcbfc19547d2be214b4fe1dae172b250e168f2a258548930b1763fb500c7869d70f2539d86fd19214dcc3bca1363154b0a0f2b0bba7dcc224ec1893cbc31cfa95158ccf5e96d74921de6f268ea4429e2ddf63d49220005742fef059f868372345f071322a7e690d56d5ac17b563fa9e923076fa2c58aa8e88e9843df17b7e79a30ca936d8215c92f6832f86887c3c3160ecfddfcdf7712382f84f39eb8";
    const PART1_HP_HEX: &str = "526172211a070100ba274f7921040000010fb5b78bc874c2401abc24a83cef823460c50737df44187dc3fa3a8316028f5a16a7ec9cd527eff412f0bd4f8e579a17b4f089c86869ed79e1eda2749f3ec19c16fa0a126c255e5a0ade47c823d3c82ddc00c1c6caebf6506ef16dd177984ee975d3669ff26194eee05db61c51b12d618f31b63f8edfe5828ad2c512093459f242c0b23a51614fe315c307cbdac485";
    const PART2_HP_HEX: &str = "526172211a070100ba274f7921040000010fb5b78bc874c2401abc24a83cef823460c50737df44187dc3fa3a831619b05ee4bf8e2194083d002591665679b4863aed78506ef5d174ab922c0c6c14e872055e0c440d2288a78fca53664503b46b93be4dc1f58098453bfc79bc498cb0cff26cdfadb5a13581c4bc1ae85166bbf4b013ccbd11873b02c45cbc42b8d64ca2effb581d24eddb503087a1cfb8599789";

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn encrypted_single_rar_without_password_is_not_multivolume() {
        let prefix = hex_bytes(SINGLE_HP_HEX);
        let mut anchor = VolumeAnchor::default();
        assert!(probe_rar(&prefix, 0, &mut anchor, None));
        assert!(anchor.encrypted);
        assert!(anchor.needs_password);
        assert!(!anchor.wrong_password);
        assert!(!anchor.multivolume, "encrypted headers must not force multivolume");
        assert!(!anchor.standalone);
        assert!(anchor.anchor_roles.contains(&"encrypted_volume"));
    }

    #[test]
    fn encrypted_single_rar_with_correct_password_is_standalone() {
        let prefix = hex_bytes(SINGLE_HP_HEX);
        let mut anchor = VolumeAnchor::default();
        assert!(probe_rar(&prefix, 0, &mut anchor, Some("secret")));
        assert!(anchor.standalone);
        assert!(!anchor.multivolume);
        assert!(!anchor.needs_password);
        assert!(anchor.anchor_roles.contains(&"standalone"));
    }

    #[test]
    fn encrypted_single_rar_with_wrong_password_reports_wrong_password() {
        let prefix = hex_bytes(SINGLE_HP_HEX);
        let mut anchor = VolumeAnchor::default();
        assert!(probe_rar(&prefix, 0, &mut anchor, Some("wrong")));
        assert!(anchor.encrypted);
        assert!(anchor.needs_password);
        assert!(anchor.wrong_password);
        assert!(!anchor.multivolume);
        assert!(!anchor.standalone);
    }

    #[test]
    fn encrypted_split_rar_uses_decrypted_volume_numbers() {
        let first = hex_bytes(PART1_HP_HEX);
        let second = hex_bytes(PART2_HP_HEX);
        let mut first_anchor = VolumeAnchor::default();
        assert!(probe_rar(&first, 0, &mut first_anchor, Some("secret")));
        assert!(first_anchor.multivolume);
        assert_eq!(first_anchor.internal_volume_number, Some(1));
        assert!(first_anchor.anchor_roles.contains(&"first"));

        let mut second_anchor = VolumeAnchor::default();
        assert!(probe_rar(&second, 0, &mut second_anchor, Some("secret")));
        assert!(second_anchor.multivolume);
        assert_eq!(second_anchor.internal_volume_number, Some(2));
        assert!(second_anchor.anchor_roles.contains(&"member"));
    }
}
