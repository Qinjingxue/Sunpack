use super::*;
use crate::io::archive_state::VolumeAttemptPlan;
use crate::password::evidence::{remove_paths, EvidenceContext, VolumeProjection};
use crate::password::input::attempts::{prepare_attempt_evidence_partial, AttemptGeometry};
use crate::password::input::VirtualRangeReader;
use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;

pub(super) enum PackedDigest {
    Crc32(u32),
    Blake2sp([u8; 32]),
}

// A successfully decoded header can constrain a native disk. Absent fields
// and a short read never imply disagreement with a neighbouring disk.
#[derive(Default)]
pub(super) struct VolumeFacts {
    pub(super) version: Option<u8>,
    pub(super) native: bool,
    pub(super) header_encrypted: bool,
    pub(super) invalid: bool,
    pub(super) number: Option<u32>,
    pub(super) has_next: Option<bool>,
    packed: Option<Vec<(u64, u64, PackedDigest)>>,
    first: Option<Option<Vec<u8>>>,
    last: Option<Option<Vec<u8>>>,
}

impl VolumeFacts {
    pub(super) fn checks_packed(&self) -> bool {
        self.packed.is_some()
    }

    pub(super) fn file(&mut self, before: bool, after: bool, name: &[u8]) {
        self.first.get_or_insert_with(|| before.then(|| name.to_vec()));
        self.last = Some(after.then(|| name.to_vec()));
    }

    pub(super) fn packed(&mut self, offset: u64, length: u64, digest: PackedDigest) {
        if let Some(spans) = &mut self.packed {
            spans.push((offset, length, digest));
        }
    }
}

// Stream only complete non-final fragments of structurally viable sources.
// Final unpacked checksums and omitted legacy RAR4 CRCs never enter this list.
fn packed_mismatch(spans: &[(u64, u64, PackedDigest)], source: &InputExtent,
    sessions: &[NativeArchiveSession], cancel: &Cancellation) -> bool {
    if spans.is_empty() { return false; }
    let Ok(ranges) = parse_ranges(std::iter::once(source), sessions) else { return false; };
    let mut reader = VirtualRangeReader::streaming(&ranges);
    let mut buffer = Vec::new();
    for &(offset, length, ref expected) in spans {
        if offset.checked_add(length).is_none_or(|end| end > reader.len()) { continue; }
        let mut stream = PackedStream { reader: &mut reader, buffer: &mut buffer, offset, length, cancel };
        let matched = match expected {
            PackedDigest::Crc32(expected) => {
                let mut crc = crc32fast::Hasher::new();
                stream.update(|data| crc.update(data)).then(|| crc.finalize() == *expected)
            }
            PackedDigest::Blake2sp(expected) => stream.blake2sp().map(|actual| actual == *expected),
        };
        if matched == Some(false) { return true; }
    }
    false
}

struct PackedStream<'a, 'ranges> {
    reader: &'a mut VirtualRangeReader<'ranges>,
    buffer: &'a mut Vec<u8>,
    offset: u64,
    length: u64,
    cancel: &'a Cancellation,
}

unsafe extern "C" {
    fn sunpack_blake2sp_run(context: *mut c_void, run: unsafe extern "C" fn(*mut c_void, *mut c_void));
    fn Blake2sp_Update(state: *mut c_void, data: *const u8, size: usize);
    fn Blake2sp_Final(state: *mut c_void, digest: *mut u8);
    fn z7_Black2sp_Prepare();
}

impl PackedStream<'_, '_> {
    fn update(&mut self, mut consume: impl FnMut(&[u8])) -> bool {
        while self.length != 0 {
            if self.cancel.cancelled() { return false; }
            let size = self.length.min(64 * 1024) as usize;
            if self.reader.read_at_into(self.offset, size, self.buffer).is_err() || self.buffer.len() != size {
                return false;
            }
            consume(self.buffer);
            self.offset += size as u64;
            self.length -= size as u64;
        }
        true
    }

    fn blake2sp(&mut self) -> Option<[u8; 32]> {
        static INITIALIZE: std::sync::Once = std::sync::Once::new();
        INITIALIZE.call_once(|| unsafe { z7_Black2sp_Prepare() });
        struct Run<'a, 'stream, 'ranges> {
            stream: &'a mut PackedStream<'stream, 'ranges>,
            digest: Option<[u8; 32]>,
        }
        unsafe extern "C" fn update(context: *mut c_void, state: *mut c_void) {
            // The synchronous shim supplies an aligned, initialized 7-Zip
            // state and keeps it alive across this callback.
            let run = unsafe { &mut *context.cast::<Run<'_, '_, '_>>() };
            if run.stream.update(|data| unsafe { Blake2sp_Update(state, data.as_ptr(), data.len()) }) {
                let mut result = [0; 32];
                unsafe { Blake2sp_Final(state, result.as_mut_ptr()); }
                run.digest = Some(result);
            }
        }
        let mut run = Run { stream: self, digest: None };
        unsafe { sunpack_blake2sp_run((&raw mut run).cast(), update); }
        run.digest
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum State<'a> {
    Bad,
    Clean(Option<Option<&'a [u8]>>),
}

/// Accept exactly paths with a contradictory native slot or adjacent pair.
/// Shared states carry only the preceding split-member name, never a tuple
/// of unrelated disk choices.
fn rejections(plan: &VolumeAttemptPlan, facts: &[VolumeFacts], anchor: Option<&VolumeFacts>, bad: &[bool]) -> VolumeProjection {
    let mut proof = VolumeProjection { roots: Vec::new(), edges: Vec::new(), ends: Vec::new() };
    let mut nodes = 0;
    for (id, layout) in plan.layouts.iter().enumerate() {
        let max = layout.slots.len();
        let min = if layout.minimum_slots == 0 { max } else { layout.minimum_slots };
        for count in (min..=max).rev() {
            let root = nodes;
            nodes += 1;
            let start = proof.edges.len();
            let mut layer = HashMap::from([(State::Clean(None), root)]);
            for ordinal in 0..count {
                let slot = &layout.slots[ordinal];
                let domain = if ordinal + 1 == count { layout.slots[max - 1].domain } else { slot.domain };
                let adjacent = ordinal != 0 && layout.slots[ordinal-1].number.checked_add(1) == Some(slot.number);
                let mut next = HashMap::new();
                for (&state, &from) in &layer {
                    for &source in plan.domains[domain].choices.iter() {
                        let mut state = state;
                        if state != State::Bad {
                            state = if bad.get(source) == Some(&true) { State::Bad }
                            else if let Some(f) = facts.get(source) {
                                let wrong_header = anchor.is_some_and(|a| a.version.is_some() && f.version.is_some() &&
                                    (a.version != f.version || a.header_encrypted != f.header_encrypted));
                                let wrong_pair = matches!(state, State::Clean(Some(previous)) if adjacent &&
                                    f.first.as_ref().is_some_and(|first| first.as_deref() != previous));
                                if f.invalid || wrong_header || f.number.is_some_and(|n| n != slot.number)
                                    || (f.has_next == Some(false) && ordinal + 1 < count) || wrong_pair { State::Bad }
                                else { State::Clean(if f.has_next.is_some() { f.last.as_ref().map(|x| x.as_deref()) } else { None }) }
                            } else { State::Clean(None) };
                        }
                        let to = *next.entry(state).or_insert_with(|| { let n = nodes; nodes += 1; n });
                        proof.edges.push([from, to, source]);
                    }
                }
                layer = next;
            }
            if let Some(&end) = layer.get(&State::Bad) {
                proof.roots.push([id,count,root]);
                proof.ends.push(end);
            } else { proof.edges.truncate(start); }
        }
    }
    proof
}

pub(in crate::password) fn rejected_sources(plan: &VolumeAttemptPlan, bad: &[bool]) -> VolumeProjection {
    rejections(plan, &[], None, bad)
}

pub(super) fn prepare(head: &InputExtent, plan: &VolumeAttemptPlan, sessions: &[NativeArchiveSession], native_volume: bool)
    -> Result<Option<PasswordContext>, PreparedStatus> {
    let cancel = Cancellation::current();
    let inspect = |extent: &InputExtent, check_data: bool| {
        let mut facts = VolumeFacts { packed: check_data.then(Vec::new), ..VolumeFacts::default() };
        let ranges = parse_ranges(std::iter::once(extent), sessions).ok()?;
        let mut reader = VirtualRangeReader::streaming(&ranges);
        let len = reader.len();
        let context = prepare_rar_volume(|offset, size, field| {
            reader.read_at(offset, size).map_err(|err|
                ReadFault::from_io(err, "read_volume", offset, size, 0, len).with_field(field, FieldLocation::Head))
        }, Some(&mut facts), RarRanges::Fixed(&ranges)).ok().map(Arc::new);
        Some((facts, context))
    };
    let Some(head_index) = plan.sources.iter().position(|s| s.path == head.path && s.start == head.start &&
        (s.end == head.end || head.end.is_none())) else { return Ok(None); };
    let Some((anchor, context)) = inspect(&plan.sources[head_index], false) else { return Ok(None); };
    if !native_volume && !anchor.native { return Ok(None); }
    let mut variable = vec![false; plan.sources.len()];
    for domain in &plan.domains {
        if domain.choices.len() > 1 {
            for &id in domain.choices.iter() { variable[id] = true; }
        }
    }
    let mut members: Vec<_> = plan.sources.par_iter().enumerate().map(|(i, s)|
        if i == head_index { Default::default() } else { cancel.run(|| inspect(s, variable[i])).unwrap_or_default() }
    ).collect();
    members[head_index] = (anchor, context);
    cancel.check_io().map_err(|err| PreparedStatus::new("unknown_needs_final_verifier", err.to_string()))?;
    let (facts, materials): (Vec<_>, Vec<_>) = members.into_iter().unzip();
    let public = rejections(plan, &facts, Some(&facts[head_index]), &[]);
    let mut reduced = !public.ends.is_empty();
    let mut remaining = if reduced {
        remove_paths(plan, &[&public]).map_err(|err| PreparedStatus::new("unknown_needs_final_verifier", err.to_string()))?
    } else { plan.clone() };
    let anchor_context = materials[head_index].clone();
    let by_extent: HashMap<_, _> = plan.sources.iter().enumerate().map(|(i,s)| (s,i)).collect();
    let bad: Vec<_> = remaining.sources.par_iter().map(|s| {
        facts[by_extent[s]].packed.as_deref().is_some_and(|spans| packed_mismatch(spans, s, sessions, &cancel))
    }).collect();
    cancel.check_io().map_err(|err| PreparedStatus::new("unknown_needs_final_verifier", err.to_string()))?;
    if bad.iter().any(|&value| value) {
        let rejected = rejected_sources(&remaining, &bad);
        remaining = remove_paths(&remaining, &[&rejected]).map_err(|err| PreparedStatus::new("unknown_needs_final_verifier", err.to_string()))?;
        reduced = true;
    }
    let plan = Arc::new(remaining);
    let materials: Vec<_> = plan.sources.iter().map(|s| materials[by_extent[s]].clone()).collect();
    if plan.layouts.is_empty() || materials.iter().all(Option::is_none) {
        return Ok(Some(PasswordContext::Evidence(EvidenceContext {
            plan, alternatives: Vec::new(), rejected: Vec::new(), public_plan: Default::default(), unresolved: None,
            public_reduced: reduced, independent_rar: Vec::new(), rar_anchor: None,
        })));
    }
    // Native disk methods use their own offset zero and ignore all earlier
    // disk lengths. Read each source once, then branch only on usable proofs.
    let disks: BTreeSet<_> = plan.layouts.iter().flat_map(|l| l.slots.iter().map(|s| (s.number - 1) as usize)).collect();
    let prepared = prepare_attempt_evidence_partial(head, &plan, sessions, AttemptGeometry::DiskRelative, |reader| {
        for strong in [true, false] {
            for &disk in &disks {
                let source = reader.native_proof(disk, |source| materials[source].as_ref().and_then(|ctx| {
                    let is_strong = matches!(ctx.material, RarPasswordMaterial::Rar5(_) | RarPasswordMaterial::Rar5Header { .. });
                    (strong == is_strong).then_some(source)
                })).map_err(|err| PreparedStatus::new("unknown_needs_final_verifier", err.to_string()))?;
                if let Some(source) = source { return Ok(materials[source].clone()); }
            }
        }
        Err(PreparedStatus::new("unknown_needs_final_verifier", "native RAR requires member verification"))
    })?;
    let PasswordContext::Evidence(mut context) = prepared.into_context(PasswordContext::Rar) else { unreachable!() };
    context.public_reduced = reduced;
    // A data-only proof belongs to a member. Testing that password against
    // unrelated files on other disks would falsely reject mixed-password data.
    if facts[head_index].header_encrypted {
        context.independent_rar = materials;
        context.rar_anchor = anchor_context.filter(|c| matches!(c.material, RarPasswordMaterial::Header(_) | RarPasswordMaterial::Rar5Header { .. }));
    }
    Ok(Some(PasswordContext::Evidence(context)))
}
