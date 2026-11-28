//! Exact logical-to-physical mappings. File ownership always stays with the backing reader.
use super::reader::{
    ByteSource, FileIdentity, ManagedReader, PhysicalFileGeneration, ReaderConfig,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::{fs::File, io, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Span {
    pub start: u64,
    pub end: u64,
    pub reverse: bool,
}

impl Span {
    pub(crate) fn join(&mut self, next: &Self) -> bool {
        let single = self.end - self.start == 1;
        let next_single = next.end - next.start == 1;
        if self.end == next.start && (!self.reverse || single) && (!next.reverse || next_single) {
            self.end = next.end;
            self.reverse = false;
            return true;
        }
        if next.end == self.start && (self.reverse || single) && (next.reverse || next_single) {
            self.start = next.start;
            self.reverse = true;
            return true;
        }
        false
    }

    pub(super) fn normalize(&mut self) {
        self.reverse &= self.end - self.start > 1;
    }

    fn append_to(mut self, runs: &mut Vec<Self>) {
        if runs.last_mut().is_some_and(|last| last.join(&self)) { return; }
        self.normalize();
        runs.push(self);
    }
}

// A method implements its cheap signature and one logical-to-physical mapping step.
// Rejection bits share the directory probe word with the low format bits.
macro_rules! mapped_methods {
    ($(($method:ident, $module:ident, $bit:literal, $tag:literal))+) => {
        $(mod $module {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/io/view/", stringify!($module), ".rs"));
        })+
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub(crate) enum ViewMethod { Plain, $(#[serde(rename = $tag)] $method),+ }

        impl ViewMethod {
            const MAPPED: &'static [Self] = &[$(Self::$method),+];

            const fn rejection(self) -> u32 {
                match self { Self::Plain => 0, $(Self::$method => 1 << $bit),+ }
            }
            const fn probe(self) -> ProbeShape {
                match self { Self::Plain => unreachable!(), $(Self::$method => $module::PROBE),+ }
            }
            fn accepts(self, size: u64, prefix: &[u8], suffix: &[u8]) -> bool {
                match self { Self::Plain => unreachable!(), $(Self::$method => $module::accepts(size, prefix, suffix)),+ }
            }
            fn layer(self, file: &ManagedReader, previous: Option<&ReadView>, size: u64, evidence: Option<ProbeBytes>) -> io::Result<Option<Layer>> {
                match self { Self::Plain => unreachable!(), $(Self::$method => $module::layer(file, previous, size, evidence)),+ }
            }
            fn mapped(tag: &str) -> Option<Self> {
                match tag { $($tag => Some(Self::$method)),+, _ => None }
            }
        }
        impl std::fmt::Display for ViewMethod {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(match self { Self::Plain => "plain", $(Self::$method => $tag),+ })
            }
        }
    };
}
include!(concat!(env!("OUT_DIR"), "/read_view_methods.rs"));

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ReadView {
    pub method: ViewMethod,
    pub depth: u32,
    pub physical_size: u64,
    pub spans: Vec<Span>,
    // Live plans pin the generation that supplied the mapping. Recovery
    // already validates persisted source generations against its receipts.
    #[serde(skip)]
    pub(crate) generation: Option<Arc<PhysicalFileGeneration>>,
}

impl PartialEq for ReadView {
    fn eq(&self, other: &Self) -> bool { self.geometry() == other.geometry() }
}

impl Eq for ReadView {}

impl Serialize for ReadView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[cfg(windows)]
        let stamp = self.generation.as_ref().filter(|_| serializer.is_human_readable())
            .map(|generation| generation.worker_stamp());
        #[cfg(not(windows))]
        let stamp: Option<[u64; 4]> = None;
        // The named worker wire carries the live stamp. Compact checkpoints
        // keep their existing layout and validate their group generations.
        let mut view = serializer.serialize_struct("ReadView", 4 + usize::from(stamp.is_some()))?;
        view.serialize_field("method", &self.method)?;
        view.serialize_field("depth", &self.depth)?;
        view.serialize_field("physical_size", &self.physical_size)?;
        view.serialize_field("spans", &self.spans)?;
        if let Some(stamp) = stamp { view.serialize_field("file_generation", &stamp)?; }
        view.end()
    }
}

impl Hash for ReadView {
    fn hash<H: Hasher>(&self, state: &mut H) { self.geometry().hash(state); }
}

impl ReadView {
    fn geometry(&self) -> (ViewMethod, u32, u64, &[Span]) {
        (self.method, self.depth, self.physical_size, &self.spans)
    }

    pub(crate) fn matches_generation(&self, current: Option<&PhysicalFileGeneration>) -> bool {
        self.generation.as_deref().is_none_or(|saved| current.is_some_and(|current| current.matches_input(saved)))
    }

    pub fn len(&self) -> u64 {
        self.spans.iter().map(|s| s.end - s.start).sum()
    }

    // Clip in logical coordinates. Every reported range still refers to the original file.
    pub fn visit(
        &self,
        start: u64,
        end: u64,
        mut visit: impl FnMut(Span) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut base = 0;
        for span in &self.spans {
            let next = base + (span.end - span.start);
            if base >= end {
                break;
            }
            if next > start {
                let a = start.saturating_sub(base);
                let b = end.min(next) - base;
                if a < b {
                    let (lo, hi) = if span.reverse {
                        (span.end - b, span.end - a)
                    } else {
                        (span.start + a, span.start + b)
                    };
                    visit(Span {
                        start: lo,
                        end: hi,
                        reverse: span.reverse,
                    })?;
                }
            }
            base = next;
        }
        Ok(())
    }

    pub(crate) fn read(
        &self,
        file: &ManagedReader,
        offset: u64,
        buf: &mut [u8],
        direct: bool,
    ) -> io::Result<usize> {
        self.read_with(offset, buf, |at, dest| {
            if direct {
                file.read_direct_into_at(at, dest)
            } else {
                file.read_into_at(at, dest)
            }
        })
    }

    fn read_with(
        &self,
        offset: u64,
        buf: &mut [u8],
        mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    ) -> io::Result<usize> {
        let mut pos = 0;
        self.visit(offset, offset.saturating_add(buf.len() as u64), |span| {
            let n = (span.end - span.start) as usize;
            let dest = &mut buf[pos..pos + n];
            let mut done = 0;
            while done < n {
                let count = read(span.start + done as u64, &mut dest[done..])?;
                if count == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                done += count;
            }
            if span.reverse {
                dest.reverse();
            }
            pos += n;
            Ok(())
        })?;
        Ok(pos)
    }

    // Scalar identity for evidence reads contained in one contiguous physical run.
    // A read crossing a boundary keeps its original logical source identity.
    pub(crate) fn single_run(&self, start: u64, len: u64) -> Option<Span> {
        let mut run = None;
        self.visit(start, start.checked_add(len)?, |mut span| {
            if span.end - span.start == len {
                span.normalize();
                run = Some(span);
            }
            Ok(())
        })
        .ok()?;
        run
    }

    pub fn unchanged(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        let mut cursor = start;
        let mapped = self.visit(start, end, |span| {
            if span.reverse && span.end - span.start > 1 || span.start != cursor {
                return Err(io::ErrorKind::InvalidData.into());
            }
            cursor = span.end;
            Ok(())
        });
        mapped.is_ok() && cursor == end
    }

    pub(crate) fn validate_source(&self, physical: &ManagedReader) -> io::Result<()> {
        if physical.len() != self.physical_size {
            return Err(io::Error::other("file size changed after view discovery"));
        }
        if !self.matches_generation(physical.physical_generation()) {
            return Err(io::Error::other("file changed after view discovery"));
        }
        Ok(())
    }

    pub fn bind(self: &Arc<Self>, physical: &ManagedReader) -> io::Result<ManagedReader> {
        self.validate_source(physical)?;
        let len = self
            .spans
            .iter()
            .try_fold(0u64, |n, s| {
                (s.start < s.end && s.end <= self.physical_size)
                    .then(|| n.checked_add(s.end - s.start))
                    .flatten()
            })
            .filter(|n| *n <= self.physical_size)
            .ok_or_else(|| io::Error::other("invalid file view"))?;
        Ok(ManagedReader::new(
            Arc::new(ViewSource {
                file: physical.clone(),
                view: self.clone(),
                len,
            }),
            ReaderConfig::default(),
        ))
    }
}

struct ViewSource {
    file: ManagedReader,
    view: Arc<ReadView>,
    len: u64,
}
impl ByteSource for ViewSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn validate_cached_range(&self, offset: u64, len: usize) -> io::Result<()> {
        // The backing source validates its open generation even on a probe-window hit.
        self.file.validate_cached_range(offset, len)
    }
    fn read_view(&self) -> Option<&Arc<ReadView>> {
        Some(&self.view)
    }
    fn file_identity(&self) -> Option<FileIdentity> {
        self.file.file_identity().ok()
    }
    fn physical_generation(&self) -> Option<&PhysicalFileGeneration> {
        self.file.physical_generation()
    }
    fn read_into_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.view.read(&self.file, offset, buf, false)
    }
    fn read_direct_into_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.view.read(&self.file, offset, buf, true)
    }
    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf =
            super::resource_error::zeroed_bytes(len.min(self.len.saturating_sub(offset) as usize))?;
        self.read_direct_into_at(offset, &mut buf)?;
        Ok(buf)
    }
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf =
            super::resource_error::zeroed_bytes(len.min(self.len.saturating_sub(offset) as usize))?;
        self.read_into_at(offset, &mut buf)?;
        Ok(buf)
    }
}

#[derive(Clone, Copy)]
struct ProbeShape {
    minimum: u64,
    prefix: usize,
    suffix: usize,
}

#[derive(Clone, Copy)]
struct ProbeBytes<'a> {
    prefix: &'a [u8],
    suffix: &'a [u8],
}
impl<'a> ProbeBytes<'a> {
    fn for_method(self, shape: ProbeShape) -> Option<Self> {
        Some(Self {
            prefix: self.prefix.get(..shape.prefix)?,
            suffix: self.suffix.get(self.suffix.len().checked_sub(shape.suffix)?..)?,
        })
    }
}

struct Layer {
    size: u64,
    spans: Vec<Span>,
    // Optional candidate boundary in the parent view's logical coordinates.
    prefix_end: Option<u64>,
}

const fn maximum_probe() -> ProbeShape {
    let mut result = ProbeShape { minimum: 0, prefix: 0, suffix: 0 };
    let mut i = 0;
    let mut bits = 0;
    while i < ViewMethod::MAPPED.len() {
        let method = ViewMethod::MAPPED[i];
        let shape = method.probe();
        let bit = method.rejection();
        assert!(bits & bit == 0 && bit >= (1 << 16));
        assert!(shape.minimum >= shape.prefix as u64 && shape.minimum >= shape.suffix as u64);
        bits |= bit;
        if shape.prefix > result.prefix { result.prefix = shape.prefix; }
        if shape.suffix > result.suffix { result.suffix = shape.suffix; }
        i += 1;
    }
    result
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ViewProbes(u32);

impl ViewProbes {
    // The directory word also carries format rejections below the method bits.
    const PROBED: u32 = 1 << 15;

    pub(crate) fn enabled(self) -> bool { self.0 != 0 }
    pub(crate) fn was_probed(evidence: u32) -> bool { evidence & Self::PROBED != 0 }
    pub(crate) fn has_view_rejection(evidence: u32) -> bool {
        ViewMethod::MAPPED.iter().any(|method| evidence & method.rejection() != 0)
    }

    pub(crate) fn could_derive(self, size: Option<u64>, rejected: u32) -> bool {
        let pending = self.0 & !rejected;
        pending != 0 && ViewMethod::MAPPED.iter().any(|&method|
            pending & method.rejection() != 0 && size.is_none_or(|n| n >= method.probe().minimum))
    }

    pub(crate) fn probe_evidence(self, file: &File, size: u64, prefix: &[u8]) -> u32 {
        if !self.enabled() { return 0; }
        self.probe(size, prefix, |at, buf| super::reader::positional_read(file, buf, at), |rejected, _| rejected | Self::PROBED)
    }

    /// Share prefix/suffix reads on this handle. A short read is inconclusive.
    fn probe<T>(self, size: u64, prefix: &[u8], mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
                finish: impl FnOnce(u32, ProbeBytes) -> T) -> T {
        let mut rejected = 0;
        let mut head_len = 0;
        let mut tail_len = 0;
        for &method in ViewMethod::MAPPED {
            if self.0 & method.rejection() == 0 { continue; }
            let shape = method.probe();
            if size < shape.minimum { rejected |= method.rejection(); }
            else {
                head_len = head_len.max(shape.prefix);
                tail_len = tail_len.max(shape.suffix);
            }
        }
        if rejected == self.0 { return finish(rejected, ProbeBytes { prefix, suffix: &[] }); }

        let mut head = [0; maximum_probe().prefix];
        let prefix = if prefix.len() < head_len {
            head[..prefix.len()].copy_from_slice(prefix);
            let remaining = &mut head[prefix.len()..head_len];
            let read = read(prefix.len() as u64, remaining).unwrap_or(0);
            &head[..prefix.len() + read]
        } else { prefix };
        let mut tail = [0; maximum_probe().suffix];
        let suffix = if prefix.len() as u64 == size {
            &prefix[prefix.len() - tail_len..]
        } else if tail_len == 0 || read(size - tail_len as u64, &mut tail[..tail_len]).ok() == Some(tail_len) {
            &tail[..tail_len]
        } else { &[] };
        let evidence = ProbeBytes { prefix, suffix };
        for &method in ViewMethod::MAPPED {
            let bit = method.rejection();
            if self.0 & !rejected & bit == 0 { continue; }
            if let Some(bytes) = evidence.for_method(method.probe()) {
                if !method.accepts(size, bytes.prefix, bytes.suffix) { rejected |= bit; }
            }
        }
        finish(rejected, evidence)
    }
}

type Selection = (ViewMethod, u32);

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StoredViews")]
pub(crate) struct ConfiguredViews {
    pub(crate) plain: bool,
    methods: Arc<[Selection]>,
    #[serde(skip)]
    probes: ViewProbes,
}

// Earlier Watch indexes stored just the Apate depths in their second field.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredSelection { Method(Selection), ApateDepth(u32) }
#[derive(Deserialize)]
struct StoredViews {
    plain: bool,
    #[serde(alias = "apate_depths")]
    methods: Vec<StoredSelection>,
}
impl TryFrom<StoredViews> for ConfiguredViews {
    type Error = &'static str;
    fn try_from(stored: StoredViews) -> Result<Self, Self::Error> {
        let mut methods = Vec::with_capacity(stored.methods.len());
        for selection in stored.methods {
            let pair = match selection {
                StoredSelection::Method(pair) => pair,
                StoredSelection::ApateDepth(depth) => (ViewMethod::Apate, depth),
            };
            if pair.0 == ViewMethod::Plain || pair.1 == 0 { return Err("invalid saved mapped view"); }
            methods.push(pair);
        }
        Ok(Self::from_methods(stored.plain, methods))
    }
}
impl Default for ConfiguredViews {
    fn default() -> Self { Self::from_methods(true, Vec::new()) }
}

#[derive(Default)]
pub(crate) struct MaskBoundaries {
    ends: Vec<u64>,
    // Plain ends occupy the implicit prefix. The remaining ends have one sorted key
    // each, so an ordinary one-layer mask allocates only the ends array.
    mapped: Vec<Selection>,
}
impl MaskBoundaries {
    fn indices(&self, view: Option<&ReadView>) -> std::ops::Range<usize> {
        let plain = self.ends.len() - self.mapped.len();
        let Some(view) = view else { return 0..plain; };
        let key = (view.method, view.depth);
        let lo = self.mapped.partition_point(|&k| k < key);
        let count = self.mapped[lo..].partition_point(|&k| k == key);
        (plain + lo)..(plain + lo + count)
    }
    fn record(&mut self, parent: Option<&ReadView>, end: u64) {
        if let Some(view) = parent {
            let key = (view.method, view.depth);
            if self.mapped.last().is_none_or(|&last| last < key) {
                self.mapped.push(key);
                self.ends.push(end);
                return;
            }
        }
        let range = self.indices(parent);
        if let Err(i) = self.ends[range.clone()].binary_search(&end) {
            let at = range.start + i;
            if let Some(view) = parent {
                let plain = self.ends.len() - self.mapped.len();
                self.mapped.insert(at - plain, (view.method, view.depth));
            }
            self.ends.insert(at, end);
        }
    }
    pub(crate) fn ends(&self, view: Option<&ReadView>) -> &[u64] { &self.ends[self.indices(view)] }
    pub(crate) fn is_empty(&self) -> bool { self.ends.is_empty() }
}

impl ConfiguredViews {
    pub(crate) fn from_methods(plain: bool, mut methods: Vec<Selection>) -> Self {
        methods.sort_unstable();
        methods.dedup();
        let probes = ViewProbes(methods.iter().fold(0, |bits, &(method, _)| bits | method.rejection()));
        Self { plain, methods: methods.into(), probes }
    }

    pub(crate) fn parse<'a>(tags: impl Iterator<Item = Option<&'a str>>) -> Result<Self, &'static str> {
        let mut plain = false;
        let mut methods = Vec::new();
        for tag in tags {
            let tag = tag.ok_or("unknown filesystem read view")?;
            if tag == "plain" { plain = true; continue; }
            let (name, depth) = tag.split_once(':').ok_or("unknown filesystem read view")?;
            let method = ViewMethod::mapped(name)
                .ok_or("unknown filesystem read view")?;
            let depth = depth.parse::<u32>().ok().filter(|&n| n > 0).ok_or("expected a positive read view depth")?;
            methods.push((method, depth));
        }
        Ok(Self::from_methods(plain, methods))
    }
    pub(crate) fn probes(&self) -> ViewProbes { self.probes }
    pub(crate) fn has_mapped_views(&self) -> bool { self.probes.enabled() }

    /// Share the derivation prefix for all requested depths of each method.
    pub(crate) fn derive_views(&self, physical: &ManagedReader, boundaries: &mut MaskBoundaries) -> io::Result<Vec<Arc<ReadView>>> {
        if self.probes.0.count_ones() > 1 {
            return self.probes.probe(physical.len(), &[], |at, buf| physical.read_direct_into_at(at, buf),
                |rejected, bytes| self.derive(physical, boundaries, rejected, Some(bytes)));
        }
        self.derive(physical, boundaries, 0, None)
    }

    fn derive(&self, physical: &ManagedReader, boundaries: &mut MaskBoundaries, rejected: u32, evidence: Option<ProbeBytes>)
        -> io::Result<Vec<Arc<ReadView>>> {
        let mut result = Vec::<Arc<ReadView>>::new();
        let physical_size = physical.len();
        let mut generation = None;
        for group in self.methods.chunk_by(|a, b| a.0 == b.0) {
            let method = group[0].0;
            if rejected & method.rejection() != 0 { continue; }
            let mut first = evidence.and_then(|bytes| bytes.for_method(method.probe()));
            let mut wanted = group.iter().map(|&(_, depth)| depth).peekable();
            let mut intermediate = None;
            let mut size = physical_size;
            let mut record_boundary = self.plain;
            for depth in 1..=group.last().unwrap().1 {
                if size < method.probe().minimum { break; }
                super::cancellation::Cancellation::check_current_io()?;
                let parent = intermediate.as_ref().or_else(|| {
                    result.last().map(Arc::as_ref).filter(|view| view.method == method && view.depth == depth - 1)
                });
                let Some(layer) = method.layer(physical, parent, size, first.take())? else { break; };
                if record_boundary {
                    if let Some(end) = layer.prefix_end { boundaries.record(parent, end); }
                }
                let mut view = ReadView { method, depth, physical_size, spans: layer.spans, generation: None };
                record_boundary = wanted.peek() == Some(&depth);
                if record_boundary {
                    wanted.next();
                    view.generation = generation.get_or_insert_with(||
                        physical.physical_generation().cloned().map(Arc::new)).clone();
                    result.push(Arc::new(view));
                    intermediate = None;
                } else {
                    intermediate = Some(view);
                }
                size = layer.size;
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/io/view/tests.rs"]
mod tests;
