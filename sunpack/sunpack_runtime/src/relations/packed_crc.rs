//! Public 7z packed checksums for the candidate projection. Cache physical
//! segment CRCs only while assembling one plan, including projection replays.
use super::{AttemptReader, AttemptSource, Cancellation, Topology};
use crate::io::cancellation::CancellableOnce;
use crc32fast::Hasher;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

type Segment = (usize, u64, u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Digest {
    Crc(u32),
    Truncated,
    Unavailable,
}

#[derive(Default)]
pub(crate) struct PackedCrcs {
    digests: Mutex<HashMap<Segment, Arc<CancellableOnce<Digest>>>>,
    by_start: OnceLock<Box<[(u64, usize)]>>,
}

impl PackedCrcs {
    fn edges(&self, graph: &Topology, start: u64) -> &[(u64, usize)] {
        let sorted = self.by_start.get_or_init(|| {
            let mut edges: Vec<_> = graph.edges.iter().enumerate()
                .filter(|(_, edge)| edge.start < edge.end)
                .map(|(index, edge)| (edge.start, index))
                .collect();
            edges.sort_unstable();
            let mut max_end = 0;
            for (end, index) in &mut edges {
                max_end = max_end.max(graph.edges[*index].end);
                *end = max_end;
            }
            edges.into()
        });
        &sorted[sorted.partition_point(|&(end, _)| end <= start)..]
    }

    fn segment(&self, key: Segment, source: &AttemptSource, cancel: &Cancellation) -> Digest {
        let slot = Arc::clone(self.digests.lock().unwrap_or_else(|err| err.into_inner()).entry(key).or_default());
        slot.get_or_init(cancel, || digest_range(source, key.1, key.2, cancel))
            .copied().unwrap_or(Digest::Unavailable)
    }
}

fn digest_range(source: &AttemptSource, mut offset: u64, mut remaining: u64, cancel: &Cancellation) -> Digest {
    let Ok(reader) = source.file.open() else {
        return Digest::Unavailable;
    };
    let mut crc = Hasher::new();
    let mut buffer = [0; 64 * 1024];
    while remaining != 0 {
        if cancel.cancelled() {
            return Digest::Unavailable;
        }
        let size = remaining.min(buffer.len() as u64) as usize;
        match reader.read_direct_into_at(offset, &mut buffer[..size]) {
            Ok(0) => return Digest::Truncated,
            Ok(count) => {
                crc.update(&buffer[..count]);
                offset += count as u64;
                remaining -= count as u64;
            }
            Err(_) => return Digest::Unavailable,
        }
    }
    Digest::Crc(crc.finalize())
}

impl AttemptReader<'_> {
    /// Branch only on physical mappings covered by this checksum. Unlike a
    /// byte observation, equal digests never require rereading representatives.
    pub(crate) fn packed_matches(
        &mut self, start: u64, size: u64, expected: u32, cache: &PackedCrcs,
    ) -> io::Result<bool> {
        self.metadata_ready()?;
        let Some(end) = start.checked_add(size).filter(|&end| end <= self.len()) else { return Ok(true) };
        let cancel = Cancellation::current();
        let projection = &self.projection;
        let graph = &projection.topology;
        let shortest = projection.ends.iter().zip(&graph.ends).filter_map(|(&active, &(_, end, _, _))| {
            active.then_some(end)
        }).min().unwrap_or(end);
        let mut remaining = cache.edges(graph, start).iter().map(|&(_, index)| index)
            .filter(|&index| projection.active[index] && graph.edges[index].end > start).peekable();
        let observe = |index: usize, position, size| {
            let edge = &graph.edges[index];
            if edge.unresolved { return Digest::Unavailable; }
            let source = &self.sources[edge.source];
            let offset = source.start + (position - edge.start);
            cache.segment((edge.source, offset, size), source, &cancel)
        };
        let mut position = start;
        let mut crc = Hasher::new();
        let mut covering = Vec::<usize>::new();
        while position < end {
            cancel.check_io()?;
            covering.retain(|&index| graph.edges[index].end > position);
            while let Some(index) = remaining.next_if(|&index| graph.edges[index].start <= position) {
                if graph.edges[index].end > position { covering.push(index); }
            }
            if covering.is_empty() { return Ok(true); }
            let upcoming = remaining.peek().map_or(end, |&index| graph.edges[index].start);
            let next = covering.iter().fold(end.min(upcoming), |end, &index| end.min(graph.edges[index].end));
            let short = shortest <= position;
            let size = if short { next } else { next.min(shortest) } - position;
            if let [index] = covering.as_slice() {
                if !short {
                    match observe(*index, position, size) {
                        Digest::Crc(digest) => crc.combine(&Hasher::new_with_initial_len(digest, size)),
                        Digest::Truncated => return Ok(false),
                        Digest::Unavailable => return Ok(true),
                    }
                    position += size;
                    continue;
                }
            }
            let mut groups = Vec::<(Digest, Vec<usize>)>::new();
            let mut by_digest = HashMap::new();
            let mut by_location = HashMap::new();
            for &index in &covering {
                let edge = &graph.edges[index];
                let digest = if edge.unresolved {
                    Digest::Unavailable
                } else {
                    let source = &self.sources[edge.source];
                    let offset = source.start + (position - edge.start);
                    *by_location.entry((edge.source, offset)).or_insert_with(|| {
                        observe(index, position, size)
                    })
                };
                cancel.check_io()?;
                let group = *by_digest.entry(digest).or_insert_with(|| {
                    groups.push((digest, Vec::new()));
                    groups.len() - 1
                });
                groups[group].1.push(index);
            }
            if groups.len() > 1 || short {
                let mut branches: Vec<_> = groups.into_iter().filter_map(|(_, edges)| {
                    projection.select(&covering, &edges, false, position)
                }).collect();
                if short { branches.extend(projection.select(&covering, &[], true, position)); }
                self.pending = Some(branches);
                return Err(io::Error::other("packed checksum projection pending"));
            }
            let digest = match groups[0].0 {
                Digest::Crc(digest) => digest,
                Digest::Truncated => return Ok(false),
                Digest::Unavailable => return Ok(true),
            };
            crc.combine(&Hasher::new_with_initial_len(digest, size));
            position += size;
        }
        Ok(crc.finalize() == expected)
    }
}
