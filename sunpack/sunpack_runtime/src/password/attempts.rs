//! Exact password proof reuse while readers share a physical source.
use crate::collections::CacheOrder;
use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::cancellation::Cancellation;
use crate::io::reader::NativeArchiveSession;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

const BATCH_SIZE: usize = super::VERIFICATION_BATCH_SIZE;
pub(crate) const MAX_SUCCESSES: usize = 1024;
pub(crate) const MAX_REJECTIONS: usize = 8192;

// Compact exact identities, not hash-only fingerprints: a collision must never
// skip a password. Single files stay allocation-free; compound keys reuse the
// existing binary serializer and are shared between plans and cache entries.

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Key {
    generation: u64,
    format: &'static str,
    start: u64,
    end: Option<u64>,
    eocd: Option<u64>,
    native_disks: bool,
    compound: Option<Arc<[u8]>>,
    compound_hash: u64,
}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Negative entries are keyed per candidate. Hash a compound layout
        // once when planning, not once per password; Eq still checks the full
        // identity, so a fast-hash collision cannot reuse another proof.
        std::hash::Hash::hash(&(
            self.generation, self.format, self.start, self.end, self.eocd,
            self.native_disks, self.compound.is_some(), self.compound_hash,
        ), state);
    }
}

impl Key {
    pub(crate) fn for_input<'a>(input: &ArchiveInput, sessions: &'a [NativeArchiveSession]) -> Option<(Self, &'a AttemptCache)> {
        let format = match input.format_hint.as_str() {
            "zip" => "zip", "rar" => "rar", "7z" => "7z", "enc" => "enc",
            _ => return None,
        };
        let (path, start, end) = match input.mode {
            OpenMode::File => (input.entry_path.as_str(), 0, None),
            OpenMode::FileRange => {
                let extent = &input.parts.first()?.extent;
                (extent.path.as_str(), extent.start, extent.end)
            }
            _ => (input.entry_path.as_str(), 0, None),
        };
        let (generation, compound): (_, Option<Arc<[u8]>>) = if input.volume_attempts.is_some()
            || !matches!(input.mode, OpenMode::File | OpenMode::FileRange) {
            // Iteration follows the descriptor, not HashMap order. Binding all
            // candidate sources prevents stale proof reuse after a volume edit.
            let generations = sessions.iter().map(NativeArchiveSession::generation)
                .collect::<io::Result<HashMap<_, _>>>().ok()?;
            let members = input.physical_paths().chain(std::iter::once(input.entry_path.as_str()))
                .map(|path| Some((path, *generations.get(path)?)))
                .collect::<Option<Vec<_>>>()?;
            // A giant layout still goes through the normal verifier. Only its
            // optional memoization key is omitted if it cannot fit here.
            const COMPOUND_KEY_BYTES: usize = 4096;
            let mut storage = [0; COMPOUND_KEY_BYTES];
            let mut remaining = storage.as_mut_slice();
            rmp_serde::encode::write_named(&mut remaining, &(
                input.mode, &members, &input.parts,
                &input.volume_attempts,
            )).ok()?;
            let len = COMPOUND_KEY_BYTES - remaining.len();
            (*generations.get(path)?, Some(Arc::from(&storage[..len])))
        } else {
            let generation = sessions.iter().find_map(|session| {
                let (source, generation) = session.generation().ok()?;
                (source == path).then_some(generation)
            })?;
            (generation, None)
        };
        let compound_hash = compound.as_deref().map_or(0, |bytes| crate::fast_hash_core::xxh64(bytes, 0));
        let cache = sessions.iter().find(|session| session.path() == path)?.attempt_cache();
        Some((Self { generation, format, start, end,
            eocd: input.analysis.zip_eocd_offset, native_disks: input.analysis.zip_spanned || input.analysis.rar_native_volume,
            compound, compound_hash }, cache))
    }

    #[cfg(test)]
    pub(crate) fn synthetic(generation: u64, compound: Option<Arc<[u8]>>) -> Self {
        Self { generation, format: "zip", start: 0, end: None, eocd: None,
            native_disks: false, compound, compound_hash: 0 }
    }
}

#[derive(Default)]
pub(crate) struct AttemptCache(Mutex<AttemptCacheState>);

#[derive(Default)]
struct AttemptCacheState {
    // Independent budgets keep negative candidates from evicting positive proofs.
    successes: CacheOrder<Key, Option<Arc<str>>>,
    negative: CacheOrder<(Key, Arc<str>), ()>,
}

impl AttemptCache {
    pub(crate) fn proof(&self, key: &Key) -> Option<Option<Arc<str>>> {
        self.0.lock().unwrap().successes.get(key).cloned()
    }

    #[cfg(test)]
    pub(crate) fn remove_rejected(&self, key: &Key, candidates: &mut Vec<Arc<str>>) -> bool {
        let before = candidates.len();
        candidates.retain(|password| !self.rejected(key, password));
        candidates.len() != before
    }

    pub(crate) fn rejected(&self, key: &Key, password: &Arc<str>) -> bool {
        self.0.lock().unwrap().negative.get(&(key.clone(), Arc::clone(password))).is_some()
    }

    pub(crate) fn fill_available<'p>(
        &self,
        key: &Key,
        batch: &mut Vec<Arc<str>>,
        candidates: &mut impl Iterator<Item = &'p Arc<str>>,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        while batch.len() < BATCH_SIZE {
            cancellation.check_io()?;
            let mut state = self.0.lock().unwrap();
            // Bound the work under the cache lock even if every candidate
            // in this window was rejected on a previous request.
            for _ in 0..BATCH_SIZE {
                let Some(candidate) = candidates.next() else { return Ok(()); };
                if state.negative.get(&(key.clone(), candidate.clone())).is_none() {
                    batch.push(candidate.clone());
                    if batch.len() == BATCH_SIZE {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn remember_proof(&self, key: Key, proof: Option<Arc<str>>) {
        self.0.lock().unwrap().successes.insert(key, proof, MAX_SUCCESSES);
    }

    pub(crate) fn reject(&self, key: Key, candidates: &[Arc<str>]) {
        for batch in candidates.chunks(BATCH_SIZE) {
            let mut state = self.0.lock().unwrap();
            for password in batch {
                state.negative.insert((key.clone(), Arc::clone(password)), (), MAX_REJECTIONS);
            }
        }
    }
}

