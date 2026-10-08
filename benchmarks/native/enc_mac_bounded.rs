//! Benchmark-only streaming keyed BLAKE3 with a fixed task budget.
//! Kept out of production: worker A/B did not justify parallel MAC scheduling.
//! Upstream hazmat owns compression and merging; no independent hash rounds.
use blake3::hazmat::{self, ChainingValue, HasherExt, Mode};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const MIN_PARALLEL: usize = 64 * 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Authenticator {
    key: [u8; 32],
    chunk: blake3::Hasher,
    // u64 byte offsets contain at most 2^54 chunks. Largest subtree first.
    stack: [ChainingValue; 54],
    used: usize,
    chunks: u64,
}
impl Authenticator {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self {
            key: *key,
            chunk: blake3::Hasher::new_keyed(key),
            stack: [[0; 32]; 54],
            used: 0,
            chunks: 0,
        }
    }
    pub(crate) fn update(&mut self, input: &[u8], threads: usize) {
        for part in input.chunks(256 * 1024) {
            self.update_batch(part, threads);
        }
    }
    fn update_batch(&mut self, mut input: &[u8], threads: usize) {
        #[cfg(not(feature = "parallel-decrypt"))]
        let _ = threads;
        if input.is_empty() {
            return;
        }
        if self.chunk.count() != 0 {
            let n = input
                .len()
                .min(blake3::CHUNK_LEN - self.chunk.count() as usize);
            self.chunk.update(&input[..n]);
            input = &input[n..];
            if input.is_empty() {
                return;
            }
            self.push(self.chunk.finalize_non_root(), 1);
        }
        #[cfg(feature = "parallel-decrypt")]
        if threads > 1 && input.len() >= 2 * MIN_PARALLEL {
            use rayon::prelude::*;
            #[derive(Clone, Copy, Default, Zeroize)]
            struct Job {
                offset: u64,
                start: usize,
                len: usize,
                cv: ChainingValue,
            }
            let threads = threads.min(input.len() / MIN_PARALLEL).min(4);
            let target = (1usize << (input.len() / threads).ilog2()).max(MIN_PARALLEL);
            let mut jobs = Zeroizing::new([[Job::default(); 16]; 4]);
            let mut plan = [(0usize, 0usize, 0u64, 0usize); 32];
            let mut count = 0;
            let (mut start, mut chunk) = (0usize, self.chunks);
            while input.len() - start > blake3::CHUNK_LEN {
                let available = (input.len() - start - 1) / blake3::CHUNK_LEN;
                let mut n = (1usize << available.ilog2()).min(target / blake3::CHUNK_LEN);
                if chunk != 0 {
                    n = n.min(1usize << chunk.trailing_zeros());
                }
                plan[count] = (start, n * blake3::CHUNK_LEN, chunk, 0);
                count += 1;
                start += n * blake3::CHUNK_LEN;
                chunk += n as u64;
            }
            let mut loads = [0usize; 4];
            let mut counts = [0usize; 4];
            for index in (0..count).rev() {
                let lane = (0..threads).min_by_key(|&lane| loads[lane]).unwrap();
                let (begin, n, chunk, _) = plan[index];
                let slot = counts[lane];
                jobs[lane][slot] = Job {
                    offset: chunk * blake3::CHUNK_LEN as u64,
                    start: begin,
                    len: n,
                    cv: [0; 32],
                };
                plan[index].3 = lane * 16 + slot;
                counts[lane] += 1;
                loads[lane] += n;
            }
            // One executor entry and exactly `threads` serial leaf tasks.
            jobs[..threads]
                .par_iter_mut()
                .with_max_len(1)
                .for_each(|lane| {
                    for job in lane.iter_mut().take_while(|job| job.len != 0) {
                        job.cv = subtree(
                            &self.key,
                            &input[job.start..job.start + job.len],
                            job.offset,
                        );
                    }
                });
            for &(_, n, _, slot) in &plan[..count] {
                self.push(
                    jobs[slot / 16][slot % 16].cv,
                    (n / blake3::CHUNK_LEN) as u64,
                );
            }
            input = &input[start..];
        }
        // Keep the final chunk in Hasher: finalization needs the ROOT flag.
        while input.len() > blake3::CHUNK_LEN {
            let available = (input.len() - 1) / blake3::CHUNK_LEN;
            let mut chunks = 1usize << available.ilog2();
            if self.chunks != 0 {
                chunks = chunks.min(1usize << self.chunks.trailing_zeros());
            }
            let n = chunks * blake3::CHUNK_LEN;
            let cv = subtree(
                &self.key,
                &input[..n],
                self.chunks * blake3::CHUNK_LEN as u64,
            );
            self.push(cv, chunks as u64);
            input = &input[n..];
        }
        self.chunk.zeroize();
        self.chunk = blake3::Hasher::new_keyed(&self.key);
        self.chunk
            .set_input_offset(self.chunks * blake3::CHUNK_LEN as u64);
        self.chunk.update(input);
    }
    fn push(&mut self, mut cv: ChainingValue, chunks: u64) {
        debug_assert_eq!(self.chunks % chunks, 0);
        let mut width = chunks;
        while self.chunks & width != 0 {
            self.used -= 1;
            cv = hazmat::merge_subtrees_non_root(
                &self.stack[self.used],
                &cv,
                Mode::KeyedHash(&self.key),
            );
            self.stack[self.used].zeroize();
            width *= 2;
        }
        self.stack[self.used] = cv;
        self.used += 1;
        self.chunks += chunks;
    }
    pub(crate) fn finalize(&self) -> blake3::Hash {
        if self.used == 0 {
            return self.chunk.finalize();
        }
        let mut cv = Zeroizing::new(self.chunk.finalize_non_root());
        for left in self.stack[1..self.used].iter().rev() {
            *cv = hazmat::merge_subtrees_non_root(left, &cv, Mode::KeyedHash(&self.key));
        }
        hazmat::merge_subtrees_root(&self.stack[0], &cv, Mode::KeyedHash(&self.key))
    }
}

fn subtree(key: &[u8; 32], input: &[u8], offset: u64) -> ChainingValue {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(key));
    hasher.set_input_offset(offset).update(input);
    hasher.finalize_non_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_stream_matches_upstream_with_arbitrary_prefixes_and_updates() {
        let key = [0x93; 32];
        let bytes: Vec<u8> = (0..1024 * 1024 + 193).map(|i| (i * 13) as u8).collect();
        for len in [
            0,
            1,
            1023,
            1024,
            1025,
            2048,
            2049,
            65535,
            65536,
            65537,
            131072,
            262143,
            262144,
            262145,
            bytes.len(),
        ] {
            for prefix in [0, 48, 56, 72, 168, 232, 1023] {
                for threads in [1, 2, 3, 4, 5, 9] {
                    let mut reference = blake3::Hasher::new_keyed(&key);
                    reference.update(&bytes[..prefix]).update(&bytes[..len]);
                    let mut mac = Authenticator::new(&key);
                    mac.update(&bytes[..prefix], 1);
                    let mut position = 0;
                    for n in [1, 7, 1024, 65537, 262144].into_iter().cycle() {
                        if position == len {
                            break;
                        }
                        let end = len.min(position + n);
                        mac.update(&bytes[position..end], threads);
                        position = end;
                        let mut expected = blake3::Hasher::new_keyed(&key);
                        expected.update(&bytes[..prefix]).update(&bytes[..position]);
                        assert_eq!(mac.finalize(), expected.finalize());
                    }
                    assert_eq!(mac.finalize(), reference.finalize());
                }
            }
        }
    }
}
