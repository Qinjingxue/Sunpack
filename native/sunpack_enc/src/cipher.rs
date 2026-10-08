//! CTR uses a full big-endian counter for every block size. AES batches blocks
//! through RustCrypto's runtime-selected hardware backend (no per-byte dispatch).
use cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop};
#[path = "blowfish.rs"]
mod blowfish;
#[path = "gost.rs"]
mod gost;
#[path = "rc6.rs"]
mod rc6;
#[path = "serpent.rs"]
mod serpent;
#[path = "shacal.rs"]
mod shacal;
#[path = "threefish.rs"]
mod threefish;
#[path = "twofish.rs"]
mod twofish;

enum Primitive {
    Aes(aes::Aes256),
    Rc6(rc6::Rc6),
    Serpent(serpent::Serpent),
    Blowfish(blowfish::Blowfish),
    Twofish(twofish::Twofish),
    Gost(gost::Gost),
    Threefish(threefish::Threefish),
    Shacal(shacal::Shacal),
}
impl Primitive {
    fn new(code: u8, key: &[u8]) -> (Self, usize) {
        match code {
            0 => (Self::Aes(aes::Aes256::new_from_slice(key).unwrap()), 16),
            1 => (Self::Rc6(rc6::Rc6::new(key)), 16),
            2 => (Self::Serpent(serpent::Serpent::new(key)), 16),
            3 | 6 => (Self::Blowfish(blowfish::Blowfish::new(key)), 8),
            4 => (Self::Twofish(twofish::Twofish::new(key)), 16),
            5 => (Self::Gost(gost::Gost::new(key)), 8),
            7 => (Self::Threefish(threefish::Threefish::new(key)), 128),
            8 => (Self::Shacal(shacal::Shacal::new(key)), 32),
            _ => unreachable!(),
        }
    }
    fn encrypt(&self, bytes: &mut [u8]) {
        match self {
            Self::Aes(c) => batch(c, bytes),
            Self::Serpent(c) => c.encrypt(bytes),
            Self::Blowfish(c) => c.encrypt(bytes),
            Self::Twofish(c) => c.encrypt(bytes),
            Self::Gost(c) => c.encrypt(bytes),
            Self::Threefish(c) => c.encrypt(bytes),
            Self::Rc6(c) => c.encrypt(bytes),
            Self::Shacal(c) => c.encrypt(bytes),
        }
    }
}
fn batch<C: BlockEncrypt>(cipher: &C, bytes: &mut [u8]) {
    let mut blocks: [Block<C>; 16] = std::array::from_fn(|_| Block::<C>::default());
    let size = blocks[0].len();
    for group in bytes.chunks_mut(size * blocks.len()) {
        let count = group.len() / size;
        for (block, src) in blocks.iter_mut().zip(group.chunks_exact(size)) {
            block.copy_from_slice(src);
        }
        cipher.encrypt_blocks(&mut blocks[..count]);
        for (block, dst) in blocks.iter_mut().zip(group.chunks_exact_mut(size)) {
            dst.copy_from_slice(block);
        }
    }
}

struct Ctr {
    primitive: Primitive,
    size: usize,
    initial: [u8; 128],
    state: CtrState,
}
#[derive(Zeroize, ZeroizeOnDrop)]
struct CtrState {
    counter: [u8; 128],
    pad: [u8; 2048],
    used: usize,
    available: usize,
}
impl Ctr {
    fn new(code: u8, key: &[u8], nonce: &[u8]) -> Self {
        let (primitive, size) = Primitive::new(code, key);
        let mut counter = [0; 128];
        counter[..size].copy_from_slice(nonce);
        Self {
            primitive,
            size,
            initial: counter,
            state: CtrState::new(counter),
        }
    }
    fn apply(&mut self, bytes: &mut [u8]) {
        self.state.apply(&self.primitive, self.size, bytes);
    }
    fn apply_at(&self, offset: u64, bytes: &mut [u8]) {
        let mut state = CtrState::new(self.initial);
        let mut carry = offset / self.size as u64;
        for byte in state.counter[..self.size].iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xff);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        // The quick proof and arbitrary range boundaries need not be block aligned.
        let skip = offset as usize % self.size;
        if skip != 0 {
            state.apply(&self.primitive, self.size, &mut [0u8; 128][..skip]);
        }
        state.apply(&self.primitive, self.size, bytes);
    }
}
impl CtrState {
    fn new(counter: [u8; 128]) -> Self {
        Self {
            counter,
            pad: [0; 2048],
            used: 0,
            available: 0,
        }
    }
    fn apply(&mut self, primitive: &Primitive, size: usize, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            if self.used == self.available {
                // Only generate what this call needs (especially the 32B password proof).
                let blocks = bytes.len().div_ceil(size).min(self.pad.len() / size);
                self.available = blocks * size;
                self.used = 0;
                match size {
                    8 => {
                        let mut counter = u64::from_be_bytes(self.counter[..8].try_into().unwrap());
                        for block in self.pad[..self.available].chunks_exact_mut(8) {
                            block.copy_from_slice(&counter.to_be_bytes());
                            counter = counter.wrapping_add(1);
                        }
                        self.counter[..8].copy_from_slice(&counter.to_be_bytes());
                    }
                    16 => {
                        let mut counter =
                            u128::from_be_bytes(self.counter[..16].try_into().unwrap());
                        for block in self.pad[..self.available].chunks_exact_mut(16) {
                            block.copy_from_slice(&counter.to_be_bytes());
                            counter = counter.wrapping_add(1);
                        }
                        self.counter[..16].copy_from_slice(&counter.to_be_bytes());
                    }
                    _ => {
                        for block in self.pad[..self.available].chunks_exact_mut(size) {
                            block.copy_from_slice(&self.counter[..size]);
                            for byte in self.counter[..size].iter_mut().rev() {
                                *byte = byte.wrapping_add(1);
                                if *byte != 0 {
                                    break;
                                }
                            }
                        }
                    }
                }
                primitive.encrypt(&mut self.pad[..self.available]);
            }
            let n = bytes.len().min(self.available - self.used);
            for (b, p) in bytes[..n]
                .iter_mut()
                .zip(&self.pad[self.used..self.used + n])
            {
                *b ^= p;
            }
            self.used += n;
            bytes = &mut bytes[n..];
        }
    }
}
pub(crate) struct Stream {
    stages: Vec<Ctr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pad_refills_match_independent_single_block_counters() {
        for (code, key_len) in [
            (0, 32),
            (1, 32),
            (2, 32),
            (3, 32),
            (4, 32),
            (5, 32),
            (6, 56),
            (7, 128),
            (8, 64),
        ] {
            let key = vec![0x73; key_len];
            let (primitive, size) = Primitive::new(code, &key);
            for tail in [0xf8, 0xff] {
                let mut nonce = vec![0xff; size];
                nonce[size - 1] = tail;
                let mut counter = nonce.clone();
                let mut expected = Vec::new();
                for _ in 0..8197usize.div_ceil(size) {
                    let mut block = counter.clone();
                    primitive.encrypt(&mut block);
                    expected.extend_from_slice(&block);
                    for byte in counter.iter_mut().rev() {
                        let (value, carry) = byte.overflowing_add(1);
                        *byte = value;
                        if !carry {
                            break;
                        }
                    }
                }
                expected.truncate(8197);
                for chunk in [32, 2047, 2048, 2049, 8197] {
                    let mut state = Ctr::new(code, &key, &nonce);
                    let mut actual = vec![0; expected.len()];
                    for part in actual.chunks_mut(chunk) {
                        state.apply(part);
                    }
                    assert_eq!(actual, expected, "cipher {code}, chunk {chunk}");
                }
                let mut proof = Ctr::new(code, &key, &nonce);
                proof.apply(&mut [0; 32]);
                assert_eq!(proof.state.available, 32usize.div_ceil(size) * size);
            }
        }
    }
}
impl Stream {
    pub fn new(code: u8, key: &[u8], nonce: &[u8]) -> Self {
        if code != 9 {
            return Self {
                stages: vec![Ctr::new(code, key, nonce)],
            };
        }
        let mut k = 0;
        let mut n = 0;
        let mut stages = Vec::with_capacity(4);
        for (code, key_len, nonce_len) in [(7, 128, 128), (2, 32, 16), (0, 32, 16), (8, 64, 32)] {
            stages.push(Ctr::new(
                code,
                &key[k..k + key_len],
                &nonce[n..n + nonce_len],
            ));
            k += key_len;
            n += nonce_len;
        }
        Self { stages }
    }
    pub fn apply(&mut self, bytes: &mut [u8]) {
        for stage in &mut self.stages {
            stage.apply(bytes);
        }
    }
    pub fn apply_at(&self, offset: u64, bytes: &mut [u8]) {
        for stage in &self.stages {
            // Share the expanded key; each task owns only its counter and pad.
            stage.apply_at(offset, bytes);
        }
    }
    #[cfg(feature = "parallel-decrypt")]
    pub fn apply_with_threads(&self, offset: u64, bytes: &mut [u8], threads: usize) {
        use rayon::prelude::*;
        if bytes.is_empty() {
            return;
        }
        let chunk_size = bytes.len().div_ceil(threads.max(1));
        if chunk_size == bytes.len() {
            self.apply_at(offset, bytes);
            return;
        }
        // Exactly one CTR operation per granted CPU credit. Rayon cannot fan
        // this work out beyond these slices, even though the pool is shared.
        bytes
            .par_chunks_mut(chunk_size)
            .with_max_len(1)
            .enumerate()
            .for_each(|(index, part)| {
                self.apply_at(offset + (index * chunk_size) as u64, part);
            });
    }
}
