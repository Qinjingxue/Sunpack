//! CTR uses a full big-endian counter for every block size. AES batches blocks
//! through RustCrypto's runtime-selected hardware backend (no per-byte dispatch).
use cipher::{Block, BlockEncrypt, KeyInit};
use cipher5::{
    consts::{U20, U32},
    BlockCipherEncrypt, KeyInit as KeyInit5,
};

type Rc6 = rc6::RC6<u32, U20, U32>;
enum Primitive {
    Aes(aes::Aes256),
    Rc6(Rc6),
    Serpent(serpent::Serpent),
    Blowfish(blowfish::Blowfish),
    Twofish(twofish::Twofish),
    Gost(magma::Gost89Test),
    Threefish(threefish::Threefish1024),
    Shacal([u8; 64]),
}
impl Primitive {
    fn new(code: u8, key: &[u8]) -> (Self, usize) {
        match code {
            0 => (Self::Aes(aes::Aes256::new_from_slice(key).unwrap()), 16),
            1 => (
                Self::Rc6(<Rc6 as KeyInit5>::new_from_slice(key).unwrap()),
                16,
            ),
            2 => {
                let mut k: [u8; 32] = key.try_into().unwrap();
                k.reverse();
                (
                    Self::Serpent(serpent::Serpent::new_from_slice(&k).unwrap()),
                    16,
                )
            }
            3 | 6 => (
                Self::Blowfish(blowfish::Blowfish::new_from_slice(key).unwrap()),
                8,
            ),
            4 => (
                Self::Twofish(twofish::Twofish::new_from_slice(key).unwrap()),
                16,
            ),
            5 => {
                let mut k: [u8; 32] = key.try_into().unwrap();
                for word in k.chunks_exact_mut(4) {
                    word.reverse();
                }
                (
                    Self::Gost(magma::Gost89Test::new_from_slice(&k).unwrap()),
                    8,
                )
            }
            7 => (
                Self::Threefish(threefish::Threefish1024::new_with_tweak(
                    key.try_into().unwrap(),
                    &[0; 16],
                )),
                128,
            ),
            8 => (Self::Shacal(key.try_into().unwrap()), 32),
            _ => unreachable!(),
        }
    }
    fn encrypt(&self, bytes: &mut [u8]) {
        match self {
            Self::Aes(c) => batch(c, bytes, false),
            Self::Serpent(c) => batch(c, bytes, true),
            Self::Blowfish(c) => batch(c, bytes, false),
            Self::Twofish(c) => batch(c, bytes, false),
            Self::Gost(c) => batch(c, bytes, true),
            Self::Threefish(c) => batch(c, bytes, false),
            Self::Rc6(c) => {
                for block in bytes.chunks_exact_mut(16) {
                    let mut b = cipher5::Block::<Rc6>::default();
                    b.copy_from_slice(block);
                    c.encrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
            }
            Self::Shacal(key) => {
                for block in bytes.chunks_exact_mut(32) {
                    let mut state = [0u32; 8];
                    for (dst, src) in state.iter_mut().zip(block.chunks_exact(4)) {
                        *dst = u32::from_be_bytes(src.try_into().unwrap());
                    }
                    let initial = state;
                    // SHA-256 compression is SHACAL-2 plus feed-forward. Undo the
                    // latter, reusing the upstream optimized round implementation.
                    sha2::compress256(&mut state, &[(*key).into()]);
                    for ((value, old), dst) in
                        state.iter().zip(initial).zip(block.chunks_exact_mut(4))
                    {
                        dst.copy_from_slice(&value.wrapping_sub(old).to_be_bytes());
                    }
                }
            }
        }
    }
}
fn batch<C: BlockEncrypt>(cipher: &C, bytes: &mut [u8], reverse: bool) {
    let mut blocks: [Block<C>; 16] = std::array::from_fn(|_| Block::<C>::default());
    let size = blocks[0].len();
    let count = bytes.len() / size;
    for (block, src) in blocks.iter_mut().zip(bytes.chunks_exact(size)) {
        block.copy_from_slice(src);
        if reverse {
            block.reverse();
        }
    }
    cipher.encrypt_blocks(&mut blocks[..count]);
    for (block, dst) in blocks.iter_mut().zip(bytes.chunks_exact_mut(size)) {
        if reverse {
            block.reverse();
        }
        dst.copy_from_slice(block);
    }
}

struct Ctr {
    primitive: Primitive,
    size: usize,
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
            counter,
            pad: [0; 2048],
            used: 0,
            available: 0,
        }
    }
    fn apply(&mut self, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            if self.used == self.available {
                // Only generate what this call needs (especially the 32B password proof).
                let blocks = bytes.len().div_ceil(self.size).min(16);
                self.available = blocks * self.size;
                self.used = 0;
                for block in self.pad[..self.available].chunks_exact_mut(self.size) {
                    block.copy_from_slice(&self.counter[..self.size]);
                    for byte in self.counter[..self.size].iter_mut().rev() {
                        *byte = byte.wrapping_add(1);
                        if *byte != 0 {
                            break;
                        }
                    }
                }
                self.primitive.encrypt(&mut self.pad[..self.available]);
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
}
