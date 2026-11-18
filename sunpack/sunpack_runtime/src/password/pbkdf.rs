//! Share the fixed-size HMAC rounds used by ZIP AES and RAR5 PBKDF2.
//! The SHA crates provide the compression and select the hardware backend.
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub(super) struct FixedHmac<const WORDS: usize, const BYTES: usize, F> {
    inner: [u32; WORDS],
    outer: [u32; WORDS],
    compress: F,
}

impl<const WORDS: usize, const BYTES: usize, F> FixedHmac<WORDS, BYTES, F>
where
    F: Fn(&mut [u32; WORDS], &[u8; 64]),
{
    fn new(password: &[u8], iv: [u32; WORDS], compress: F) -> Self {
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for ((inner, outer), &byte) in inner_pad.iter_mut().zip(&mut outer_pad).zip(password) {
            *inner ^= byte;
            *outer ^= byte;
        }
        let mut inner = iv;
        let mut outer = iv;
        compress(&mut inner, &inner_pad);
        compress(&mut outer, &outer_pad);
        Self { inner, outer, compress }
    }

    pub(super) fn start(&self, salt: &[u8], index: u32) -> [u8; BYTES] {
        let length = salt.len() + 4;
        assert!(length <= 55, "ZIP AES and RAR5 salts fit a single SHA block");
        let mut first = padded(length);
        first[..salt.len()].copy_from_slice(salt);
        first[salt.len()..length].copy_from_slice(&index.to_be_bytes());
        let mut state = self.inner;
        (self.compress)(&mut state, &first);

        let mut last = padded(BYTES);
        write_words(&mut last[..BYTES], state);
        let mut state = self.outer;
        (self.compress)(&mut state, &last);
        let mut output = [0; BYTES];
        write_words(&mut output, state);
        output
    }

    pub(super) fn block(
        &self, salt: &[u8], index: u32, more_rounds: u32, keep_running: impl Fn() -> bool,
    ) -> Option<[u8; BYTES]> {
        let mut previous = self.start(salt, index);
        let mut output = previous;
        self.extend(&mut previous, &mut output, more_rounds, keep_running).then_some(output)
    }

    pub(super) fn extend(
        &self,
        previous: &mut [u8; BYTES],
        output: &mut [u8; BYTES],
        mut remaining: u32,
        keep_running: impl Fn() -> bool,
    ) -> bool {
        // Each subsequent HMAC hashes exactly one digest. Reuse the
        // padding and the already-compressed key pads for every round.
        let mut block = padded(BYTES);
        while remaining != 0 {
            if !keep_running() { return false; }
            let count = remaining.min(64);
            for _ in 0..count {
                block[..BYTES].copy_from_slice(previous);
                let mut inner = self.inner;
                (self.compress)(&mut inner, &block);
                write_words(&mut block[..BYTES], inner);
                let mut outer = self.outer;
                (self.compress)(&mut outer, &block);
                write_words(previous, outer);
                for (value, byte) in output.iter_mut().zip(previous.iter()) {
                    *value ^= byte;
                }
            }
            remaining -= count;
        }
        true
    }
}

fn padded(length: usize) -> [u8; 64] {
    let mut block = [0; 64];
    block[length] = 0x80;
    // The compressed key pad is part of the SHA message length.
    block[62..].copy_from_slice(&(((64 + length) * 8) as u16).to_be_bytes());
    block
}

fn write_words<const WORDS: usize>(output: &mut [u8], words: [u32; WORDS]) {
    for (bytes, word) in output.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
}

pub(super) fn sha1(password: &[u8]) -> FixedHmac<5, 20, impl Fn(&mut [u32; 5], &[u8; 64])> {
    const IV: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let long_key;
    let key = if password.len() > 64 {
        long_key = Sha1::digest(password);
        long_key.as_slice()
    } else {
        password
    };
    FixedHmac::new(key, IV, |state, block| sha1::compress(state, std::slice::from_ref(block.into())))
}

pub(super) fn sha256(password: &[u8]) -> FixedHmac<8, 32, impl Fn(&mut [u32; 8], &[u8; 64])> {
    const IV: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    let long_key;
    let key = if password.len() > 64 {
        long_key = Sha256::digest(password);
        long_key.as_slice()
    } else {
        password
    };
    FixedHmac::new(key, IV, |state, block| sha2::compress256(state, std::slice::from_ref(block.into())))
}
