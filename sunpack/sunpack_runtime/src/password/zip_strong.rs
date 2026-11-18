//! PKWARE APPNOTE §7.2.4 password-only AES decryption header.
use super::{
    le_u16, le_u32, zip_password_bytes, PasswordVerification, PreparedStatus, ZipKey, ZipKeyCache,
    ZipKeyMaterial,
};
use crate::formats::zip::zip64::CentralValues;
use crate::io::cancellation::Cancellation;
use aes::cipher::{Block, BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use std::sync::Arc;

const BLOCK: usize = 16;
const FIELD: &str = "zip.strong_encryption.decryption_header";

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PasswordHeader {
    iv: [u8; BLOCK],
    iv_len: usize,
    key_len: usize,
    erd_len: usize,
    body: Arc<[u8]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Reject,
    Possible,
    Match,
}

impl PasswordHeader {
    pub(super) fn read(
        sizes_and_crc: Option<(CentralValues, u32)>,
        mut read: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, PreparedStatus>,
    ) -> Result<Self, PreparedStatus> {
        let unsupported = || {
            PreparedStatus::new(
                "unsupported_method",
                "unsupported PKWARE Strong decryption header",
            )
        };
        let invalid = || {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                "invalid PKWARE Strong decryption header",
            )
        };
        let prefix = read(0, 2, FIELD)?;
        let explicit_iv_len = usize::from(le_u16(&prefix, 0).ok_or_else(invalid)?);
        let iv_len = match explicit_iv_len {
            0 => 12,
            BLOCK => BLOCK,
            _ => return Err(unsupported()),
        };
        // Format, algorithm, key width, flags and ErdSize follow the size word.
        let prefix = read(2, explicit_iv_len + 14, FIELD)?;
        let (explicit_iv, fields) = prefix.split_at(explicit_iv_len);
        let mut iv = [0; BLOCK];
        if explicit_iv_len == 0 {
            let (sizes, crc) = sizes_and_crc.as_ref().ok_or_else(|| {
                PreparedStatus::new(
                    "unknown_needs_final_verifier",
                    "PKWARE Strong implicit IV requires member CRC and size",
                )
            })?;
            iv[..4].copy_from_slice(&crc.to_le_bytes());
            iv[4..12].copy_from_slice(&sizes.uncompressed.to_le_bytes());
        } else {
            iv.copy_from_slice(explicit_iv);
        }
        let key_len = match le_u16(fields, 6).ok_or_else(invalid)? {
            0x660e => 16,
            0x660f => 24,
            0x6610 => 32,
            _ => return Err(unsupported()),
        };
        if le_u16(fields, 4) != Some(3)
            || le_u16(fields, 8) != Some((8 * key_len) as u16)
            || le_u16(fields, 10) != Some(1)
        {
            return Err(unsupported());
        }
        let remaining = le_u32(fields, 0).ok_or_else(invalid)?;
        let erd_len = usize::from(le_u16(fields, 12).ok_or_else(invalid)?);
        let validation_len = (remaining as usize).checked_sub(erd_len + 16).ok_or_else(invalid)?;
        if erd_len == 0
            || erd_len % BLOCK != 0
            || validation_len == 0
            || validation_len % BLOCK != 0
            || validation_len > usize::from(u16::MAX)
            || sizes_and_crc.as_ref().is_some_and(|(sizes, _)| {
                u64::from(remaining) + explicit_iv_len as u64 + 6 > sizes.compressed
            })
        {
            return Err(invalid());
        }
        let body_offset = (explicit_iv_len + 16) as u64;
        // Read the certificate marker and VSize before the encrypted fields.
        let lengths = read(body_offset + erd_len as u64, 6, FIELD)?;
        if le_u32(&lengths, 0) != Some(0) {
            return Err(unsupported());
        }
        if le_u16(&lengths, 4) != Some(validation_len as u16) {
            return Err(invalid());
        }
        let body = read(body_offset, erd_len + 6 + validation_len, FIELD)?;
        Ok(Self {
            iv,
            iv_len,
            key_len,
            erd_len,
            body: body.into(),
        })
    }

    pub(super) fn verify(
        &self,
        candidates: &[Arc<str>],
        cache: Option<&ZipKeyCache>,
    ) -> std::io::Result<PasswordVerification> {
        let cancellation = Cancellation::current();
        let slots = cache.and_then(|cache| cache.cells(&ZipKeyMaterial::Strong, candidates.len()));
        let check = |(index, password): (usize, &Arc<str>)| {
            if cancellation.cancelled() {
                return None;
            }
            let derive = || {
                Some(ZipKey::Strong(derive_key(Sha1::new_with_prefix(
                    zip_password_bytes(password),
                ))))
            };
            let Some(ZipKey::Strong(key)) =
                slots.map_or_else(derive, |slots| *slots[index].get_or_init(derive))
            else {
                return None;
            };
            let proof = match self.key_len {
                16 => self.check::<Aes128>(&key),
                24 => self.check::<Aes192>(&key),
                32 => self.check::<Aes256>(&key),
                _ => unreachable!(),
            };
            (proof != Evidence::Reject).then_some((index, proof))
        };
        let mut survivors: Vec<_> = if candidates.len() >= 32 {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(check)
                .collect()
        } else {
            candidates.iter().enumerate().filter_map(check).collect()
        };
        cancellation.check_io()?;
        if survivors.iter().any(|&(_, proof)| proof == Evidence::Match) {
            survivors.retain(|&(_, proof)| proof == Evidence::Match);
        }
        let proven = survivors
            .first()
            .is_some_and(|&(_, evidence)| evidence == Evidence::Match);
        let mut result = if proven {
            PasswordVerification::status("match", "PKWARE Strong password validation CRC matched")
        } else if !survivors.is_empty() {
            // Exact ERD padding under this key plus a bad VCRC can mean damage
            // to the encrypted validation bytes. Let the decoder resolve it.
            PasswordVerification::status(
                "match",
                "PKWARE Strong password padding matched; validation CRC is inconclusive",
            )
        } else {
            PasswordVerification::status(
                "no_match",
                "PKWARE Strong password validation did not match",
            )
        };
        result.attempts = candidates.len();
        result.matched_indices = survivors.iter().map(|&(index, _)| index).collect();
        result.matched_index = result.matched_indices.first().copied();
        if result.matched_index.is_some() {
            let strong = proven && survivors.len() == 1;
            result.final_confirmation_required = Some(!strong);
            result.match_evidence = Some(if proven {
                "zip_pkware_strong_vcrc32"
            } else {
                "zip_pkware_strong_padding"
            });
        }
        Ok(result)
    }

    fn check<C: BlockCipherDecrypt + KeyInit>(&self, master_key: &[u8; 32]) -> Evidence {
        let erd = &self.body[..self.erd_len];
        let random_len = erd.len() - BLOCK;
        let master_cipher = C::new_from_slice(&master_key[..self.key_len]).unwrap();
        // The final CBC block is known full padding in the supported native
        // method. Reject before walking ERD or deriving the file key.
        let prev = if random_len == 0 {
            &self.iv[..]
        } else {
            &erd[random_len - BLOCK..random_len]
        };
        if decrypt_block(&master_cipher, prev, &erd[random_len..]) != [BLOCK as u8; BLOCK] {
            return Evidence::Reject;
        }
        let mut previous = &self.iv[..];
        let mut sha = Sha1::new_with_prefix(&self.iv[..self.iv_len]);
        for block in erd[..random_len].chunks_exact(BLOCK) {
            sha.update(decrypt_block(&master_cipher, previous, block));
            previous = block;
        }
        let file_key = derive_key(sha);
        let file_cipher = C::new_from_slice(&file_key[..self.key_len]).unwrap();
        let mut previous = &self.iv[..];
        let mut crc = crc32fast::Hasher::new();
        let mut blocks = self.body[self.erd_len + 6..].chunks_exact(BLOCK);
        let last = blocks.next_back().unwrap();
        for block in blocks {
            crc.update(&decrypt_block(&file_cipher, previous, block));
            previous = block;
        }
        let last = decrypt_block(&file_cipher, previous, last);
        crc.update(&last[..BLOCK - 4]);
        if crc.finalize() == le_u32(&last, BLOCK - 4).unwrap() {
            Evidence::Match
        } else {
            Evidence::Possible
        }
    }
}

fn decrypt_block<C: BlockCipherDecrypt>(
    cipher: &C,
    previous: &[u8],
    encrypted: &[u8],
) -> [u8; BLOCK] {
    let mut block = Block::<C>::default();
    block.copy_from_slice(encrypted);
    cipher.decrypt_block(&mut block);
    std::array::from_fn(|i| block[i] ^ previous[i])
}

fn derive_key(sha: Sha1) -> [u8; 32] {
    let source = sha.finalize();
    let digest = |pad| {
        let mut bytes = [pad; 64];
        for (byte, &source) in bytes.iter_mut().zip(source.iter()) {
            *byte ^= source;
        }
        Sha1::digest(bytes)
    };
    let mut key = [0; 32];
    key[..20].copy_from_slice(&digest(0x36));
    key[20..].copy_from_slice(&digest(0x5c)[..12]);
    key
}

#[cfg(test)]
#[path = "../../tests/unit/password/zip/strong_tests.rs"]
mod tests;
