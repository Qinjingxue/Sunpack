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
pub(super) const VALIDATION_FIELD: &str = "zip.strong_encryption.validation";

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PasswordHeader {
    iv: [u8; BLOCK],
    iv_len: usize,
    key_len: usize,
    erd_tail: [[u8; BLOCK]; 2],
    ranges: ValidationRanges,
    validation: Option<Validation>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ValidationRanges {
    body_offset: u64,
    erd_len: usize,
    validation_len: usize,
    validation_size_checked: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct Validation {
    erd_prefix: Arc<[u8]>,
    erd_has_random_data: bool,
    bytes: Arc<[u8]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Reject,
    Possible,
    Match,
}

impl PasswordHeader {
    pub(super) fn read(
        sizes_and_crc: Option<(&CentralValues, u32)>,
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
        let validation_len = (remaining as usize)
            .checked_sub(erd_len + 16)
            .ok_or_else(invalid)?;
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
        let tail_len = erd_len.min(2 * BLOCK);
        let erd_prefix_len = erd_len - tail_len;
        let tail = read(body_offset + erd_prefix_len as u64, tail_len, FIELD)?;
        let erd_tail = [
            if tail_len == BLOCK {
                iv
            } else {
                tail[..BLOCK].try_into().unwrap()
            },
            tail[tail_len - BLOCK..].try_into().unwrap(),
        ];
        let mut header = Self {
            iv,
            iv_len,
            key_len,
            erd_tail,
            ranges: ValidationRanges {
                body_offset,
                erd_len,
                validation_len,
                validation_size_checked: false,
            },
            validation: None,
        };
        header.load_validation(read)?;
        Ok(header)
    }

    pub(super) fn has_validation(&self) -> bool {
        self.validation.is_some()
    }

    pub(super) fn load_validation(
        &mut self,
        mut read: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, PreparedStatus>,
    ) -> Result<(), PreparedStatus> {
        // Only the ERD tail is required for the padding proof. Inspect the
        // certificate marker and declared VSize before reading the ciphertext.
        let ValidationRanges {
            body_offset,
            erd_len,
            validation_len,
            validation_size_checked,
        } = self.ranges;
        let erd_prefix_len = erd_len.saturating_sub(2 * BLOCK);
        let validation_offset = body_offset + erd_len as u64;
        if !validation_size_checked {
            let Ok(lengths) = read(validation_offset, 6, VALIDATION_FIELD) else {
                return Ok(());
            };
            if le_u32(&lengths, 0) != Some(0) {
                return Err(PreparedStatus::new(
                    "unsupported_method",
                    "unsupported PKWARE Strong certificate data",
                ));
            }
            if le_u16(&lengths, 4) != Some(validation_len as u16) {
                return Err(PreparedStatus::new(
                    "unknown_needs_final_verifier",
                    "invalid PKWARE Strong validation size",
                ));
            }
            self.ranges.validation_size_checked = true;
        }
        self.validation = read(validation_offset + 6, validation_len, VALIDATION_FIELD)
            .ok()
            .and_then(|bytes| {
                let erd_prefix = if erd_prefix_len == 0 {
                    Arc::default()
                } else {
                    read(body_offset, erd_prefix_len, VALIDATION_FIELD)
                        .ok()?
                        .into()
                };
                Some(Validation {
                    erd_prefix,
                    erd_has_random_data: erd_len > BLOCK,
                    bytes: bytes.into(),
                })
            });
        Ok(())
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
        let master_cipher = C::new_from_slice(&master_key[..self.key_len]).unwrap();
        // The final CBC block is known full padding in the supported native
        // method. Reject before walking ERD or deriving the file key.
        if decrypt_block(&master_cipher, &self.erd_tail[0], &self.erd_tail[1])
            != [BLOCK as u8; BLOCK]
        {
            return Evidence::Reject;
        }
        let Some(validation) = &self.validation else {
            return Evidence::Possible;
        };
        let mut previous = &self.iv[..];
        let mut sha = Sha1::new_with_prefix(&self.iv[..self.iv_len]);
        for block in validation.erd_prefix.chunks_exact(BLOCK) {
            sha.update(decrypt_block(&master_cipher, previous, block));
            previous = block;
        }
        if validation.erd_has_random_data {
            sha.update(decrypt_block(&master_cipher, previous, &self.erd_tail[0]));
        }
        let file_key = derive_key(sha);
        let file_cipher = C::new_from_slice(&file_key[..self.key_len]).unwrap();
        let mut previous = &self.iv[..];
        let mut crc = crc32fast::Hasher::new();
        let mut blocks = validation.bytes.chunks_exact(BLOCK);
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
