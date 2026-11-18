//! PKWARE APPNOTE §7.2.4 password-only AES decryption header.
use super::{
    le_u16, le_u32, zip_password_bytes, PasswordVerification, PreparedStatus, ZipKey, ZipKeyCache,
    ZipKeyMaterial,
};
use super::probe::{read_reason, CheckRead, ZipPrefix, ZipRead};
use crate::formats::zip::zip64::CentralValues;
use crate::io::cancellation::Cancellation;
use crate::password::input::attempts::DeferredReadError;
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
    erd_tail: [[u8; BLOCK]; 2],
    ranges: ValidationRanges,
    source: Option<ZipRead>,
    prefix: Option<ZipPrefix>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ValidationRanges {
    body_offset: u64,
    erd_len: usize,
    validation_len: usize,
}

struct Validation {
    erd_prefix: Vec<u8>,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValidationMatch {
    CrcMismatch,
    BodyContradiction,
    Proven,
}

struct ValidationEvidence {
    matches: Vec<ValidationMatch>,
    body_issue: Option<DeferredReadError>,
}

enum ValidationUnavailable {
    Read(DeferredReadError),
    Certificate,
    InvalidSize,
}

impl ValidationUnavailable {
    fn reason(&self) -> String {
        match self {
            Self::Certificate => "unsupported certificate data".into(),
            Self::InvalidSize => "validation length disagrees with the decryption header".into(),
            Self::Read(error) => read_reason(error),
        }
    }

    fn contradicts_header(&self) -> bool {
        // These bytes have already been located by a password-only header.
        matches!(self, Self::Certificate | Self::InvalidSize | Self::Read(DeferredReadError::Truncated))
    }
}

impl PasswordHeader {
    pub(super) fn read(
        method: u16,
        flags: u16,
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
        let body_start = body_offset + erd_len as u64 + 6 + validation_len as u64;
        Ok(Self {
            iv,
            iv_len,
            key_len,
            erd_tail,
            ranges: ValidationRanges {
                body_offset,
                erd_len,
                validation_len,
            },
            source: None,
            prefix: ZipPrefix::new(method, flags, body_start, body_start, sizes_and_crc.map(|(sizes, _)| sizes)),
        })
    }

    pub(super) fn bind(&mut self, source: ZipRead) {
        self.source = Some(source);
    }

    pub(super) fn set_sizes(&mut self, sizes: Option<&CentralValues>) {
        self.prefix = self.prefix.take().map(|prefix| prefix.with_sizes(sizes));
    }

    pub(super) fn needs_sizes(&self) -> bool {
        self.prefix.as_ref().is_some_and(ZipPrefix::needs_size)
    }

    fn load_validation(&self, read: &mut CheckRead<'_>) -> Result<Validation, ValidationUnavailable> {
        let ValidationRanges {
            body_offset,
            erd_len,
            validation_len,
        } = self.ranges;
        let erd_prefix_len = erd_len.saturating_sub(2 * BLOCK);
        let validation_offset = body_offset + erd_len as u64;
        let lengths = read(validation_offset, 6).map_err(ValidationUnavailable::Read)?;
        if le_u32(&lengths, 0) != Some(0) {
            return Err(ValidationUnavailable::Certificate);
        }
        if le_u16(&lengths, 4) != Some(validation_len as u16) {
            return Err(ValidationUnavailable::InvalidSize);
        }
        let bytes = read(validation_offset + 6, validation_len).map_err(ValidationUnavailable::Read)?;
        let erd_prefix = if erd_prefix_len == 0 { Vec::new() }
            else { read(body_offset, erd_prefix_len).map_err(ValidationUnavailable::Read)? };
        Ok(Validation { erd_prefix, bytes })
    }

    pub(super) fn verify(
        &self,
        candidates: &[Arc<str>],
        cache: Option<&ZipKeyCache>,
    ) -> std::io::Result<PasswordVerification> {
        match self.key_len {
            16 => self.verify_aes::<Aes128>(candidates, cache),
            24 => self.verify_aes::<Aes192>(candidates, cache),
            32 => self.verify_aes::<Aes256>(candidates, cache),
            _ => unreachable!(),
        }
    }

    fn verify_aes<C: BlockCipherDecrypt + KeyInit + Send>(
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
            let local;
            let material = if let Some(slots) = slots { slots[index].get_or_init(derive) }
                else { local = derive(); &local };
            let Some(ZipKey::Strong(key)) = material else { return None; };
            let cipher = C::new_from_slice(&key[..self.key_len]).unwrap();
            (decrypt_block(&cipher, &self.erd_tail[0], &self.erd_tail[1])
                == [BLOCK as u8; BLOCK]).then_some((index, cipher))
        };
        let survivors: Vec<_> = if candidates.len() >= 32 {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(check)
                .collect()
        } else {
            candidates.iter().enumerate().filter_map(check).collect()
        };
        cancellation.check_io()?;
        if survivors.is_empty() {
            return Ok(PasswordVerification {
                attempts: candidates.len(),
                ..PasswordVerification::status("no_match", "PKWARE Strong ERD padding did not match")
            });
        }
        // Only padding survivors may load the optional VData and ERD prefix.
        let checks = if let Some(source) = &self.source {
            let body = self.prefix.as_ref().and_then(|prefix| {
                let offset = prefix.cbc_first_block_offset()?;
                source.ambiguous(offset, BLOCK as u64).then_some((prefix, offset))
            });
            source.evaluate(|read| -> Result<ValidationEvidence, ValidationUnavailable> {
                let validation = self.load_validation(read)?;
                let mut first_body_block = None;
                let matches = survivors.iter().map(|(_, cipher)| {
                    let Some(file_cipher) = self.check_validation(cipher, &validation) else {
                        return ValidationMatch::CrcMismatch;
                    };
                    if let Some((prefix, offset)) = body {
                        // VData is the first ciphertext in this CBC stream.
                        // Its final block is already available as the chaining
                        // value for the adjacent compression header.
                        match first_body_block.get_or_insert_with(|| read(offset, BLOCK)) {
                            Ok(bytes) => {
                                let previous = validation.bytes.last_chunk::<BLOCK>().unwrap();
                                let plain = decrypt_block(&file_cipher, previous, bytes);
                                if prefix.check_plain(&plain) == Some(false) {
                                    return ValidationMatch::BodyContradiction;
                                }
                            }
                            Err(DeferredReadError::Truncated) => return ValidationMatch::BodyContradiction,
                            Err(_) => {}
                        }
                    }
                    ValidationMatch::Proven
                }).collect();
                Ok(ValidationEvidence {
                    matches,
                    body_issue: first_body_block.and_then(Result::err),
                })
            })?
        } else { Vec::new() };
        let unavailable = checks.iter().find_map(|(_, check)| {
            check.as_ref().err().filter(|error| !error.contradicts_header())
        });
        let viable_body = checks.iter().any(|(_, check)| {
            check.as_ref().is_ok_and(|evidence| evidence.matches.contains(&ValidationMatch::Proven))
        });
        let crc_matches = viable_body || checks.iter().any(|(_, check)| check.as_ref().is_ok_and(
            |evidence| evidence.matches.contains(&ValidationMatch::BodyContradiction)));
        let reason = if let Some(error) = checks.iter().find_map(|(_, check)| check.as_ref().err()) {
            error.reason()
        } else if checks.is_empty() {
            "validation range is unavailable".into()
        } else if !crc_matches {
            "validation CRC did not match".into()
        } else {
            "validation CRC is not unique across volume choices".into()
        };
        let mut result = PasswordVerification::status("match",
            format!("PKWARE Strong password padding matched; {reason}"));
        result.attempts = candidates.len();
        for (position, (index, _)) in survivors.into_iter().enumerate() {
            let compatible = |proof: ValidationMatch| {
                proof == ValidationMatch::Proven || (!viable_body && proof == ValidationMatch::BodyContradiction)
            };
            let matched = checks.iter().any(|(_, check)| check.as_ref()
                .is_ok_and(|evidence| compatible(evidence.matches[position])));
            if matched || !crc_matches || unavailable.is_some() {
                result.matched_indices.push(index);
            }
            if crc_matches {
                for (scope, check) in &checks {
                    if let Some(scope) = scope {
                        // A valid VCRC can establish the password even when
                        // the particular member body contradicts this layout.
                        if match check {
                            Ok(evidence) => evidence.matches[position] != ValidationMatch::Proven,
                            Err(error) => error.contradicts_header(),
                        } {
                            result.scoped_rejections.push((scope.clone(), index));
                        }
                    }
                }
            }
        }
        result.matched_index = result.matched_indices.first().copied();
        let strong = crc_matches && unavailable.is_none() && result.matched_indices.len() == 1;
        result.final_confirmation_required = Some(!strong);
        result.match_evidence = Some(if strong {
            let body_issue = checks.iter().find_map(|(_, check)| check.as_ref().ok()?.body_issue.as_ref());
            result.message = if let Some(error) = body_issue {
                format!("PKWARE Strong password validation CRC matched; {}", read_reason(error))
            } else if !viable_body {
                "PKWARE Strong password validation CRC matched; member compression header is invalid".into()
            } else {
                "PKWARE Strong password validation CRC matched".into()
            };
            "zip_pkware_strong_vcrc32"
        } else {
            "zip_pkware_strong_padding"
        });
        Ok(result)
    }

    fn check_validation<C: BlockCipherDecrypt + KeyInit>(
        &self, master_cipher: &C, validation: &Validation,
    ) -> Option<C> {
        let mut previous = &self.iv[..];
        let mut sha = Sha1::new_with_prefix(&self.iv[..self.iv_len]);
        for block in validation.erd_prefix.chunks_exact(BLOCK) {
            sha.update(decrypt_block(master_cipher, previous, block));
            previous = block;
        }
        if self.ranges.erd_len > BLOCK {
            sha.update(decrypt_block(master_cipher, previous, &self.erd_tail[0]));
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
        (crc.finalize() == le_u32(&last, BLOCK - 4).unwrap()).then_some(file_cipher)
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
