use super::*;
use aes::cipher::BlockCipherEncrypt;

const MEMBER: &[u8] = b"a PKWARE Strong test member";

fn encrypt<C: BlockCipherEncrypt + KeyInit>(
    size: usize,
    key: &[u8; 32],
    mut iv: [u8; 16],
    bytes: &mut [u8],
) {
    let cipher = C::new_from_slice(&key[..size]).unwrap();
    for chunk in bytes.chunks_exact_mut(16) {
        let mut block = Block::<C>::default();
        for (i, &byte) in chunk.iter().enumerate() {
            block[i] = byte ^ iv[i];
        }
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        iv.copy_from_slice(chunk);
    }
}

fn archive<C: BlockCipherEncrypt + KeyInit>(
    algorithm: u16,
    size: usize,
    explicit_iv: bool,
) -> (Vec<u8>, usize, usize) {
    archive_member::<C>(algorithm, size, explicit_iv, 0, MEMBER)
}

fn archive_member<C: BlockCipherEncrypt + KeyInit>(algorithm: u16, size: usize,
    explicit_iv: bool, method: u16, packed: &[u8],
) -> (Vec<u8>, usize, usize) {
    let crc = crc32fast::hash(MEMBER);
    let mut iv = [0x9a; 16];
    let iv_len = if explicit_iv {
        16u16
    } else {
        iv[..4].copy_from_slice(&crc.to_le_bytes());
        iv[4..12].copy_from_slice(&(MEMBER.len() as u64).to_le_bytes());
        iv[12..].fill(0);
        0
    };
    let mut erd = [0x76; 48];
    erd[32..].fill(16);
    let mut sha = Sha1::new_with_prefix(&iv[..if explicit_iv { 16 } else { 12 }]);
    sha.update(&erd[..32]);
    let session = derive_key(sha);
    encrypt::<C>(
        size,
        &derive_key(Sha1::new_with_prefix(b"secret")),
        iv,
        &mut erd,
    );
    let mut encrypted = vec![0x43; 28];
    encrypted.extend(crc32fast::hash(&encrypted).to_le_bytes());
    encrypted.extend(packed);
    let padding = 16 - packed.len() % 16;
    encrypted.resize(encrypted.len() + padding, padding as u8);
    encrypt::<C>(size, &session, iv, &mut encrypted);
    let mut header = vec![0; 31];
    header[..4].copy_from_slice(super::super::ZIP_LOCAL);
    header[4] = 51;
    header[6] = 0x41;
    header[8..10].copy_from_slice(&method.to_le_bytes());
    header[14..18].copy_from_slice(&crc.to_le_bytes());
    header[18..22].copy_from_slice(
        &((6 + usize::from(iv_len) + 16 + erd.len() + encrypted.len()) as u32).to_le_bytes(),
    );
    header[22..26].copy_from_slice(&(MEMBER.len() as u32).to_le_bytes());
    header[26] = 1;
    header[30] = b'a';
    header.extend(iv_len.to_le_bytes());
    if explicit_iv {
        header.extend(iv);
    }
    header.extend(((16 + erd.len() + 32) as u32).to_le_bytes());
    header.extend(3u16.to_le_bytes());
    header.extend(algorithm.to_le_bytes());
    header.extend(((size * 8) as u16).to_le_bytes());
    let flags = header.len();
    header.extend(1u16.to_le_bytes());
    header.extend((erd.len() as u16).to_le_bytes());
    header.extend(erd);
    header.extend(0u32.to_le_bytes());
    header.extend(32u16.to_le_bytes());
    let validation = header.len();
    header.extend(encrypted);
    (header, flags, validation)
}

#[test]
fn pkware_strong_rejects_alternative_ciphertext_after_shared_validation() {
    use super::super::{local_anchor_tests::volume_alternatives, zip_fast_verify_passwords_from_attempts, Preparation};
    let mut packed = vec![1]; // Final stored Deflate block.
    packed.extend_from_slice(&(MEMBER.len() as u16).to_le_bytes());
    packed.extend_from_slice(&(!(MEMBER.len() as u16)).to_le_bytes());
    packed.extend_from_slice(MEMBER);
    let (good, _, validation) = archive_member::<Aes256>(0x6610, 32, true, 8, &packed);
    packed[0] = 7; // Forbidden BTYPE with valid ERD and VData.
    let (bad, _, _) = archive_member::<Aes256>(0x6610, 32, true, 8, &packed);
    let start = validation + 32;
    assert_eq!(good[..start], bad[..start]);
    let (paths, sources, plan) = volume_alternatives(&good[..start], &bad[start..], &good[start..]);
    let mut preparation = Preparation::default();
    let proof = zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
        &[Arc::from("wrong"), Arc::from("secret")], false, None, &[]).unwrap();
    assert_eq!(proof.matched_indices, [1]);
    assert_eq!(proof.final_confirmation_required, Some(false));
    let reduced = proof.volume_attempts.expect("contradicting tail was removed");
    assert_eq!(reduced.sources.len(), 2);
    assert_eq!(reduced.sources[1].path, sources[2].path);
    drop(preparation);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn pkware_strong_screens_xz_block_beyond_the_first_cbc_block() {
    use super::super::{local_anchor_tests::{volume_alternatives, xz_payload},
        zip_fast_verify_passwords_from_attempts, Preparation};
    let mut packed = xz_payload(MEMBER);
    let (good, _, validation) = archive_member::<Aes256>(0x6610, 32, true, 95, &packed);
    let block_end = 12 + (usize::from(packed[12]) + 1) * 4;
    packed[block_end - 1] ^= 1;
    let (bad, _, _) = archive_member::<Aes256>(0x6610, 32, true, 95, &packed);
    let split = validation + 32 + 16;
    assert_eq!(good[..split], bad[..split]);
    let (paths, sources, plan) = volume_alternatives(&good[..split], &bad[split..], &good[split..]);
    let mut preparation = Preparation::default();
    let proof = zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
        &[Arc::from("wrong"), Arc::from("secret")], false, None, &[]).unwrap();
    assert_eq!(proof.matched_indices, [1]);
    assert_eq!(proof.final_confirmation_required, Some(false));
    let reduced = proof.volume_attempts.expect("XZ header ruled out the wrong volume");
    assert_eq!(reduced.sources.len(), 2);
    assert_eq!(reduced.sources[1].path, sources[2].path);
    drop(preparation);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn pkware_strong_structural_proof_across_disk_and_damage() {
    use super::super::{prepare_zip_stream_from, prepare_zip_volumes, RangeSpec, ZipReadInput};
    use crate::io::reader::{ManagedReader, ReaderConfig};
    use crate::password::input::{VolumeSet, VolumeSpec};
    for (mut bytes, flags, validation) in [
        archive::<Aes128>(0x660e, 16, false),
        archive::<Aes192>(0x660f, 24, true),
        archive::<Aes256>(0x6610, 32, true),
    ] {
        let password = [Arc::from("wrong"), Arc::from("secret"), Arc::from("other")];
        let split = validation + 9;
        let part = |data: &[u8], number| VolumeSpec {
            reader: ManagedReader::from_bytes(data.to_vec(), ReaderConfig::default()),
            number,
            start: 0,
            end: None,
        };
        let volumes = Arc::new(VolumeSet::new(vec![part(&bytes[..split], 1), part(&bytes[split..], 2)]));
        let context = prepare_zip_volumes(&volumes, None)
            .unwrap_or_else(|_| panic!("complete split password header"));
        let proof = context.verify(&password).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.match_evidence, Some("zip_pkware_strong_vcrc32"));
        assert_eq!(proof.final_confirmation_required, Some(false));
        let volumes = Arc::new(VolumeSet::new(vec![part(&bytes[..split], 1), part(&bytes[split..], 3)]));
        let context = prepare_zip_volumes(&volumes, None)
            .unwrap_or_else(|_| panic!("ERD tail remains usable without the validation range"));
        let proof = context.verify(&password).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.match_evidence, Some("zip_pkware_strong_padding"));
        assert_eq!(proof.final_confirmation_required, Some(true));

        bytes[validation] ^= 1;
        let prepare = |bytes: &[u8]| {
            let reader = ManagedReader::from_bytes(bytes.to_vec(), ReaderConfig::default());
            let input = ZipReadInput::Ranges(Arc::from([RangeSpec::entire(&reader)]));
            prepare_zip_stream_from(&mut reader.cursor(), reader.len(), None, Some(&input))
        };
        let context = prepare(&bytes)
            .unwrap_or_else(|_| panic!("complete header with damaged validation ciphertext"));
        let proof = context.verify(&password).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.final_confirmation_required, Some(true));
        bytes[flags] = 3;
        assert!(matches!(
            prepare(&bytes),
            Err(PreparedStatus::Status("unsupported_method", _))
        ));
    }
}
