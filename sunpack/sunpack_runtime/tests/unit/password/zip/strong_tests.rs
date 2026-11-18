use super::*;
use aes::cipher::BlockCipherEncrypt;

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
    let member = b"a PKWARE Strong test member";
    let crc = crc32fast::hash(member);
    let mut iv = [0x9a; 16];
    let iv_len = if explicit_iv {
        16u16
    } else {
        iv[..4].copy_from_slice(&crc.to_le_bytes());
        iv[4..12].copy_from_slice(&(member.len() as u64).to_le_bytes());
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
    encrypted.extend(member);
    let padding = 16 - member.len() % 16;
    encrypted.resize(encrypted.len() + padding, padding as u8);
    encrypt::<C>(size, &session, iv, &mut encrypted);
    let mut header = vec![0; 31];
    header[..4].copy_from_slice(super::super::ZIP_LOCAL);
    header[4] = 51;
    header[6] = 0x41;
    header[14..18].copy_from_slice(&crc.to_le_bytes());
    header[18..22].copy_from_slice(
        &((6 + usize::from(iv_len) + 16 + erd.len() + encrypted.len()) as u32).to_le_bytes(),
    );
    header[22..26].copy_from_slice(&(member.len() as u32).to_le_bytes());
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
fn pkware_strong_structural_proof_across_disk_and_damage() {
    use super::super::{prepare_zip_stream, prepare_zip_volumes};
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
        let volumes = VolumeSet::new(vec![part(&bytes[..split], 1), part(&bytes[split..], 2)]);
        let context = prepare_zip_volumes(&volumes, None)
            .unwrap_or_else(|_| panic!("complete split password header"));
        let proof = context.verify(&password).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.match_evidence, Some("zip_pkware_strong_vcrc32"));
        assert_eq!(proof.final_confirmation_required, Some(false));
        let volumes = VolumeSet::new(vec![part(&bytes[..split], 1), part(&bytes[split..], 3)]);
        assert!(prepare_zip_volumes(&volumes, None).is_err());

        bytes[validation] ^= 1;
        let context =
            prepare_zip_stream(&mut std::io::Cursor::new(&bytes), bytes.len() as u64, None)
                .unwrap_or_else(|_| panic!("complete header with damaged validation ciphertext"));
        let proof = context.verify(&password).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.final_confirmation_required, Some(true));
        bytes[flags] = 3;
        assert!(matches!(
            prepare_zip_stream(&mut std::io::Cursor::new(&bytes), bytes.len() as u64, None),
            Err(PreparedStatus::Status("unsupported_method", _))
        ));
    }
}
