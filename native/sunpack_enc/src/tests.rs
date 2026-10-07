use super::*;
use std::io::Cursor;
const FIXTURES: [&[u8]; 10] = [
    include_bytes!("../tests/data/algorithm_0.mov"),
    include_bytes!("../tests/data/algorithm_1.mov"),
    include_bytes!("../tests/data/algorithm_2.mov"),
    include_bytes!("../tests/data/algorithm_3.mov"),
    include_bytes!("../tests/data/algorithm_4.mov"),
    include_bytes!("../tests/data/algorithm_5.mov"),
    include_bytes!("../tests/data/algorithm_6.mov"),
    include_bytes!("../tests/data/algorithm_7.mov"),
    include_bytes!("../tests/data/algorithm_8.mov"),
    include_bytes!("../tests/data/algorithm_9.mov"),
];
fn pw(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn decode(bytes: &[u8], password: &str, expected: &[u8]) {
    let mut workspace = Workspace::default();
    let mut input = Cursor::new(bytes);
    let decoder = Decoder::open(
        &mut input,
        bytes.len() as u64,
        &pw(password),
        &mut workspace,
    )
    .unwrap();
    assert_eq!(decoder.output_size(), expected.len() as u64);
    let mut output = Vec::new();
    let mut progress = Vec::new();
    decoder
        .decrypt(&mut input, &mut output, |n| {
            progress.push(n);
            Ok(())
        })
        .unwrap();
    assert_eq!(output, expected);
    assert_eq!(progress.last(), Some(&(bytes.len() as u64)));
}
#[test]
fn official_all_cipher_and_kdf_vectors() {
    let expected = include_bytes!("../tests/data/expected.zip");
    for fixture in FIXTURES {
        decode(fixture, "sunpack-test", expected);
    }
    for fixture in [
        include_bytes!("../tests/data/params_01.enc").as_slice(),
        include_bytes!("../tests/data/params_10.enc").as_slice(),
    ] {
        decode(fixture, "sunpack-test", expected);
    }
    decode(
        include_bytes!("../tests/data/unicode.enc"),
        "contraseña中文😀",
        expected,
    );
    decode(
        include_bytes!("../tests/data/recovery.enc"),
        "sunpack-test",
        include_bytes!("../tests/data/recovery.zip"),
    );
}
#[test]
fn bounded_batch_reuses_one_workspace_without_payload_reads() {
    let data = FIXTURES[0];
    let password = pw("sunpack-test");
    let mut workspace = Workspace::default();
    let probe = PasswordProbe::read(&mut Cursor::new(data), data.len() as u64).unwrap();
    for wrong in ["wrong1", "wrong2", "wrong3"] {
        assert!(!probe.matches(&pw(wrong), &mut workspace).unwrap());
    }
    assert_eq!(workspace.kdf_runs, 3);
    let memory = workspace.memory.as_ptr();
    assert!(probe.matches(&password, &mut workspace).unwrap());
    assert_eq!(workspace.memory.as_ptr(), memory);
    assert_eq!(workspace.memory.len(), 10240);
    assert_eq!(workspace.kdf_runs, 4);
    // Extraction derives the selected password independently, with no process
    // crossing key cache or long-lived Argon2 workspace.
    let mut changed = data.to_vec();
    changed[40] ^= 0xff;
    let changed_probe =
        PasswordProbe::read(&mut Cursor::new(&changed), changed.len() as u64).unwrap();
    assert!(!changed_probe.matches(&password, &mut workspace).unwrap());
}
#[test]
fn password_probe_read_cost_does_not_scale_with_payload() {
    struct Sparse {
        position: u64,
        read: usize,
    }
    impl Read for Sparse {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.read += out.len();
            out.fill(0);
            if self.position < 72 {
                let start = self.position as usize;
                let n = out.len().min(72 - start);
                out[..n].copy_from_slice(&FIXTURES[0][start..start + n]);
            }
            self.position += out.len() as u64;
            Ok(out.len())
        }
    }
    impl Seek for Sparse {
        fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
            let SeekFrom::Start(p) = s else { panic!() };
            self.position = p;
            Ok(p)
        }
    }
    for length in [FIXTURES[0].len() as u64, 1 << 30, 1 << 40] {
        let mut input = Sparse {
            position: 0,
            read: 0,
        };
        let probe = PasswordProbe::read(&mut input, length).unwrap();
        let mut workspace = Workspace::default();
        for password in ["wrong1", "wrong2", "sunpack-test"] {
            assert_eq!(
                probe.matches(&pw(password), &mut workspace).unwrap(),
                password == "sunpack-test"
            );
        }
        assert_eq!(input.read, 72);
    }
}
#[test]
fn corruption_cancellation_and_short_reads() {
    let recovery = include_bytes!("../tests/data/recovery.enc");
    let mut damaged = recovery.to_vec();
    damaged[recovery.len() - 120] ^= 1; // Recovery trailer framing, before its CRC.
    let mut input = Cursor::new(&damaged);
    assert!(PasswordProbe::read(&mut input, damaged.len() as u64)
        .unwrap()
        .matches(&pw("sunpack-test"), &mut Workspace::default())
        .unwrap());
    let decoder = Decoder::open(
        &mut input,
        damaged.len() as u64,
        &pw("sunpack-test"),
        &mut Workspace::default(),
    )
    .unwrap();
    assert_eq!(decoder.output_size(), 0);
    assert_eq!(
        decoder
            .decrypt(&mut input, &mut std::io::sink(), |_| Ok(()))
            .unwrap_err(),
        Error::Framing
    );
    for fixture in [
        FIXTURES[0],
        include_bytes!("../tests/data/recovery.enc").as_slice(),
    ] {
        for offset in [80, fixture.len() - 1] {
            let mut damaged = fixture.to_vec();
            damaged[offset] ^= 1;
            let mut input = Cursor::new(&damaged);
            let decoder = Decoder::open(
                &mut input,
                damaged.len() as u64,
                &pw("sunpack-test"),
                &mut Workspace::default(),
            )
            .unwrap();
            assert_eq!(
                decoder
                    .decrypt(&mut input, &mut std::io::sink(), |_| Ok(()))
                    .unwrap_err(),
                Error::Authentication
            );
        }
    }
    let data = FIXTURES[0];
    let mut input = Cursor::new(data);
    let decoder = Decoder::open(
        &mut input,
        data.len() as u64,
        &pw("sunpack-test"),
        &mut Workspace::default(),
    )
    .unwrap();
    assert_eq!(
        decoder
            .decrypt(&mut input, &mut std::io::sink(), |_| Err(Error::Cancelled))
            .unwrap_err(),
        Error::Cancelled
    );
    struct Short<R>(R);
    impl<R: Read> Read for Short<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(7);
            self.0.read(&mut out[..n])
        }
    }
    impl<R: Seek> Seek for Short<R> {
        fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(s)
        }
    }
    let mut input = Short(Cursor::new(data));
    let decoder = Decoder::open(
        &mut input,
        data.len() as u64,
        &pw("sunpack-test"),
        &mut Workspace::default(),
    )
    .unwrap();
    let mut output = Vec::new();
    decoder
        .decrypt(&mut input, &mut output, |_| Ok(()))
        .unwrap();
    assert_eq!(output, include_bytes!("../tests/data/expected.zip"));
}
#[test]
fn ctr_arbitrary_chunking_matches_official_all_ciphers() {
    for fixture in FIXTURES {
        let header = Header::parse(fixture, fixture.len() as u64).unwrap();
        let keys = Workspace::default()
            .derive(&header, &pw("sunpack-test"))
            .unwrap();
        for chunk in [1, 7, 15, 31, 32, 127, 129] {
            let mut bytes = fixture[40..fixture.len() - 32].to_vec();
            let mut stream = cipher::Stream::new(header.bytes[6], &keys.key, &keys.nonce);
            for part in bytes.chunks_mut(chunk) {
                stream.apply(part);
            }
            assert_eq!(&bytes[32..], include_bytes!("../tests/data/expected.zip"));
        }
    }
}
#[test]
fn static_identity_never_runs_kdf() {
    for length in [0, 39, 40, 72, 103] {
        assert!(Header::parse(FIXTURES[0], length).is_err());
    }
    for code in [10, 255] {
        let mut data = FIXTURES[0].to_vec();
        data[6] = code;
        assert!(Header::parse(&data, data.len() as u64).is_err());
    }
    for params in 0..=255 {
        let mut data = FIXTURES[0].to_vec();
        data[7] = params;
        assert!(Header::parse(&data, data.len() as u64).is_ok());
    }
}
