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

#[test]
fn kdf_credit_counts_preserve_official_keys() {
    for fixture in [
        FIXTURES[2],
        FIXTURES[9],
        include_bytes!("../tests/data/params_10.enc"),
    ] {
        let header = Header::parse(fixture, fixture.len() as u64).unwrap();
        let serial = Workspace::with_threads(1)
            .derive(&header, &pw("sunpack-test"))
            .unwrap();
        for threads in [2, 3, 4] {
            let parallel = Workspace::with_threads(threads)
                .derive(&header, &pw("sunpack-test"))
                .unwrap();
            assert_eq!(parallel.key, serial.key);
            assert_eq!(parallel.nonce, serial.nonce);
            assert_eq!(parallel.auth, serial.auth);
        }
    }
}

#[test]
fn open_returns_kdf_credits_before_io_and_on_password_failure() {
    use std::cell::Cell;
    struct CheckedReader<'a> {
        input: Cursor<&'a [u8]>,
        held: &'a Cell<usize>,
    }
    impl Read for CheckedReader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            assert_eq!(self.held.get(), 0, "KDF credits held during input I/O");
            self.input.read(bytes)
        }
    }
    impl Seek for CheckedReader<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            assert_eq!(self.held.get(), 0, "KDF credits held during seek");
            self.input.seek(pos)
        }
    }
    let run = || {
        for grant in 0..=3 {
            for password in ["sunpack-test", "wrong"] {
                let held = Cell::new(0);
                let acquired = Cell::new(0);
                let mut input = CheckedReader {
                    input: Cursor::new(FIXTURES[9]),
                    held: &held,
                };
                let result = Decoder::open_with_budget(
                    &mut input,
                    FIXTURES[9].len() as u64,
                    &pw(password),
                    |wanted| {
                        assert_eq!(wanted, 3);
                        let extra = wanted.min(grant);
                        assert_eq!(held.get(), 0);
                        held.set(extra);
                        acquired.set(extra);
                        extra
                    },
                    |extra| {
                        assert!(held.get() >= extra);
                        held.set(held.get() - extra);
                    },
                );
                assert_eq!(held.get(), 0);
                if password == "wrong" {
                    assert!(matches!(result, Err(Error::Password)));
                } else {
                    assert_eq!(result.unwrap().output_size(), 192);
                }
                assert_eq!(acquired.get(), grant);
            }
        }
        // Invalid/short input is rejected before requesting CPU or KDF memory.
        for bytes in [&FIXTURES[0][..39], b"bad header".as_slice()] {
            assert!(Decoder::open_with_budget(
                &mut Cursor::new(bytes),
                bytes.len() as u64,
                &pw("sunpack-test"),
                |_| panic!("invalid header requested credits"),
                |_| panic!("unexpected release"),
            )
            .is_err());
        }
    };
    for threads in 1..=4 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(run);
    }
}
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
        .decrypt_with_budget(
            &mut input,
            &mut output,
            |_| 0,
            |_| (),
            |n| {
                progress.push(n);
                Ok(())
            },
        )
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
            .decrypt_with_budget(&mut input, &mut std::io::sink(), |_| 0, |_| (), |_| Ok(()))
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
                    .decrypt_with_budget(
                        &mut input,
                        &mut std::io::sink(),
                        |_| 0,
                        |_| (),
                        |_| Ok(())
                    )
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
            .decrypt_with_budget(
                &mut input,
                &mut std::io::sink(),
                |_| 0,
                |_| (),
                |_| Err(Error::Cancelled)
            )
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
        .decrypt_with_budget(&mut input, &mut output, |_| 0, |_| (), |_| Ok(()))
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

#[test]
fn ctr_offsets_match_official_vectors_and_full_counter_carries() {
    for fixture in FIXTURES {
        let header = Header::parse(fixture, fixture.len() as u64).unwrap();
        let keys = Workspace::default()
            .derive(&header, &pw("sunpack-test"))
            .unwrap();
        let mut stream = cipher::Stream::new(header.bytes[6], &keys.key, &keys.nonce);
        // Absolute offsets remain valid even after the serial cursor has advanced.
        stream.apply(&mut [0; 39]);
        for offset in [0, 1, 7, 8, 15, 16, 31, 32, 127, 128, 129, 223] {
            let mut bytes = fixture[40 + offset..fixture.len() - 32].to_vec();
            stream.apply_at(offset as u64, &mut bytes);
            let mut expected = vec![b'a'; 32];
            // Official quick blocks use random alphanumeric text; compare payload only.
            expected.extend_from_slice(include_bytes!("../tests/data/expected.zip"));
            let skip = 32usize.saturating_sub(offset);
            assert_eq!(&bytes[skip..], &expected[offset + skip..]);
        }
        // All sizes, especially C4's mixed block sizes, must carry across the
        // whole nonce and wrap identically to the serial full-width counter.
        let (_, nonce_len) = header.dimensions();
        let mut nonce = vec![0xff; nonce_len];
        nonce[nonce_len - 1] = 0xf8;
        let stream = cipher::Stream::new(header.bytes[6], &keys.key, &nonce);
        let mut serial = cipher::Stream::new(header.bytes[6], &keys.key, &nonce);
        let mut expected = vec![0x53; 4099];
        serial.apply(&mut expected);
        for chunk in [1, 7, 31, 129, 513, 2047, 2048, 2049, 4097] {
            let mut bytes = vec![0x53; expected.len()];
            for (index, part) in bytes.chunks_mut(chunk).enumerate() {
                stream.apply_at((index * chunk) as u64, part);
            }
            assert_eq!(bytes, expected);
        }
        if header.bytes[6] != 9 {
            let offset = (1u64 << 40) + 129;
            let size = nonce_len;
            // Starting at 2^(block bits)-8 wraps to block_index-8. Construct
            // that counter independently to cover offsets beyond 32 bits.
            let counter = offset / size as u64 - 8;
            let mut at_nonce = vec![0; nonce_len];
            at_nonce[nonce_len - 8..].copy_from_slice(&counter.to_be_bytes());
            let mut serial = cipher::Stream::new(header.bytes[6], &keys.key, &at_nonce);
            let mut skip = vec![0; offset as usize % size];
            serial.apply(&mut skip);
            let mut expected = vec![0x53; 513];
            serial.apply(&mut expected);
            let mut actual = vec![0x53; expected.len()];
            stream.apply_at(offset, &mut actual);
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn parallel_decryption_authenticates_multibuffer_payload_and_recovery() {
    for code in 0..10 {
        let mut header = Header::parse(FIXTURES[code], FIXTURES[code].len() as u64).unwrap();
        header.bytes[7] = 0;
        let keys = Workspace::default()
            .derive(&header, &pw("sunpack-test"))
            .unwrap();
        let plaintext: Vec<u8> = (0..(if code == 9 { 2 } else { 1 }) * 1024 * 1024 + 137)
            .map(|i| (i * 13) as u8)
            .collect();
        let mut bytes = header.bytes.to_vec();
        let mut encrypted = vec![b'a'; 32];
        encrypted.extend_from_slice(&plaintext);
        cipher::Stream::new(code as u8, &keys.key, &keys.nonce).apply(&mut encrypted);
        bytes.extend_from_slice(&encrypted);
        let encrypted_end = bytes.len() as u64;
        // A partial final decrypt chunk followed by authenticated recovery bytes.
        bytes.extend_from_slice(&vec![0x73; BUFFER + 193]);
        let mut mac = blake3::Hasher::new_keyed(&keys.auth);
        mac.update(&keys.nonce);
        mac.update(&bytes);
        bytes.extend_from_slice(mac.finalize().as_bytes());
        let decoder = Decoder {
            header,
            keys,
            packed: bytes.len() as u64,
            encrypted_end,
            framing_error: None,
        };
        for threads in [1usize, 2, 3, 4, 5, 8, 9] {
            let mut output = Vec::new();
            decoder
                .decrypt_with_budget(
                    &mut Cursor::new(&bytes),
                    &mut output,
                    |wanted| wanted.min(threads - 1),
                    |_| (),
                    |_| Ok(()),
                )
                .unwrap();
            assert_eq!(output, plaintext);
        }
        if code == 9 {
            for executor_threads in [1usize, 3] {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(executor_threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        use std::cell::Cell;
                        let position = Cell::new(PREFIX);
                        let held = Cell::new(0usize);
                        let requests = Cell::new(0usize);
                        let mut output = Vec::new();
                        decoder
                            .decrypt_with_budget(
                                &mut Cursor::new(&bytes),
                                &mut output,
                                |wanted| {
                                    let decrypt_n = encrypted_end
                                        .saturating_sub(position.get())
                                        .min(BUFFER as u64)
                                        as usize;
                                    assert_eq!(
                                        wanted,
                                        (decrypt_n / MIN_PARALLEL_CHUNK)
                                            .saturating_sub(1)
                                            .min(executor_threads - 1),
                                        "request exceeds data or executor capacity"
                                    );
                                    assert_eq!(held.get(), 0);
                                    requests.set(requests.get() + 1);
                                    held.set(wanted);
                                    wanted
                                },
                                |extra| {
                                    assert_eq!(held.get(), extra);
                                    held.set(0);
                                },
                                |current| {
                                    assert_eq!(held.get(), 0);
                                    position.set(current);
                                    Ok(())
                                },
                            )
                            .unwrap();
                        assert!(requests.get() > 0);
                        assert_eq!(held.get(), 0);
                        assert_eq!(output, plaintext);
                    });
            }
            rayon::ThreadPoolBuilder::new()
                .num_threads(9)
                .build()
                .unwrap()
                .install(|| {
                    use std::cell::{Cell, RefCell};
                    let held = Cell::new(0usize);
                    let grants = RefCell::new(Vec::new());
                    let next = Cell::new(0usize);
                    let acquire = |wanted: usize| {
                        assert_eq!(held.get(), 0);
                        let extra = [0, 1, 2, 4, 6, 3, 0, 5][next.get() % 8].min(wanted);
                        next.set(next.get() + 1);
                        grants.borrow_mut().push(extra);
                        held.set(extra);
                        extra
                    };
                    let release = |extra| {
                        assert!(held.get() >= extra);
                        held.set(held.get() - extra);
                    };
                    struct CheckedWriter<'a> {
                        held: &'a Cell<usize>,
                        bytes: Vec<u8>,
                        fail: bool,
                    }
                    impl Write for CheckedWriter<'_> {
                        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                            assert_eq!(
                                self.held.get(),
                                0,
                                "extra CPU credits held during output I/O"
                            );
                            if self.fail {
                                return Err(std::io::ErrorKind::Other.into());
                            }
                            self.bytes.extend_from_slice(bytes);
                            Ok(bytes.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> {
                            Ok(())
                        }
                    }
                    let mut output = CheckedWriter {
                        held: &held,
                        bytes: Vec::new(),
                        fail: false,
                    };
                    decoder
                        .decrypt_with_budget(
                            &mut Cursor::new(&bytes),
                            &mut output,
                            acquire,
                            release,
                            |_| {
                                assert_eq!(held.get(), 0, "credits held during progress callback");
                                Ok(())
                            },
                        )
                        .unwrap();
                    assert_eq!(output.bytes, plaintext);
                    assert_eq!(held.get(), 0);
                    assert_eq!(&grants.borrow()[..8], &[0, 1, 2, 4, 6, 3, 0, 5]);
                    // Progress cancellation must happen before any credit request.
                    assert_eq!(
                        decoder.decrypt_with_budget(
                            &mut Cursor::new(&bytes),
                            &mut std::io::sink(),
                            |_| panic!("credits requested after cancellation"),
                            |_| panic!("credits released without a request"),
                            |_| Err(Error::Cancelled)
                        ),
                        Err(Error::Cancelled)
                    );
                    assert_eq!(held.get(), 0);
                    output.fail = true;
                    assert_eq!(
                        decoder.decrypt_with_budget(
                            &mut Cursor::new(&bytes),
                            &mut output,
                            acquire,
                            release,
                            |_| Ok(())
                        ),
                        Err(Error::Io)
                    );
                    assert_eq!(held.get(), 0);
                });
        }
        let mut corrupt = bytes.clone();
        corrupt[encrypted_end as usize + 13] ^= 1;
        assert_eq!(
            decoder.decrypt_with_budget(
                &mut Cursor::new(&corrupt),
                &mut std::io::sink(),
                |wanted| wanted.min(3),
                |_| (),
                |_| Ok(())
            ),
            Err(Error::Authentication)
        );
        assert_eq!(
            decoder.decrypt_with_budget(
                &mut Cursor::new(&bytes),
                &mut std::io::sink(),
                |wanted| wanted.min(3),
                |_| (),
                |_| { Err(Error::Cancelled) }
            ),
            Err(Error::Cancelled)
        );
        assert_eq!(
            decoder.decrypt_with_budget(
                &mut Cursor::new(&bytes[..bytes.len() - 1]),
                &mut std::io::sink(),
                |wanted| wanted.min(3),
                |_| (),
                |_| Ok(())
            ),
            Err(Error::Truncated)
        );
    }
}
