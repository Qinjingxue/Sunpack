//! Pure CTR throughput, excluding KDF and disk I/O. Uses the production cipher.
//! cargo run --release -p sunpack-enc --example throughput -- 256 3 4
#[path = "../../native/sunpack_enc/src/cipher.rs"]
#[allow(dead_code)]
mod cipher;

use ::cipher::{Block, BlockEncrypt, KeyInit};
use std::{hint::black_box, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mib: usize = args.get(1).map_or(256, |v| v.parse().unwrap());
    let rounds: usize = args.get(2).map_or(3, |v| v.parse().unwrap());
    let threads: usize = args.get(3).map_or(1, |v| v.parse().unwrap());
    let algorithms: Option<Vec<u8>> = args
        .get(4)
        .map(|v| v.split(',').map(|code| code.parse().unwrap()).collect());
    assert!(mib > 0 && rounds > 0 && threads > 0);
    if args.get(5).is_some_and(|v| v == "raw-aes") {
        assert_eq!(threads, 1, "raw AES measures one hardware backend");
        let aes = aes::Aes256::new_from_slice(&[0x73; 32]).unwrap();
        let mut blocks = vec![Block::<aes::Aes256>::default(); 256 * 1024 / 16];
        println!("algorithm,threads,mib,round,ms,mib_per_second");
        for round in 0..rounds {
            let start = Instant::now();
            for _ in 0..mib * 4 {
                aes.encrypt_blocks(black_box(&mut blocks));
            }
            let elapsed = start.elapsed().as_secs_f64();
            black_box(&blocks);
            println!(
                "0,1,{mib},{round},{:.3},{:.3}",
                elapsed * 1000.0,
                mib as f64 / elapsed
            );
        }
        return;
    }
    let mut buffer = vec![0u8; 256 * 1024];
    println!("algorithm,threads,mib,round,ms,mib_per_second");
    for (code, key_len, nonce_len) in [
        (0, 32, 16),
        (1, 32, 16),
        (2, 32, 16),
        (3, 32, 8),
        (4, 32, 16),
        (5, 32, 8),
        (6, 56, 8),
        (7, 128, 128),
        (8, 64, 32),
        (9, 256, 192),
    ] {
        if algorithms
            .as_ref()
            .is_some_and(|codes| !codes.contains(&code))
        {
            continue;
        }
        for round in 0..rounds {
            let stream = cipher::Stream::new(code, &vec![0x73; key_len], &vec![0xff; nonce_len]);
            let start = Instant::now();
            for chunk in 0..mib * 4 {
                stream.apply_with_threads(
                    (chunk * 256 * 1024) as u64,
                    black_box(&mut buffer),
                    threads,
                );
            }
            let elapsed = start.elapsed().as_secs_f64();
            black_box(&buffer);
            println!(
                "{code},{threads},{mib},{round},{:.3},{:.3}",
                elapsed * 1000.0,
                mib as f64 / elapsed
            );
        }
    }
}
