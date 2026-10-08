//! 32B ENC quick-proof CTR latency, excluding KDF, key expansion and I/O.
//! Same CSV/arguments as throughput; MiB denotes the total 32B proof bytes.
#[path = "../../native/sunpack_enc/src/cipher.rs"]
#[allow(dead_code)]
mod cipher;

use std::{hint::black_box, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mib: usize = args.get(1).map_or(4, |s| s.parse().unwrap());
    let rounds: usize = args.get(2).map_or(9, |s| s.parse().unwrap());
    let threads: usize = args.get(3).map_or(1, |s| s.parse().unwrap());
    let algorithms: Option<Vec<u8>> = args
        .get(4)
        .map(|s| s.split(',').map(|code| code.parse().unwrap()).collect());
    assert!(mib > 0 && rounds > 0 && threads == 1);
    let count = mib.checked_mul(1024 * 1024 / 32).unwrap();
    let mut proof = [0u8; 32];
    println!("algorithm,threads,mib,round,ms,mib_per_second,ns_per_proof");
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
        let stream = cipher::Stream::new(code, &vec![0x73; key_len], &vec![0xff; nonce_len]);
        for round in 0..rounds {
            let start = Instant::now();
            for _ in 0..count {
                // Fresh CTR scratch at the real quick-proof offset and length.
                stream.apply_at(0, black_box(&mut proof));
            }
            black_box(&proof);
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "{code},1,{mib},{round},{:.3},{:.3},{:.3}",
                elapsed * 1000.0,
                mib as f64 / elapsed,
                elapsed * 1e9 / count as f64
            );
        }
    }
}
