//! Keyed streaming BLAKE3, including ENC's unaligned nonce+header prefix.
#[path = "enc_mac_bounded.rs"]
#[allow(dead_code)]
mod mac;
use std::{hint::black_box, time::Instant};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mib: usize = args.get(1).map_or(256, |s| s.parse().unwrap());
    let rounds: usize = args.get(2).map_or(7, |s| s.parse().unwrap());
    let threads: usize = args.get(3).map_or(1, |s| s.parse().unwrap());
    let mode = args.get(4).map_or("bounded", String::as_str);
    assert!(mib > 0 && rounds > 0 && threads > 0);
    assert!(matches!(mode, "serial" | "bounded"));
    #[cfg(not(feature = "parallel-decrypt"))]
    assert_eq!(threads, 1, "enable parallel-decrypt for multiple threads");
    let data = vec![0x73; 256 * 1024];
    let key = [0x93; 32];
    println!("mode,threads,mib,round,ms,mib_per_second");
    for round in 0..rounds {
        let start = Instant::now();
        if mode == "serial" {
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&[0x35; 56]);
            for _ in 0..mib * 4 {
                hasher.update(black_box(&data));
            }
            black_box(hasher.finalize());
        } else {
            let mut hasher = mac::Authenticator::new(&key);
            hasher.update(&[0x35; 56], 1);
            for _ in 0..mib * 4 {
                hasher.update(black_box(&data), threads);
            }
            black_box(hasher.finalize());
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "{mode},{threads},{mib},{round},{:.3},{:.3}",
            elapsed * 1000.0,
            mib as f64 / elapsed
        );
    }
}
