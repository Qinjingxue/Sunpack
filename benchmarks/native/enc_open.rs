//! Worker Open/KDF with a fixed CPU budget; includes arena allocation and wipe.
//! cargo run --release -p sunpack-enc --example open -- input.enc sunpack-test 4 11
use std::{fs::File, time::Instant};
use sunpack_enc::Decoder;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let threads: usize = args.get(3).map_or(1, |v| v.parse().unwrap());
    let rounds: usize = args.get(4).map_or(11, |v| v.parse().unwrap());
    assert!(threads > 0 && rounds > 0);
    let mut input = File::open(&args[1]).unwrap();
    let length = input.metadata().unwrap().len();
    let password: Vec<u16> = args[2].encode_utf16().collect();
    println!("threads,bytes,round,ms");
    for round in 0..rounds {
        let start = Instant::now();
        let decoder = Decoder::open_with_budget(
            &mut input,
            length,
            &password,
            |wanted| wanted.min(threads - 1),
            |_| (),
        )
        .unwrap();
        std::hint::black_box(decoder);
        println!(
            "{threads},{length},{round},{:.3}",
            start.elapsed().as_secs_f64() * 1000.0
        );
    }
}
