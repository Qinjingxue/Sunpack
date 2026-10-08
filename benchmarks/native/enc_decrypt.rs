//! Authenticated streaming throughput to a null sink, excluding password KDF.
//! cargo run --release -p sunpack-enc --example decrypt -- input.enc sunpack-test 4 3
use std::{fs::File, io::sink, time::Instant};
use sunpack_enc::{Decoder, Workspace};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let threads: usize = args.get(3).map_or(1, |v| v.parse().unwrap());
    let rounds: usize = args.get(4).map_or(3, |v| v.parse().unwrap());
    let mut input = File::open(&args[1]).unwrap();
    let length = input.metadata().unwrap().len();
    let password: Vec<u16> = args[2].encode_utf16().collect();
    let decoder = Decoder::open(&mut input, length, &password, &mut Workspace::default()).unwrap();
    println!("threads,bytes,round,ms,mib_per_second");
    for round in 0..rounds {
        let start = Instant::now();
        decoder
            .decrypt_with_budget(
                &mut input,
                &mut sink(),
                |wanted| wanted.min(threads.saturating_sub(1)),
                |_| (),
                |_| Ok(()),
            )
            .unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "{threads},{},{round},{:.3},{:.3}",
            decoder.output_size(),
            elapsed * 1000.0,
            decoder.output_size() as f64 / (1024.0 * 1024.0) / elapsed
        );
    }
}
