//! Standalone, bounded-memory benchmark fixture writer; no production API.
use std::{env, fs::{self, File}, io::{self, Write}, path::PathBuf};

fn main() -> io::Result<()> {
    if env::args().nth(1).as_deref() == Some("--copy") {
        fs::copy(env::args_os().nth(2).expect("source"), env::args_os().nth(3).expect("destination"))?;
        return Ok(());
    }
    let root = PathBuf::from(env::args_os().nth(1).expect("payload root"));
    let mib: usize = env::args().nth(2).expect("MiB per large file").parse().expect("integer MiB");
    let small = root.join("many-small");
    let large = root.join("few-large");
    fs::create_dir_all(&small)?;
    fs::create_dir_all(&large)?;
    let mut state = 20260729_u64;
    let mut random = vec![0_u8; 1024 * 1024];
    let pattern = b"sunpack-benchmark\n";
    let text: Vec<u8> = (0..random.len()).map(|i| pattern[i % pattern.len()]).collect();
    for index in 0..2 {
        let mut file = File::create(large.join(format!("large-{index:02}.bin")))?;
        for _ in 0..mib {
            if index == 0 {
                file.write_all(&text)?;
            } else {
                for bytes in random.chunks_exact_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    bytes.copy_from_slice(&state.to_le_bytes());
                }
                file.write_all(&random)?;
            }
        }
    }
    for index in 0..8 {
        File::create(small.join(format!("file-{index:05}.bin")))?.write_all(&random[..1024])?;
    }
    Ok(())
}
