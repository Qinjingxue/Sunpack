//! Standalone, bounded-memory benchmark fixture writer; no production API.
use std::{env, fs::{self, File}, io::{self, Read, Write}, path::PathBuf};

fn main() -> io::Result<()> {
    if env::args().nth(1).as_deref() == Some("--verify-output") {
        fn files(root: &std::path::Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
            for entry in fs::read_dir(root)? {
                let path = entry?.path();
                if path.is_dir() { files(&path, output)?; } else { output.push(path); }
            }
            Ok(())
        }
        fn equal(left: &std::path::Path, right: &std::path::Path) -> io::Result<()> {
            let (mut a, mut b) = (File::open(left)?, File::open(right)?);
            if a.metadata()?.len() != b.metadata()?.len() {
                return Err(io::Error::other("output length mismatch"));
            }
            let (mut x, mut y) = ([0u8; 65536], [0u8; 65536]);
            loop {
                let n = a.read(&mut x)?;
                if n == 0 { break; }
                b.read_exact(&mut y[..n])?;
                if x[..n] != y[..n] { return Err(io::Error::other("output bytes mismatch")); }
            }
            Ok(())
        }
        let fmt = env::args().nth(2).expect("format");
        let reference = PathBuf::from(env::args_os().nth(3).expect("reference"));
        let output = PathBuf::from(env::args_os().nth(4).expect("output root"));
        let mut actual = Vec::new();
        files(&output, &mut actual)?;
        if fmt == "gz" || fmt == "stream" {
            if actual.len() != 1 { return Err(io::Error::other("gzip file count")); }
            return equal(&reference, &actual[0]);
        }
        let expected = fs::read_dir(&reference)?.count();
        if actual.len() != expected { return Err(io::Error::other("zip file count")); }
        for file in actual { equal(&reference.join(file.file_name().unwrap()), &file)?; }
        return Ok(());
    }
    if env::args().nth(1).as_deref() == Some("--sync-tree") {
        fn sync_tree(path: &std::path::Path) -> io::Result<()> {
            if path.is_dir() {
                for entry in fs::read_dir(path)? { sync_tree(&entry?.path())?; }
            } else if path.is_file() {
                fs::OpenOptions::new().write(true).open(path)?.sync_all()?;
            }
            Ok(())
        }
        return sync_tree(&PathBuf::from(env::args_os().nth(2).expect("output root")));
    }
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
