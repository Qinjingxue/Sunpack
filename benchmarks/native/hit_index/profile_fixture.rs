//! Diagnostic inputs only. Binary IO and generation stay in Rust.
use std::io::{self, Write};
fn main() -> io::Result<()> {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).expect("output directory"));
    std::fs::create_dir_all(&root)?;
    let mut seed = 1729u64;
    let mut next = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    let mut data = vec![0u8; 64 * 1024 * 1024];
    std::fs::write(root.join("zero-64m.opaque"), &data)?;
    for word in data.chunks_exact_mut(8) { word.copy_from_slice(&next().to_le_bytes()); }
    std::fs::write(root.join("noise-64m.opaque"), &data)?;
    drop(data);
    for irregular in [false, true] {
        let name = if irregular { "false-zip-irregular" } else { "false-zip-arithmetic" };
        let mut out = io::BufWriter::new(std::fs::File::create(root.join(format!("{name}.opaque")))?);
        out.write_all(&[0xaf; 64])?;
        let mut header = [0u8; 30];
        header[..4].copy_from_slice(b"PK\x03\x04");
        header[4] = 20;
        // Pass fixed-header filtering, fail structural ZIP64 validation because
        // the required extra field is absent. No valid candidates are emitted.
        header[18..26].fill(0xff);
        header[26] = 1;
        for _ in 0..131072 {
            out.write_all(&header)?;
            let gap = if irregular { 33 + next() as usize % 480 } else { 128 };
            out.write_all(&[0xaf; 512][..gap - 30])?;
        }
        out.flush()?;
    }
    Ok(())
}
