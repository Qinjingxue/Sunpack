//! Test-only binary IO. No SunPack parser is used to construct or select fixtures.
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Request {
    Assemble {
        output: PathBuf,
        paths: Vec<PathBuf>,
        seed: u64,
        junk_min: usize,
        junk_max: usize,
        #[serde(default)]
        prefix_lengths: Option<Vec<usize>>,
        #[serde(default)]
        decoys: bool,
    },
    Inventory {
        root: PathBuf,
    },
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn junk(
    writer: &mut impl Write,
    state: &mut u64,
    length: usize,
    decoys: bool,
) -> io::Result<Value> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut written = 0;
    while written < length {
        let count = (length - written).min(buffer.len());
        for byte in &mut buffer[..count] {
            *byte = next(state) as u8;
        }
        // Invalid local ZIP / 7z headers with no valid directory or header CRC.
        // These are deliberate decoys, never obtained by querying a parser.
        if decoys && written == 0 && count >= 64 {
            buffer[..32].fill(0xff);
            buffer[..4].copy_from_slice(b"PK\x03\x04");
            buffer[32..64].fill(0xff);
            buffer[32..38].copy_from_slice(b"7z\xbc\xaf\x27\x1c");
        }
        writer.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        written += count;
    }
    Ok(json!({"length": length, "sha256": format!("{:x}", digest.finalize())}))
}

fn transfer(path: &Path, writer: &mut impl Write) -> io::Result<(u64, String)> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

fn inventory(root: &Path, directory: &Path, entries: &mut Vec<Value>) -> io::Result<()> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let kind = child.file_type()?;
        if kind.is_dir() {
            inventory(root, &path, entries)?;
        } else if kind.is_file() {
            let (size, sha256) = transfer(&path, &mut io::sink())?;
            entries.push(json!({
                "path": path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"),
                "size": size, "sha256": sha256,
            }));
        } else {
            return Err(io::Error::other(
                "fixture inventories require regular files",
            ));
        }
    }
    Ok(())
}

fn run(request: Request) -> io::Result<Value> {
    match request {
        Request::Inventory { root } => {
            let mut entries = Vec::new();
            inventory(&root, &root, &mut entries)?;
            Ok(json!({"files": entries}))
        }
        Request::Assemble {
            output,
            paths,
            seed,
            junk_min,
            junk_max,
            prefix_lengths,
            decoys,
        } => {
            if junk_min == 0
                || junk_min > junk_max
                || seed == 0
                || prefix_lengths
                    .as_ref()
                    .is_some_and(|items| items.len() != paths.len())
            {
                return Err(io::Error::other("invalid deterministic carrier layout"));
            }
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut writer = BufWriter::new(File::create(output)?);
            let mut state = seed;
            let mut offset = 0u64;
            let mut blocks = Vec::new();
            let mut segments = Vec::new();
            for (index, path) in paths.iter().enumerate() {
                let length = prefix_lengths
                    .as_ref()
                    .map(|items| items[index])
                    .unwrap_or_else(|| {
                        junk_min + next(&mut state) as usize % (junk_max - junk_min + 1)
                    });
                blocks.push(junk(&mut writer, &mut state, length, decoys)?);
                offset += length as u64;
                let (size, sha256) = transfer(path, &mut writer)?;
                segments.push(json!({"offset": offset, "length": size, "sha256": sha256}));
                offset += size;
            }
            let length = junk_min + next(&mut state) as usize % (junk_max - junk_min + 1);
            blocks.push(junk(&mut writer, &mut state, length, decoys)?);
            writer.flush()?;
            Ok(json!({"segments": segments, "junk_blocks": blocks}))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = serde_json::from_reader(io::stdin().lock())?;
    let result = run(request)?;
    serde_json::to_writer(io::stdout().lock(), &result)?;
    Ok(())
}
