//! Decode the Watch display store as an external consumer for acceptance tests.
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[link(name = "sunpack_lz4", kind = "static")]
extern "C" {
    fn LZ4_decompress_safe(
        source: *const u8,
        destination: *mut u8,
        size: i32,
        capacity: i32,
    ) -> i32;
}

#[derive(Deserialize)]
struct Run {
    name: String,
    head: u64,
    count: u64,
}

#[derive(Deserialize)]
struct Manifest {
    runs: Vec<Run>,
    live: Option<Run>,
}

fn decompress(
    reader: &mut impl Read,
    packed: u32,
    unpacked: u32,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    let size = i32::try_from(packed).map_err(io::Error::other)?;
    let capacity = i32::try_from(unpacked).map_err(io::Error::other)?;
    let mut compressed = vec![0; packed as usize];
    reader.read_exact(&mut compressed)?;
    let start = output.len();
    output.resize(start + unpacked as usize, 0);
    let actual = unsafe {
        LZ4_decompress_safe(
            compressed.as_ptr(),
            output[start..].as_mut_ptr(),
            size,
            capacity,
        )
    };
    if actual != capacity {
        return Err(io::Error::other("invalid Watch display record compression"));
    }
    Ok(())
}

fn read_run(folder: &Path, run: &Run) -> io::Result<Vec<Value>> {
    let mut index = BufReader::new(File::open(folder.join(format!("{}.index", run.name)))?);
    let mut data = BufReader::new(File::open(folder.join(format!("{}.data", run.name)))?);
    index.seek(SeekFrom::Start(run.head * 64))?;
    let mut rows = Vec::new();
    for _ in run.head..run.count {
        let mut item = [0; 64];
        index.read_exact(&mut item)?;
        if item[..24] == [0; 24] {
            continue;
        }
        let offset = u64::from_le_bytes(item[8..16].try_into().unwrap());
        let packed = u32::from_le_bytes(item[16..20].try_into().unwrap());
        let unpacked = u32::from_le_bytes(item[20..24].try_into().unwrap());
        data.seek(SeekFrom::Start(offset))?;
        let mut raw = Vec::new();
        if packed != 0 {
            decompress(&mut data, packed, unpacked, &mut raw)?;
        } else {
            let mut header = [0; 24];
            data.read_exact(&mut header)?;
            if header[..8] != *b"SPDC\0\0\0\0" {
                return Err(io::Error::other("invalid Watch display block header"));
            }
            let end = offset + u64::from_le_bytes(header[8..16].try_into().unwrap());
            let expected = u64::from_le_bytes(header[16..24].try_into().unwrap());
            while data.stream_position()? < end {
                let mut sizes = [0; 8];
                data.read_exact(&mut sizes)?;
                decompress(
                    &mut data,
                    u32::from_le_bytes(sizes[..4].try_into().unwrap()),
                    u32::from_le_bytes(sizes[4..].try_into().unwrap()),
                    &mut raw,
                )?;
            }
            if data.stream_position()? != end || raw.len() as u64 != expected {
                return Err(io::Error::other("invalid Watch display block size"));
            }
        }
        rows.push(rmp_serde::from_slice(&raw).map_err(io::Error::other)?);
    }
    Ok(rows)
}

pub(super) fn read(path: &Path) -> io::Result<Value> {
    let manifest: Manifest =
        serde_json::from_reader(File::open(path)?).map_err(io::Error::other)?;
    let mut directory = path.as_os_str().to_owned();
    directory.push(".store");
    let folder = Path::new(&directory);
    let mut history = Vec::new();
    for run in &manifest.runs {
        history.extend(read_run(folder, run)?);
    }
    let live = manifest
        .live
        .as_ref()
        .map(|run| read_run(folder, run))
        .transpose()?;
    Ok(json!({"history":history,"live":live.unwrap_or_default()}))
}
