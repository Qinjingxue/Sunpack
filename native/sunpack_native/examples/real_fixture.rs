//! Test-only binary IO. No SunPack parser is used to construct or select fixtures.
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
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
    Lz4 {
        output: PathBuf,
        paths: Vec<PathBuf>,
    },
    SevenZipLz4Header {
        source: PathBuf,
        output: PathBuf,
    },
    ZipMethod {
        output: PathBuf,
        method: u16,
    },
    Flip {
        path: PathBuf,
        offset: u64,
    },
    Copy {
        source: PathBuf,
        output: PathBuf,
    },
}

// Independent APPNOTE fixture for methods the archive generator cannot encode.
// Unsupported methods deliberately contain opaque bytes: the decoder must
// report unsupported_method before interpreting those bytes.
fn zip_method(output: &Path, method: u16) -> io::Result<Value> {
    let name = b"payload.txt";
    let payload = b"ZIPX method fixture payload";
    let compressed = if method == 93 {
        zstd::stream::encode_all(payload.as_slice(), 1)?
    } else {
        payload.to_vec()
    };
    let crc = crc32fast::hash(payload);
    let mut local = b"PK\x03\x04".to_vec();
    for value in [63u16, 0, method, 0, 0] {
        local.extend_from_slice(&value.to_le_bytes());
    }
    for value in [crc, compressed.len() as u32, payload.len() as u32] {
        local.extend_from_slice(&value.to_le_bytes());
    }
    for value in [name.len() as u16, 0] {
        local.extend_from_slice(&value.to_le_bytes());
    }
    local.extend_from_slice(name);
    local.extend_from_slice(&compressed);
    let mut central = b"PK\x01\x02".to_vec();
    for value in [63u16, 63, 0, method, 0, 0] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    for value in [crc, compressed.len() as u32, payload.len() as u32] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    for value in [name.len() as u16, 0, 0, 0, 0] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0u32, 0] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    central.extend_from_slice(name);
    let mut eocd = b"PK\x05\x06".to_vec();
    for value in [0u16, 0, 1, 1] {
        eocd.extend_from_slice(&value.to_le_bytes());
    }
    for value in [central.len() as u32, local.len() as u32] {
        eocd.extend_from_slice(&value.to_le_bytes());
    }
    eocd.extend_from_slice(&0u16.to_le_bytes());
    let mut writer = BufWriter::new(File::create(output)?);
    writer.write_all(&local)?;
    writer.write_all(&central)?;
    writer.write_all(&eocd)?;
    writer.flush()?;
    Ok(json!({"expected_files": {"payload.txt": {"size": payload.len(), "crc32": crc}}}))
}

fn seven_zip_uint(value: u64, output: &mut Vec<u8>) {
    for extra in 0..8 {
        if value < (1u64 << (7 + 7 * extra)) {
            let prefix = if extra == 0 { 0 } else { 0xffu8 << (8 - extra) };
            output.push(prefix | (value >> (8 * extra)) as u8);
            output.extend_from_slice(&value.to_le_bytes()[..extra]);
            return;
        }
    }
    output.push(0xff);
    output.extend_from_slice(&value.to_le_bytes());
}
fn seven_zip_lz4_header(source: &Path, output: &Path) -> io::Result<Value> {
    let mut reader = File::open(source)?;
    let mut start = [0u8; 32];
    reader.read_exact(&mut start)?;
    if start[..6] != *b"7z\xbc\xaf\x27\x1c" {
        return Err(io::Error::other("not 7z"));
    }
    let offset = u64::from_le_bytes(start[12..20].try_into().unwrap());
    let length = u64::from_le_bytes(start[20..28].try_into().unwrap());
    if length > 64 * 1024 * 1024 {
        return Err(io::Error::other("header too large"));
    }
    reader.seek(SeekFrom::Start(32 + offset))?;
    let mut header = vec![0u8; length as usize];
    reader.read_exact(&mut header)?;
    if header.first() != Some(&1) {
        return Err(io::Error::other("use -mhc=off for fixture source"));
    }
    let raw = output.with_extension("header.raw");
    let compressed = output.with_extension("header.lz4");
    fs::write(&raw, &header)?;
    compress_lz4(&[raw.clone()], &compressed)?;
    let packed = fs::metadata(&compressed)?.len();
    let mut descriptor = vec![0x17, 6];
    seven_zip_uint(offset, &mut descriptor);
    seven_zip_uint(1, &mut descriptor);
    descriptor.push(9);
    seven_zip_uint(packed, &mut descriptor);
    descriptor.extend_from_slice(&[
        0, 7, 0x0b, 1, 0, 1, 0x24, 4, 0xf7, 0x11, 4, 5, 1, 10, 1, 0, 0, 0x0c,
    ]);
    seven_zip_uint(length, &mut descriptor);
    descriptor.extend_from_slice(&[0x0a, 1]);
    descriptor.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
    descriptor.extend_from_slice(&[0, 0]);
    start[12..20].copy_from_slice(&(offset + packed).to_le_bytes());
    start[20..28].copy_from_slice(&(descriptor.len() as u64).to_le_bytes());
    start[28..32].copy_from_slice(&crc32fast::hash(&descriptor).to_le_bytes());
    let crc = crc32fast::hash(&start[12..32]);
    start[8..12].copy_from_slice(&crc.to_le_bytes());
    let mut writer = BufWriter::new(File::create(output)?);
    writer.write_all(&start)?;
    reader.seek(SeekFrom::Start(32))?;
    io::copy(&mut reader.take(offset), &mut writer)?;
    io::copy(&mut File::open(&compressed)?, &mut writer)?;
    writer.write_all(&descriptor)?;
    writer.flush()?;
    fs::remove_file(raw)?;
    fs::remove_file(compressed)?;
    Ok(json!({"encoded_header_method": "04F71104", "header_size": length}))
}

// Test-only writer using the pinned upstream encoder, independent of SunPack's
// parser/decoder. Each source is one frame; memory stays bounded for large files.
#[repr(C)]
#[derive(Default)]
struct FrameInfo {
    block_size: u32,
    block_mode: u32,
    content_checksum: u32,
    frame_type: u32,
    content_size: u64,
    dictionary_id: u32,
    block_checksum: u32,
}
#[repr(C)]
#[derive(Default)]
struct Preferences {
    frame: FrameInfo,
    level: i32,
    auto_flush: u32,
    favor_decode: u32,
    reserved: [u32; 3],
}
#[link(name = "sunpack_lz4", kind = "static")]
extern "C" {
    fn LZ4F_createCompressionContext(context: *mut *mut std::ffi::c_void, version: u32) -> usize;
    fn LZ4F_freeCompressionContext(context: *mut std::ffi::c_void) -> usize;
    fn LZ4F_compressBound(size: usize, prefs: *const Preferences) -> usize;
    fn LZ4F_compressBegin(
        context: *mut std::ffi::c_void,
        output: *mut u8,
        capacity: usize,
        prefs: *const Preferences,
    ) -> usize;
    fn LZ4F_compressUpdate(
        context: *mut std::ffi::c_void,
        output: *mut u8,
        capacity: usize,
        input: *const u8,
        size: usize,
        options: *const std::ffi::c_void,
    ) -> usize;
    fn LZ4F_compressEnd(
        context: *mut std::ffi::c_void,
        output: *mut u8,
        capacity: usize,
        options: *const std::ffi::c_void,
    ) -> usize;
    fn LZ4F_isError(code: usize) -> u32;
}
struct CompressionContext(*mut std::ffi::c_void);
impl Drop for CompressionContext {
    fn drop(&mut self) {
        unsafe {
            LZ4F_freeCompressionContext(self.0);
        }
    }
}
fn checked_lz4(code: usize) -> io::Result<usize> {
    if unsafe { LZ4F_isError(code) } != 0 {
        Err(io::Error::other("upstream LZ4 fixture compression failed"))
    } else {
        Ok(code)
    }
}
fn compress_lz4(paths: &[PathBuf], output: &Path) -> io::Result<Value> {
    if paths.is_empty() {
        return Err(io::Error::other("LZ4 requires at least one source"));
    }
    let mut writer = BufWriter::new(File::create(output)?);
    let mut input = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    let mut digest = crc32fast::Hasher::new();
    for path in paths {
        let mut source = BufReader::new(File::open(path)?);
        let prefs = Preferences {
            frame: FrameInfo {
                block_size: 4,
                block_mode: 0,
                content_checksum: 1,
                content_size: source.get_ref().metadata()?.len(),
                block_checksum: 1,
                ..FrameInfo::default()
            },
            ..Preferences::default()
        };
        let mut raw = std::ptr::null_mut();
        checked_lz4(unsafe { LZ4F_createCompressionContext(&mut raw, 100) })?;
        let context = CompressionContext(raw);
        let capacity = checked_lz4(unsafe { LZ4F_compressBound(input.len(), &prefs) })?.max(19);
        let mut packed = vec![0u8; capacity];
        let count = checked_lz4(unsafe {
            LZ4F_compressBegin(context.0, packed.as_mut_ptr(), packed.len(), &prefs)
        })?;
        writer.write_all(&packed[..count])?;
        loop {
            let count = source.read(&mut input)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            digest.update(&input[..count]);
            let written = checked_lz4(unsafe {
                LZ4F_compressUpdate(
                    context.0,
                    packed.as_mut_ptr(),
                    packed.len(),
                    input.as_ptr(),
                    count,
                    std::ptr::null(),
                )
            })?;
            writer.write_all(&packed[..written])?;
        }
        let count = checked_lz4(unsafe {
            LZ4F_compressEnd(
                context.0,
                packed.as_mut_ptr(),
                packed.len(),
                std::ptr::null(),
            )
        })?;
        writer.write_all(&packed[..count])?;
    }
    writer.flush()?;
    Ok(json!({"frames": paths.len(), "source_bytes": total, "source_crc32": digest.finalize()}))
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
            let mut source = BufReader::new(File::open(&path)?);
            let mut digest = crc32fast::Hasher::new();
            let mut buffer = [0u8; 64 * 1024];
            let mut size = 0u64;
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
                size += count as u64;
            }
            entries.push(json!({
                "path": path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"),
                "size": size, "crc32": digest.finalize(),
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
        Request::Copy { source, output } => Ok(json!({"bytes": fs::copy(source, output)?})),
        Request::ZipMethod { output, method } => zip_method(&output, method),
        Request::SevenZipLz4Header { source, output } => seven_zip_lz4_header(&source, &output),
        Request::Flip { path, offset } => {
            let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut byte = [0u8];
            file.read_exact(&mut byte)?;
            byte[0] ^= 1;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&byte)?;
            Ok(json!({"offset": offset}))
        }
        Request::Lz4 { output, paths } => compress_lz4(&paths, &output),
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
