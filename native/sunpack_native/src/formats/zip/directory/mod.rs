#[derive(Clone, Copy)]
struct EocdInfo {
    offset: usize,
    end: usize,
    disk_entries: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
}

#[derive(Clone, Copy)]
struct CdWalk {
    end: usize,
    count: usize,
}

struct CentralEntry {
    offset: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    disk_number_start: u16,
    local_header_offset: u32,
}

#[derive(Clone)]
struct LocalHeader {
    offset: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    name_len: u16,
    extra_len: u16,
}

struct Zip64Extra {
    values: Vec<u64>,
    disk_start: Option<u32>,
    disk_start_offset: Option<usize>,
    stored_size: usize,
}

#[derive(Clone, Copy)]
struct Zip64Eocd {
    offset: usize,
    end: usize,
    total_entries: u64,
    cd_size: u64,
    cd_offset: u64,
}

#[derive(Clone, Copy)]
struct Zip64Locator {
    offset: usize,
    end: usize,
    zip64_eocd_offset: u64,
    total_disks: u32,
}

#[derive(Clone, Copy)]
struct DataDescriptorRecord {
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    has_signature: bool,
}

#[derive(Clone, Copy)]
struct PayloadProbe {
    consumed: usize,
    end: usize,
    uncompressed_size: u64,
    crc32: u32,
}

struct DeflateInfo {
    consumed: usize,
    uncompressed_size: u64,
    crc32: u32,
}

struct Crc32 {
    value: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= *byte as u32;
            for _ in 0..8 {
                let mask = (self.value & 1).wrapping_neg();
                self.value = (self.value >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.value
    }
}

fn crc32_bytes(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

fn descriptor_at(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> bool {
    descriptor_at_impl(
        data,
        offset,
        expected_crc32,
        expected_compressed,
        expected_uncompressed,
    )
    .is_some()
}

fn descriptor_at_impl(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> Option<usize> {
    for (len, has_sig, zip64) in [
        (16usize, true, false),
        (24, true, true),
        (12, false, false),
        (20, false, true),
    ] {
        if offset + len > data.len() {
            continue;
        }
        let base = if has_sig {
            if &data[offset..offset + 4] != DD_SIG {
                continue;
            }
            offset + 4
        } else {
            offset
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if crc32 == expected_crc32
            && compressed == expected_compressed
            && uncompressed == expected_uncompressed
        {
            return Some(offset + len);
        }
    }
    None
}

fn expected_zip64_values(
    entry: &CentralEntry,
    local: &LocalHeader,
    local_zip64: &Zip64Extra,
) -> Option<Vec<u64>> {
    let mut expected = Vec::new();
    if entry.uncompressed_size == 0xFFFF_FFFF {
        expected.push(*local_zip64.values.first()?);
    }
    if entry.compressed_size == 0xFFFF_FFFF {
        expected.push(*local_zip64.values.get(1)?);
    }
    if entry.local_header_offset == 0xFFFF_FFFF {
        expected.push(local.offset as u64);
    }
    Some(expected)
}

fn expected_zip64_central_size(entry: &CentralEntry) -> usize {
    usize::from(entry.uncompressed_size == u32::MAX) * 8
        + usize::from(entry.compressed_size == u32::MAX) * 8
        + usize::from(entry.local_header_offset == u32::MAX) * 8
        + usize::from(entry.disk_number_start == u16::MAX) * 4
}

