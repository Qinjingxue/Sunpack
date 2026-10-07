use std::io;

pub const MAGIC: u32 = u32::from_le_bytes(*b"SPWB");
pub const MAX_VOLUME_GUID_BYTES: usize = 64;
pub const FILE_ID_BYTES: usize = 16;
pub const REQUEST_BYTES: usize = 112;
pub const RESPONSE_BYTES: usize = 42;
const _: () = assert!(REQUEST_BYTES <= 4096);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Opcode {
    Hello = 1,
    ProbeVolume = 2,
    ReadChangeReasons = 3,
    Ping = 4,
    Release = 5,
    ReadRootChanges = 6,
}

impl TryFrom<u16> for Opcode {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::ProbeVolume),
            3 => Ok(Self::ReadChangeReasons),
            4 => Ok(Self::Ping),
            5 => Ok(Self::Release),
            6 => Ok(Self::ReadRootChanges),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown broker opcode",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Ok = 0,
    InvalidRequest = 1,
    JournalUnavailable = 2,
    NotFound = 3,
    ScanLimit = 4,
    InternalError = 5,
    JournalReset = 6,
}

impl TryFrom<u16> for Status {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::JournalUnavailable),
            3 => Ok(Self::NotFound),
            4 => Ok(Self::ScanLimit),
            5 => Ok(Self::InternalError),
            6 => Ok(Self::JournalReset),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown broker status",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub opcode: Opcode,
    pub request_id: u64,
    pub previous_usn: i64,
    pub current_usn: i64,
    pub file_id: [u8; FILE_ID_BYTES],
    pub file_id_len: u8,
    pub volume_guid: String,
}

impl Request {
    pub fn simple(opcode: Opcode, request_id: u64) -> Self {
        Self {
            opcode,
            request_id,
            previous_usn: 0,
            current_usn: 0,
            file_id: [0; FILE_ID_BYTES],
            file_id_len: 0,
            volume_guid: String::new(),
        }
    }

    pub fn encode(&self) -> io::Result<[u8; REQUEST_BYTES]> {
        let volume = self.volume_guid.as_bytes();
        if volume.len() > MAX_VOLUME_GUID_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "volume GUID is too long",
            ));
        }
        if !matches!(self.file_id_len, 0 | 8 | 16) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file ID width",
            ));
        }
        let mut bytes = [0u8; REQUEST_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&(self.opcode as u16).to_le_bytes());
        bytes[6..14].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[14..22].copy_from_slice(&self.previous_usn.to_le_bytes());
        bytes[22..30].copy_from_slice(&self.current_usn.to_le_bytes());
        bytes[30] = self.file_id_len;
        bytes[31] = volume.len() as u8;
        let file_id_len = usize::from(self.file_id_len);
        bytes[32..32 + file_id_len].copy_from_slice(&self.file_id[..file_id_len]);
        bytes[48..48 + volume.len()].copy_from_slice(volume);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker request length",
            ));
        }
        if u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker request magic",
            ));
        }
        let opcode = Opcode::try_from(u16::from_le_bytes(bytes[4..6].try_into().unwrap()))?;
        let file_id_len = bytes[30];
        let volume_len = bytes[31] as usize;
        if !matches!(file_id_len, 0 | 8 | 16) || volume_len > MAX_VOLUME_GUID_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker request fields",
            ));
        }
        let mut file_id = [0u8; FILE_ID_BYTES];
        let file_id_width = usize::from(file_id_len);
        file_id[..file_id_width].copy_from_slice(&bytes[32..32 + file_id_width]);
        let volume_guid = std::str::from_utf8(&bytes[48..48 + volume_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "volume GUID is not UTF-8"))?
            .to_owned();
        Ok(Self {
            opcode,
            request_id: u64::from_le_bytes(bytes[6..14].try_into().unwrap()),
            previous_usn: i64::from_le_bytes(bytes[14..22].try_into().unwrap()),
            current_usn: i64::from_le_bytes(bytes[22..30].try_into().unwrap()),
            file_id,
            file_id_len,
            volume_guid,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: Status,
    pub request_id: u64,
    pub win32_error: u32,
    pub journal_id: u64,
    pub reasons_all: u32,
    pub reasons_without_close: u32,
    pub next_usn: i64,
}

impl Response {
    pub fn ok(request_id: u64) -> Self {
        Self {
            status: Status::Ok,
            request_id,
            win32_error: 0,
            journal_id: 0,
            reasons_all: 0,
            reasons_without_close: 0,
            next_usn: 0,
        }
    }

    pub fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0u8; RESPONSE_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&(self.status as u16).to_le_bytes());
        bytes[6..14].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[14..18].copy_from_slice(&self.win32_error.to_le_bytes());
        bytes[18..26].copy_from_slice(&self.journal_id.to_le_bytes());
        bytes[26..30].copy_from_slice(&self.reasons_all.to_le_bytes());
        bytes[30..34].copy_from_slice(&self.reasons_without_close.to_le_bytes());
        bytes[34..42].copy_from_slice(&self.next_usn.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker response length",
            ));
        }
        if u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker response header",
            ));
        }
        Ok(Self {
            status: Status::try_from(u16::from_le_bytes(bytes[4..6].try_into().unwrap()))?,
            request_id: u64::from_le_bytes(bytes[6..14].try_into().unwrap()),
            win32_error: u32::from_le_bytes(bytes[14..18].try_into().unwrap()),
            journal_id: u64::from_le_bytes(bytes[18..26].try_into().unwrap()),
            reasons_all: u32::from_le_bytes(bytes[26..30].try_into().unwrap()),
            reasons_without_close: u32::from_le_bytes(bytes[30..34].try_into().unwrap()),
            next_usn: i64::from_le_bytes(bytes[34..42].try_into().unwrap()),
        })
    }
}

pub fn parse_file_id(value: &str) -> io::Result<([u8; FILE_ID_BYTES], u8)> {
    let normalized = value.trim();
    if normalized.len() != 16 && normalized.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file ID must contain 8 or 16 bytes",
        ));
    }
    let width = (normalized.len() / 2) as u8;
    let mut little_endian = [0u8; FILE_ID_BYTES];
    for (index, byte) in little_endian.iter_mut().enumerate().take(width as usize) {
        let source = normalized.len() - (index + 1) * 2;
        *byte = u8::from_str_radix(&normalized[source..source + 2], 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "file ID is not hexadecimal")
        })?;
    }
    Ok((little_endian, width))
}

pub fn format_file_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_request_roundtrip_preserves_journal_query_fields() {
        let (file_id, file_id_len) = parse_file_id("0000000000001234").unwrap();
        let request = Request {
            opcode: Opcode::ReadChangeReasons,
            request_id: 42,
            previous_usn: 100,
            current_usn: 101,
            file_id,
            file_id_len,
            volume_guid: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned(),
        };
        assert_eq!(
            Request::decode(&request.encode().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn fixed_response_roundtrip_preserves_all_fields() {
        let response = Response {
            status: Status::JournalReset,
            request_id: 0x0102_0304_0506_0708,
            win32_error: 0x1112_1314,
            journal_id: 0x2122_2324_2526_2728,
            reasons_all: 0x3132_3334,
            reasons_without_close: 0x4142_4344,
            next_usn: 0x5152_5354_5556_5758,
        };

        assert_eq!(Response::decode(&response.encode()).unwrap(), response);
    }

    #[test]
    fn file_id_parser_rejects_non_hex_and_unbounded_widths() {
        assert!(parse_file_id("not-hex-not-hex!").is_err());
        assert!(parse_file_id(&"0".repeat(34)).is_err());
    }
}
