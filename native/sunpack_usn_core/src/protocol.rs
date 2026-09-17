use std::io;

pub const MAGIC: u32 = u32::from_le_bytes(*b"SPWB");
pub const VERSION: u16 = 3;
pub const MAX_VOLUME_GUID_BYTES: usize = 64;
pub const FILE_ID_BYTES: usize = 16;
pub const REQUEST_BYTES: usize = 128;
pub const RESPONSE_BYTES: usize = 48;
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
    VersionMismatch = 6,
    JournalReset = 7,
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
            6 => Ok(Self::VersionMismatch),
            7 => Ok(Self::JournalReset),
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
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6..8].copy_from_slice(&(self.opcode as u16).to_le_bytes());
        bytes[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.previous_usn.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.current_usn.to_le_bytes());
        bytes[32] = self.file_id_len;
        bytes[33] = volume.len() as u8;
        bytes[40..56].copy_from_slice(&self.file_id);
        bytes[56..56 + volume.len()].copy_from_slice(volume);
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
        if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "broker protocol version mismatch",
            ));
        }
        let opcode = Opcode::try_from(u16::from_le_bytes(bytes[6..8].try_into().unwrap()))?;
        let file_id_len = bytes[32];
        let volume_len = bytes[33] as usize;
        if !matches!(file_id_len, 0 | 8 | 16) || volume_len > MAX_VOLUME_GUID_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker request fields",
            ));
        }
        if bytes[34..40].iter().any(|byte| *byte != 0)
            || bytes[40 + file_id_len as usize..56]
                .iter()
                .any(|byte| *byte != 0)
            || bytes[56 + volume_len..].iter().any(|byte| *byte != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker request contains non-zero reserved bytes",
            ));
        }
        let mut file_id = [0u8; FILE_ID_BYTES];
        file_id.copy_from_slice(&bytes[40..56]);
        let volume_guid = std::str::from_utf8(&bytes[56..56 + volume_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "volume GUID is not UTF-8"))?
            .to_owned();
        Ok(Self {
            opcode,
            request_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            previous_usn: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            current_usn: i64::from_le_bytes(bytes[24..32].try_into().unwrap()),
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
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6..8].copy_from_slice(&(self.status as u16).to_le_bytes());
        bytes[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.win32_error.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.journal_id.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.reasons_all.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.reasons_without_close.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.next_usn.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker response length",
            ));
        }
        if u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != MAGIC
            || u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != VERSION
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid broker response header",
            ));
        }
        Ok(Self {
            status: Status::try_from(u16::from_le_bytes(bytes[6..8].try_into().unwrap()))?,
            request_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            win32_error: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            journal_id: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            reasons_all: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            reasons_without_close: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            next_usn: i64::from_le_bytes(bytes[40..48].try_into().unwrap()),
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
    fn wrong_protocol_version_is_rejected_before_fields_are_used() {
        let mut encoded = Request::simple(Opcode::Hello, 1).encode().unwrap();
        encoded[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
        assert_eq!(
            Request::decode(&encoded).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn non_zero_reserved_request_bytes_are_rejected() {
        let mut encoded = Request::simple(Opcode::Hello, 1).encode().unwrap();
        encoded[127] = 1;

        assert_eq!(
            Request::decode(&encoded).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn file_id_parser_rejects_non_hex_and_unbounded_widths() {
        assert!(parse_file_id("not-hex-not-hex!").is_err());
        assert!(parse_file_id(&"0".repeat(34)).is_err());
    }
}
