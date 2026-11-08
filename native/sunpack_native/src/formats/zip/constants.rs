const LFH_SIG: &[u8] = b"PK\x03\x04";
const CD_SIG: &[u8] = b"PK\x01\x02";
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const DD_SIG: &[u8] = b"PK\x07\x08";
const LOCAL_HEADER_LEN: usize = 30;
