//! SSE ENC v4: bounded password proof followed by authenticated stream decryption.
//! This is the sole container parser, shared by discovery and the 7-Zip adapter.
mod cipher;
mod ffi;
mod kdf;

use argon2_rust::{
    __internal::{secure_wipe_blocks, Block},
    params::{Memory, TagLen},
    Params,
};
use hkdf::Hkdf;
use sha3::Sha3_512;
use skein::{consts::U128, Skein1024};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAGIC: &[u8; 6] = b"SSEFE\x04";
const PREFIX: u64 = 40;
const CHECK: u64 = 32;
const MAC: u64 = 32;
const BUFFER: usize = 256 * 1024;
#[cfg(feature = "parallel-decrypt")]
const MIN_PARALLEL_CHUNK: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Format,
    Truncated,
    Password,
    Authentication,
    Framing,
    Io,
    Memory,
    Cancelled,
}
type Result<T> = std::result::Result<T, Error>;
type MasterHkdf = Hkdf<Skein1024<U128>, hmac::SimpleHmac<Skein1024<U128>>>;
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::Truncated
        } else {
            Self::Io
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    bytes: [u8; 40],
}
impl Header {
    pub fn parse(bytes: &[u8], length: u64) -> Result<Self> {
        if bytes.len() < PREFIX as usize || length < PREFIX + CHECK + MAC {
            return Err(Error::Truncated);
        }
        if !bytes.starts_with(MAGIC) || bytes[6] > 9 {
            return Err(Error::Format);
        }
        // Both nibbles are unsigned multipliers; every encoded value is structurally valid.
        Ok(Self {
            bytes: bytes[..40].try_into().unwrap(),
        })
    }
    fn params(&self) -> Result<Params> {
        Params::builder()
            .memory(Memory::kib(10240 << (self.bytes[7] >> 4)))
            .passes(10 << (self.bytes[7] & 15))
            .lanes(4)
            .threads(1)
            .tag_len(TagLen::bytes(256))
            .build()
            .map_err(|_| Error::Format)
    }
    fn dimensions(&self) -> (usize, usize) {
        match self.bytes[6] {
            3 | 5 => (32, 8),
            6 => (56, 8),
            7 => (128, 128),
            8 => (64, 32),
            9 => (256, 192),
            _ => (32, 16),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Keys {
    key: Vec<u8>,
    nonce: Vec<u8>,
    auth: [u8; 32],
}

#[derive(Default)]
pub struct Workspace {
    memory: Vec<Block>,
    kdf_threads: Option<usize>,
    #[cfg(test)]
    kdf_runs: usize,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        secure_wipe_blocks(&mut self.memory);
    }
}
impl Workspace {
    /// Bound lane scheduling to the caller's CPU budget. One thread uses the
    /// same SIMD backend without initializing or dispatching to Rayon.
    pub fn with_threads(threads: usize) -> Self {
        let mut workspace = Self::default();
        workspace.kdf_threads = Some(threads.max(1));
        workspace
    }
    fn derive(&mut self, header: &Header, password: &[u16]) -> Result<Keys> {
        let normalized = normalize_password(password);
        let mut master = Zeroizing::new([0u8; 256]);
        MasterHkdf::new(Some(b"memorySalt"), &normalized)
            .expand(b"memoryInfo", &mut *master)
            .map_err(|_| Error::Format)?;
        let params = header.params()?;
        let count = params.memory_blocks() as usize;
        if count != self.memory.len() {
            // The KDF, not candidate count or archive size, determines this bounded allocation.
            secure_wipe_blocks(&mut self.memory);
            self.memory.clear();
            self.memory
                .try_reserve_exact(count)
                .map_err(|_| Error::Memory)?;
            self.memory.resize(count, Block::default());
        }
        let mut derived = Zeroizing::new([0u8; 256]);
        #[cfg(test)]
        {
            self.kdf_runs += 1;
        }
        kdf::derive(
            &params,
            &*master,
            header.bytes[8..40].try_into().unwrap(),
            &mut *derived,
            &mut self.memory,
            self.kdf_threads.unwrap_or(4),
        )
        .map_err(|_| Error::Format)?;
        let (key_size, nonce_size) = header.dimensions();
        let mut keys = Keys {
            key: vec![0; key_size],
            nonce: vec![0; nonce_size],
            auth: [0; 32],
        };
        for (salt, info, output) in [
            (
                b"encKeySalt".as_slice(),
                b"encKeyInfo".as_slice(),
                keys.key.as_mut_slice(),
            ),
            (
                b"nonceSalt".as_slice(),
                b"nonceInfo".as_slice(),
                keys.nonce.as_mut_slice(),
            ),
            (
                b"authKeySalt".as_slice(),
                b"authKeyInfo".as_slice(),
                keys.auth.as_mut_slice(),
            ),
        ] {
            Hkdf::<Sha3_512>::new(Some(salt), &*derived)
                .expand(info, output)
                .map_err(|_| Error::Format)?;
        }
        Ok(keys)
    }
}

fn normalize_password(password: &[u16]) -> Zeroizing<Vec<u8>> {
    // Match Java Character.codePointAt(char[], i), including its historic per-UTF16-unit loop.
    let mut out = Zeroizing::new(Vec::with_capacity(password.len()));
    use std::io::Write;
    for (i, &unit) in password.iter().enumerate() {
        let mut point = unit as u32;
        if (0xd800..=0xdbff).contains(&unit) {
            if let Some(&low) = password
                .get(i + 1)
                .filter(|&&v| (0xdc00..=0xdfff).contains(&v))
            {
                point = 0x10000 + (((unit as u32 - 0xd800) << 10) | (low as u32 - 0xdc00));
            }
        }
        if (32..=126).contains(&point) {
            out.push(point as u8);
        } else {
            write!(&mut *out, "{point}").unwrap();
        }
    }
    out
}

/// Immutable, bounded password material. It contains neither payload nor derived keys.
pub struct PasswordProbe {
    header: Header,
    quick: [u8; 32],
}
impl PasswordProbe {
    pub fn read<R: Read + Seek>(input: &mut R, length: u64) -> Result<Self> {
        input.seek(SeekFrom::Start(0))?;
        let mut bytes = [0u8; 72];
        input.read_exact(&mut bytes)?;
        Self::parse(&bytes, length)
    }
    pub fn parse(bytes: &[u8], length: u64) -> Result<Self> {
        let header = Header::parse(bytes, length)?;
        let quick = bytes
            .get(40..72)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap();
        Ok(Self { header, quick })
    }
    pub fn workspace_bytes(&self) -> usize {
        self.header.params().unwrap().memory_blocks() as usize * std::mem::size_of::<Block>()
    }
    pub fn matches(&self, password: &[u16], workspace: &mut Workspace) -> Result<bool> {
        match self.keys(password, workspace) {
            Ok(_) => Ok(true),
            Err(Error::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn keys(&self, password: &[u16], workspace: &mut Workspace) -> Result<Keys> {
        let keys = workspace.derive(&self.header, password)?;
        let mut quick = self.quick;
        cipher::Stream::new(self.header.bytes[6], &keys.key, &keys.nonce).apply(&mut quick);
        if !quick
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(Error::Password);
        }
        Ok(keys)
    }
}

pub struct Decoder {
    header: Header,
    keys: Keys,
    packed: u64,
    encrypted_end: u64,
    framing_error: Option<Error>,
}
struct CpuLease<'a, F: FnMut(usize)> {
    extra: usize,
    release: &'a mut F,
}
impl<F: FnMut(usize)> Drop for CpuLease<'_, F> {
    fn drop(&mut self) {
        if self.extra != 0 {
            (self.release)(self.extra);
        }
    }
}
impl Decoder {
    pub fn open<R: Read + Seek>(
        input: &mut R,
        length: u64,
        password: &[u16],
        workspace: &mut Workspace,
    ) -> Result<Self> {
        let probe = PasswordProbe::read(input, length)?;
        let keys = probe.keys(password, workspace)?;
        Self::finish_open(input, length, probe, keys)
    }
    /// Worker final KDF: borrow at most three extra credits, then return them
    /// before reading recovery framing. No derived keys cross process boundaries.
    pub fn open_with_budget<R: Read + Seek>(
        input: &mut R,
        length: u64,
        password: &[u16],
        mut acquire: impl FnMut(usize) -> usize,
        mut release: impl FnMut(usize),
    ) -> Result<Self> {
        let probe = PasswordProbe::read(input, length)?;
        #[cfg(feature = "parallel-kdf")]
        let extra = acquire(3);
        #[cfg(not(feature = "parallel-kdf"))]
        let extra = {
            let _ = &mut acquire;
            0
        };
        let keys = {
            let lease = CpuLease {
                extra,
                release: &mut release,
            };
            #[cfg(feature = "parallel-kdf")]
            let lease = {
                let mut lease = lease;
                if lease.extra != 0 {
                    // Only initialize the shared executor if CPU was granted.
                    // Return surplus immediately when its capacity is smaller.
                    let usable = lease
                        .extra
                        .min(3)
                        .min(rayon::current_num_threads().saturating_sub(1));
                    if usable != lease.extra {
                        (lease.release)(lease.extra - usable);
                        lease.extra = usable;
                    }
                }
                lease
            };
            probe.keys(password, &mut Workspace::with_threads(1 + lease.extra))?
        };
        Self::finish_open(input, length, probe, keys)
    }
    fn finish_open<R: Read + Seek>(
        input: &mut R,
        length: u64,
        probe: PasswordProbe,
        keys: Keys,
    ) -> Result<Self> {
        // A password-only Test must succeed after a valid quick proof even if
        // recovery framing is damaged. Report that damage during real Extract,
        // so generic encrypted-CRC heuristics cannot turn it into a bad password.
        let (encrypted_end, framing_error) = match payload_end(input, length) {
            Ok(end) => (end, None),
            Err(e @ (Error::Framing | Error::Truncated)) => (length - MAC, Some(e)),
            Err(e) => return Err(e),
        };
        Ok(Self {
            header: probe.header,
            keys,
            packed: length,
            encrypted_end,
            framing_error,
        })
    }
    pub fn output_size(&self) -> u64 {
        if self.framing_error.is_some() {
            return 0;
        }
        self.encrypted_end - PREFIX - CHECK
    }
    pub fn decrypt<R: Read + Seek, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        progress: impl FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        self.decrypt_with_threads(input, output, 1, progress)
    }
    /// Fixed budget for standalone Rust callers/benchmarks. The worker uses
    /// `decrypt_with_budget` to acquire its actual remaining credits each batch.
    pub fn decrypt_with_threads<R: Read + Seek, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        threads: usize,
        progress: impl FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        self.decrypt_with_budget(
            input,
            output,
            |wanted| wanted.min(threads.saturating_sub(1)),
            |_| (),
            progress,
        )
    }
    pub fn decrypt_with_budget<R: Read + Seek, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        mut acquire: impl FnMut(usize) -> usize,
        mut release: impl FnMut(usize),
        mut progress: impl FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        if let Some(error) = self.framing_error {
            return Err(error);
        }
        #[cfg(not(feature = "parallel-decrypt"))]
        let _ = &mut acquire;
        input.seek(SeekFrom::Start(PREFIX))?;
        let mut mac = blake3::Hasher::new_keyed(&self.keys.auth);
        mac.update(&self.keys.nonce);
        mac.update(&self.header.bytes);
        let cipher = cipher::Stream::new(self.header.bytes[6], &self.keys.key, &self.keys.nonce);
        let mut buffer = Zeroizing::new(vec![0u8; BUFFER]);
        let mut position = PREFIX;
        while position < self.packed - MAC {
            let n = ((self.packed - MAC - position).min(BUFFER as u64)) as usize;
            input.read_exact(&mut buffer[..n])?;
            // Authenticate ciphertext/recovery before overwriting the buffer.
            mac.update(&buffer[..n]);
            progress(position)?;
            let decrypt_n = self.encrypted_end.saturating_sub(position).min(n as u64) as usize;
            if decrypt_n != 0 {
                {
                    #[cfg(feature = "parallel-decrypt")]
                    let extra = {
                        let slices = decrypt_n / MIN_PARALLEL_CHUNK;
                        let wanted = slices.saturating_sub(1);
                        if wanted == 0 {
                            0
                        } else {
                            // Bound demand by the executor before borrowing CPU.
                            acquire(wanted.min(rayon::current_num_threads().saturating_sub(1)))
                        }
                    };
                    #[cfg(not(feature = "parallel-decrypt"))]
                    let extra = 0;
                    let _lease = CpuLease {
                        extra,
                        release: &mut release,
                    };
                    #[cfg(feature = "parallel-decrypt")]
                    cipher.apply_with_threads(
                        position - PREFIX,
                        &mut buffer[..decrypt_n],
                        1 + extra,
                    );
                    #[cfg(not(feature = "parallel-decrypt"))]
                    cipher.apply_at(position - PREFIX, &mut buffer[..decrypt_n]);
                } // Return extra credits before writing; none are held during I/O.
                let skip = (PREFIX + CHECK)
                    .saturating_sub(position)
                    .min(decrypt_n as u64) as usize;
                output.write_all(&buffer[skip..decrypt_n])?;
            }
            position += n as u64;
        }
        let mut expected = [0u8; 32];
        input.read_exact(&mut expected)?;
        if mac.finalize().as_bytes() != &expected {
            return Err(Error::Authentication);
        }
        progress(self.packed)?;
        Ok(())
    }
}

fn payload_end<R: Read + Seek>(input: &mut R, length: u64) -> Result<u64> {
    let end = length.checked_sub(MAC).ok_or(Error::Truncated)?;
    if end < PREFIX + CHECK {
        return Err(Error::Truncated);
    }
    input.seek(SeekFrom::Start(end - 8))?;
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != b"PFTEREC1" {
        return Ok(end);
    }
    if end < 88 {
        return Err(Error::Truncated);
    }
    input.seek(SeekFrom::Start(end - 88))?;
    let mut trailer = [0; 88];
    input.read_exact(&mut trailer)?;
    let le = |o| u64::from_le_bytes(trailer[o..o + 8].try_into().unwrap());
    let container_size = le(16);
    let protected = le(24);
    if container_size < 152
        || end.checked_sub(container_size) != Some(protected)
        || protected < PREFIX + CHECK
        || trailer[36..40] != 1u32.to_le_bytes()
        || trailer[76..80] != [0; 4]
        || crc32fast::hash(&trailer[..72])
            != u32::from_le_bytes(trailer[72..76].try_into().unwrap())
        || le(0) < 64
        || le(0) > le(8)
        || le(8) > container_size - 88
    {
        return Err(Error::Framing);
    }
    input.seek(SeekFrom::Start(protected))?;
    let mut head = [0; 64];
    input.read_exact(&mut head)?;
    if &head[..8] != b"PFTEREC1"
        || head[8] != 1
        || head[9] != 1
        || !(1..=50).contains(&head[10])
        || head[11] != 0
        || crc32fast::hash(&head[..60]) != u32::from_le_bytes(head[60..64].try_into().unwrap())
    {
        return Err(Error::Framing);
    }
    // Recovery metadata is authenticated by ENC's MAC; no repair and no SHA-256 output pass.
    Ok(protected)
}

#[cfg(test)]
mod tests;
