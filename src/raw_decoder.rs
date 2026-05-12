use crate::spec::{Decode, DecodeLimits, Entry as SpecEntry, FORMAT_VERSION, MAGIC};
use crc::{CRC_64_GO_ISO, Crc};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Read},
    rc::Rc,
};

static CRC_ALG: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcAlgorithm {
    Crc64,
}

struct RawState<R> {
    reader: R,

    has_crc: bool,
    crc_alg: Option<CrcAlgorithm>,

    bytes_remaining: u64,
    checksum_consumed: bool,
    last_crc_verified: Option<u64>,
    active_digest: Option<crc::Digest<'static, u64>>,

    limits: DecodeLimits,
}

impl<R: Read> RawState<R> {
    fn consume_and_verify_checksum(&mut self) -> std::io::Result<()> {
        if !self.has_crc || self.checksum_consumed {
            return Ok(());
        }
        match self.crc_alg {
            Some(CrcAlgorithm::Crc64) => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                let stored = u64::from_le_bytes(buf);
                self.checksum_consumed = true;
                if let Some(d) = self.active_digest.take() {
                    let computed = d.finalize();
                    if computed != stored {
                        self.last_crc_verified = None;
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "CRC64 mismatch: stored {:016x}, computed {:016x}",
                                stored, computed
                            ),
                        ));
                    }
                    self.last_crc_verified = Some(stored);
                } else {
                    self.last_crc_verified = None;
                }
            }
            None => {
                self.checksum_consumed = true;
            }
        }
        Ok(())
    }

    fn drain_active_file(&mut self) -> std::io::Result<()> {
        if self.bytes_remaining > 0 {
            let mut buf = [0u8; 32 * 1024];
            while self.bytes_remaining > 0 {
                let want = std::cmp::min(buf.len() as u64, self.bytes_remaining) as usize;
                let n = self.reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated raw stream",
                    ));
                }
                if let Some(d) = self.active_digest.as_mut() {
                    d.update(&buf[..n]);
                }
                self.bytes_remaining -= n as u64;
            }
        }
        self.consume_and_verify_checksum()?;
        Ok(())
    }
}

pub struct RawFileEntry<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
    pub name: String,
    pub size: u64,
    pub time_delta_ns: i64,
}

impl<R: Read> RawFileEntry<R> {
    pub fn crc64(&self) -> Option<u64> {
        let st = self.state.borrow();
        if st.bytes_remaining == 0 && st.checksum_consumed {
            st.last_crc_verified
        } else {
            None
        }
    }
}

impl<R: Read> Read for RawFileEntry<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.borrow_mut();

        if st.bytes_remaining == 0 {
            st.consume_and_verify_checksum()?;
            return Ok(0);
        }

        let max = std::cmp::min(buf.len() as u64, st.bytes_remaining);
        let n = st.reader.read(&mut buf[0..max as usize])?;

        if n == 0 && st.bytes_remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated raw stream",
            ));
        }

        if let Some(d) = st.active_digest.as_mut() {
            d.update(&buf[..n]);
        }

        st.bytes_remaining -= n as u64;

        if st.bytes_remaining == 0 {
            st.consume_and_verify_checksum()?;
        }
        Ok(n)
    }
}

impl<R: Read> Drop for RawFileEntry<R> {
    fn drop(&mut self) {
        let _ = self.state.borrow_mut().drain_active_file();
    }
}

/// Represents a single instruction from the archive stream.
pub enum RawRecord<R: Read> {
    /// A file header. Read the inner struct as a `Read` to access content.
    File(RawFileEntry<R>),
    /// Instruction to enter a directory.
    DirEnter { name: String, time_delta_ns: i64 },
    /// Instruction to pop the directory stack.
    DirExit,
    /// Metadata change instruction. The decoder updates its state internally.
    Meta { has_crc: bool, time_base: i64 },
    /// Unix Attribute change instruction.
    UnixAttr { uid: u64, gid: u64, mode: u32 },
    Symlink {
        name: String,
        target: String,
        is_dir: bool,
        time_delta_ns: i64,
    },
    Hardlink {
        name: String,
        target: String,
        time_delta_ns: i64,
    },
    /// An unknown extension instruction. Payload was bounded by limits and
    /// has been fully read.
    Ext { type_id: u8, data: Vec<u8> },
}

pub struct RawDecoder<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
    pub base_timestamp: i64,
}

impl<R: Read> RawDecoder<R> {
    pub fn new(reader: R) -> std::io::Result<Self> {
        Self::with_limits(reader, DecodeLimits::default())
    }

    pub fn with_limits(mut reader: R, limits: DecodeLimits) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not an itaf archive (bad magic)",
            ));
        }
        let mut ver = [0u8; 1];
        reader.read_exact(&mut ver)?;
        if ver[0] != FORMAT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported itaf format version {} (this build supports {})",
                    ver[0], FORMAT_VERSION
                ),
            ));
        }
        let mut base_ts_buf = [0u8; 8];
        reader.read_exact(&mut base_ts_buf)?;
        let base_timestamp = i64::from_le_bytes(base_ts_buf);
        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;

        let has_crc = (flags[0] & 1) != 0;

        let state = RawState {
            reader,
            has_crc,
            crc_alg: if has_crc {
                Some(CrcAlgorithm::Crc64)
            } else {
                None
            },
            bytes_remaining: 0,
            checksum_consumed: true,
            last_crc_verified: None,
            active_digest: None,
            limits,
        };

        Ok(Self {
            state: Rc::new(RefCell::new(state)),
            base_timestamp,
        })
    }

    pub fn records(self) -> RawRecords<R> {
        RawRecords { state: self.state }
    }
}

pub struct RawRecords<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
}

impl<R: Read> Iterator for RawRecords<R> {
    type Item = std::io::Result<RawRecord<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.state.borrow_mut().drain_active_file() {
            return Some(Err(e));
        }

        let mut st = self.state.borrow_mut();

        let limits = st.limits;
        let spec_entry = match SpecEntry::decode(&mut st.reader, &limits) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        };

        match spec_entry {
            SpecEntry::File {
                name,
                size,
                time_delta_ns,
            } => {
                st.bytes_remaining = size;
                st.checksum_consumed = false;
                st.last_crc_verified = None;
                st.active_digest = if st.has_crc {
                    Some(CRC_ALG.digest())
                } else {
                    None
                };

                drop(st);

                Some(Ok(RawRecord::File(RawFileEntry {
                    state: self.state.clone(),
                    name,
                    size,
                    time_delta_ns,
                })))
            }
            SpecEntry::Meta { has_crc, time_base } => {
                st.has_crc = has_crc;
                st.crc_alg = if has_crc {
                    Some(CrcAlgorithm::Crc64)
                } else {
                    None
                };
                Some(Ok(RawRecord::Meta { has_crc, time_base }))
            }
            SpecEntry::DirEnter {
                name,
                time_delta_ns,
            } => Some(Ok(RawRecord::DirEnter {
                name,
                time_delta_ns,
            })),
            SpecEntry::DirExit => Some(Ok(RawRecord::DirExit)),
            SpecEntry::UnixAttr { uid, gid, mode } => {
                Some(Ok(RawRecord::UnixAttr { uid, gid, mode }))
            }
            SpecEntry::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            } => Some(Ok(RawRecord::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            })),
            SpecEntry::Hardlink {
                name,
                target,
                time_delta_ns,
            } => Some(Ok(RawRecord::Hardlink {
                name,
                target,
                time_delta_ns,
            })),
            SpecEntry::Ext { type_id, data } => Some(Ok(RawRecord::Ext { type_id, data })),
        }
    }
}
