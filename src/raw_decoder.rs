use crate::{
    payload::Payload,
    spec::{DecodeLimits, Entry as SpecEntry, FORMAT_VERSION, InstructionTag, MAGIC},
};
use std::{cell::RefCell, io::Read, rc::Rc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcAlgorithm {
    Crc64,
}

struct RawState<R> {
    reader: R,
    has_crc: bool,
    limits: DecodeLimits,
    payload: Payload,
    /// Set after the end of the archive or the first error. Past an error the
    /// stream position is unknown, so nothing further can be decoded.
    done: bool,
}

pub struct RawFileEntry<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
    generation: u64,
    crc: Option<u64>,
    pub name: String,
    pub size: u64,
    pub time_delta_ns: i64,
}

impl<R: Read> RawFileEntry<R> {
    /// The verified CRC64 of the payload, populated once the file has been
    /// read to the end and the stored checksum matched.
    pub fn crc64(&self) -> Option<u64> {
        self.crc
    }
}

/// Reads the file's payload. The entry is only readable until the iterator
/// that produced it is advanced; after that, `read` returns an error rather
/// than bytes of a later file.
impl<R: Read> Read for RawFileEntry<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let st = &mut *self.state.borrow_mut();
        let n = st.payload.read(&mut st.reader, self.generation, buf)?;
        self.crc = st.payload.verified();
        Ok(n)
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
            limits,
            payload: Payload::new(),
            done: false,
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
        let mut st = self.state.borrow_mut();
        if st.done {
            return None;
        }
        let entry = match st.advance() {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                st.done = true;
                return None;
            }
            Err(e) => {
                st.done = true;
                return Some(Err(e));
            }
        };

        Some(Ok(match entry {
            SpecEntry::File {
                name,
                size,
                time_delta_ns,
            } => {
                let has_crc = st.has_crc;
                let generation = st.payload.begin(size, has_crc);
                drop(st);
                RawRecord::File(RawFileEntry {
                    state: self.state.clone(),
                    generation,
                    crc: None,
                    name,
                    size,
                    time_delta_ns,
                })
            }
            SpecEntry::Meta { has_crc, time_base } => {
                st.has_crc = has_crc;
                RawRecord::Meta { has_crc, time_base }
            }
            SpecEntry::DirEnter {
                name,
                time_delta_ns,
            } => RawRecord::DirEnter {
                name,
                time_delta_ns,
            },
            SpecEntry::DirExit => RawRecord::DirExit,
            SpecEntry::UnixAttr { uid, gid, mode } => RawRecord::UnixAttr { uid, gid, mode },
            SpecEntry::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            } => RawRecord::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            },
            SpecEntry::Hardlink {
                name,
                target,
                time_delta_ns,
            } => RawRecord::Hardlink {
                name,
                target,
                time_delta_ns,
            },
            SpecEntry::Ext { type_id, data } => RawRecord::Ext { type_id, data },
        }))
    }
}

impl<R: Read> RawState<R> {
    fn advance(&mut self) -> std::io::Result<Option<SpecEntry>> {
        self.payload.skip(&mut self.reader)?;
        match InstructionTag::decode_or_eof(&mut self.reader)? {
            Some(tag) => SpecEntry::decode_body(tag, &mut self.reader, &self.limits).map(Some),
            None => Ok(None),
        }
    }
}
