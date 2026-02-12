use std::cell::RefCell;
use std::io::{self, Read};
use std::rc::Rc;

use crate::spec::{Decode, Entry as SpecEntry};

struct RawState<R> {
    reader: R,

    has_crc: bool,
    crc_type: Option<u8>,

    bytes_remaining: u64,
    checksum_consumed: bool,
}

impl<R: Read> RawState<R> {
    fn consume_checksum(&mut self) -> io::Result<()> {
        if self.has_crc && !self.checksum_consumed {
            if self.crc_type == Some(2) {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
            }
            self.checksum_consumed = true;
        }
        Ok(())
    }

    fn drain_active_file(&mut self) -> io::Result<()> {
        if self.bytes_remaining > 0 {
            let mut sink = io::sink();
            let mut take = (&mut self.reader).take(self.bytes_remaining);
            io::copy(&mut take, &mut sink)?;
            self.bytes_remaining = 0;
        }
        self.consume_checksum()?;
        Ok(())
    }
}

pub struct RawFileEntry<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
    pub name: String,
    pub size: u64,
    pub time_delta_ns: i64,
}

impl<R: Read> Read for RawFileEntry<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut st = self.state.borrow_mut();

        if st.bytes_remaining == 0 {
            st.consume_checksum()?;
            return Ok(0);
        }

        let max = std::cmp::min(buf.len() as u64, st.bytes_remaining);
        let n = st.reader.read(&mut buf[0..max as usize])?;

        if n == 0 && st.bytes_remaining > 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Truncated raw stream",
            ));
        }

        st.bytes_remaining -= n as u64;

        if st.bytes_remaining == 0 {
            st.consume_checksum()?;
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
    /// A file header. The payload (file content) is ready to be read from the inner struct.
    File(RawFileEntry<R>),

    /// Instruction to enter a directory.
    DirEnter { name: String, time_delta_ns: i64 },

    /// Instruction to pop the directory stack.
    DirExit,

    /// Metadata change instruction.
    /// Note: The RawDecoder automatically updates its internal CRC state based on this,
    /// so you don't need to manually track it for parsing purposes.
    Meta { has_crc: bool, time_base: i64 },

    /// Unix Attribute change instruction.
    UnixAttr { uid: u64, gid: u64, mode: u32 },

    Symlink {
        name: String,
        target: String,
        is_dir: bool,
        time_delta_ns: i64,
    },

    /// An Extension or Hardlink (mapped broadly for raw view)
    Other(SpecEntry),
}

pub struct RawDecoder<R: Read> {
    state: Rc<RefCell<RawState<R>>>,
    pub base_timestamp: i64,
}

impl<R: Read> RawDecoder<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let mut ver = [0u8; 1];
        reader.read_exact(&mut ver)?;
        let mut base_ts_buf = [0u8; 8];
        reader.read_exact(&mut base_ts_buf)?;
        let base_timestamp = i64::from_le_bytes(base_ts_buf);
        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;

        let has_crc = (flags[0] & 1) != 0;

        let state = RawState {
            reader,
            has_crc,
            crc_type: if has_crc { Some(2) } else { None },
            bytes_remaining: 0,
            checksum_consumed: true,
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
    type Item = io::Result<RawRecord<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.state.borrow_mut().drain_active_file() {
            return Some(Err(e));
        }

        let mut st = self.state.borrow_mut();

        let spec_entry = match SpecEntry::decode(&mut st.reader) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return None,
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
                st.crc_type = if has_crc { Some(2) } else { None };

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
            other => Some(Ok(RawRecord::Other(other))),
        }
    }
}
