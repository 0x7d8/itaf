use crate::spec::{Encode, Entry as RawEntry, FORMAT_VERSION, MAGIC, validate_name};
use crc::{CRC_64_GO_ISO, Crc};
use std::{
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

static CRC_ALG: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

#[derive(Debug, Clone)]
pub struct EncoderOptions {
    pub base_timestamp: Option<i64>,
    pub crc_enabled: bool,
}

impl Default for EncoderOptions {
    fn default() -> Self {
        Self {
            base_timestamp: None,
            crc_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub uid: u64,
    pub gid: u64,
    pub mode: u32,
    pub modified: SystemTime,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            mode: 0o644,
            modified: SystemTime::now(),
        }
    }
}

pub struct ItafEncoder<W: Write> {
    writer: W,

    path_stack: Vec<String>,

    current_uid: u64,
    current_gid: u64,
    current_mode: u32,
    current_time_base: i64,
    crc_enabled: bool,
}

impl<W: Write> ItafEncoder<W> {
    pub fn new(mut writer: W, options: EncoderOptions) -> std::io::Result<Self> {
        let base_ts = options.base_timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64
        });

        writer.write_all(MAGIC)?;
        writer.write_all(&[FORMAT_VERSION])?;
        writer.write_all(&base_ts.to_le_bytes())?;

        let flags = if options.crc_enabled { 1 } else { 0 };
        writer.write_all(&[flags])?;

        Ok(Self {
            writer,
            path_stack: Vec::new(),
            current_uid: 0,
            current_gid: 0,
            current_mode: 0o644,
            current_time_base: base_ts,
            crc_enabled: options.crc_enabled,
        })
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        while !self.path_stack.is_empty() {
            self.exit_dir()?;
        }
        Ok(self.writer)
    }

    fn ensure_metadata_state(&mut self, meta: &Metadata) -> std::io::Result<()> {
        if meta.uid != self.current_uid
            || meta.gid != self.current_gid
            || meta.mode != self.current_mode
        {
            let op = RawEntry::UnixAttr {
                uid: meta.uid,
                gid: meta.gid,
                mode: meta.mode,
            };
            op.encode(&mut self.writer)?;

            self.current_uid = meta.uid;
            self.current_gid = meta.gid;
            self.current_mode = meta.mode;
        }
        Ok(())
    }

    /// Compute a delta from the current time base. Uses saturating arithmetic
    /// so that pathological timestamps (e.g. SystemTime values far outside the
    /// representable range) don't wrap silently.
    fn calculate_time_delta(&self, time: SystemTime) -> i64 {
        let ns = time
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or_else(|e| -(e.duration().as_nanos() as i128));
        let delta = ns - self.current_time_base as i128;
        if delta > i64::MAX as i128 {
            i64::MAX
        } else if delta < i64::MIN as i128 {
            i64::MIN
        } else {
            delta as i64
        }
    }

    /// Adds a file to the archive.
    ///
    /// `name` may be a `/`-separated chain relative to the current directory,
    /// which saves a `DirEnter`/`DirExit` pair per level for a file that is the
    /// only thing in its directory.
    ///
    /// `size` must match the number of bytes available in `content`. The encoder
    /// reads exactly `size` bytes; if `content` ends sooner it returns
    /// `UnexpectedEof`, and if `content` still has data after `size` it returns
    /// `InvalidInput` ("declared size shorter than source").
    pub fn add_file(
        &mut self,
        name: &str,
        meta: &Metadata,
        size: u64,
        content: &mut dyn Read,
    ) -> std::io::Result<()> {
        validate_name(name)?;
        self.ensure_metadata_state(meta)?;

        let time_delta = self.calculate_time_delta(meta.modified);

        let entry = RawEntry::File {
            name: name.to_string(),
            size,
            time_delta_ns: time_delta,
        };
        entry.encode(&mut self.writer)?;

        let mut digest = if self.crc_enabled {
            Some(CRC_ALG.digest())
        } else {
            None
        };

        let mut buf = vec![0u8; 64 * 1024];
        let mut written = 0u64;

        while written < size {
            let remaining = size - written;
            let limit = std::cmp::min(buf.len() as u64, remaining) as usize;

            let n = content.read(&mut buf[0..limit])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "source reader ended before declared size",
                ));
            }

            self.writer.write_all(&buf[..n])?;

            if let Some(d) = &mut digest {
                d.update(&buf[..n]);
            }

            written += n as u64;
        }

        let mut probe = [0u8; 1];
        match content.read(&mut probe) {
            Ok(0) => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "declared file size shorter than actual source length",
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }

        if let Some(d) = digest {
            let crc_val = d.finalize();
            self.writer.write_all(&crc_val.to_le_bytes())?;
        }

        Ok(())
    }

    /// Pushes a new directory onto the stack.
    ///
    /// `name` may be a `/`-separated chain (`world/region`), which opens every
    /// level in one instruction instead of one `DirEnter` per level — worth it
    /// whenever a directory has a single child. The whole chain is one stack
    /// frame, so a single [`Self::exit_dir`] leaves all of it; the metadata
    /// given here applies to the deepest level, and intermediate levels are
    /// materialized by the extractor.
    pub fn enter_dir(&mut self, name: &str, meta: &Metadata) -> std::io::Result<()> {
        validate_name(name)?;
        self.ensure_metadata_state(meta)?;
        let time_delta = self.calculate_time_delta(meta.modified);

        let entry = RawEntry::DirEnter {
            name: name.to_string(),
            time_delta_ns: time_delta,
        };
        entry.encode(&mut self.writer)?;

        self.path_stack.push(name.to_string());
        Ok(())
    }

    /// Pops the current directory from the stack, leaving every level a
    /// compressed [`Self::enter_dir`] name opened.
    pub fn exit_dir(&mut self) -> std::io::Result<()> {
        if self.path_stack.pop().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot exit dir: Root reached",
            ));
        }
        RawEntry::DirExit.encode(&mut self.writer)?;
        Ok(())
    }

    pub fn add_symlink(
        &mut self,
        name: &str,
        target: &str,
        target_is_dir: bool,
        meta: &Metadata,
    ) -> std::io::Result<()> {
        validate_name(name)?;
        self.ensure_metadata_state(meta)?;
        let time_delta = self.calculate_time_delta(meta.modified);

        let entry = RawEntry::Symlink {
            name: name.to_string(),
            target: target.to_string(),
            is_dir: target_is_dir,
            time_delta_ns: time_delta,
        };
        entry.encode(&mut self.writer)?;
        Ok(())
    }

    pub fn add_hardlink(
        &mut self,
        name: &str,
        target: &str,
        meta: &Metadata,
    ) -> std::io::Result<()> {
        validate_name(name)?;
        self.ensure_metadata_state(meta)?;
        let time_delta = self.calculate_time_delta(meta.modified);

        let entry = RawEntry::Hardlink {
            name: name.to_string(),
            target: target.to_string(),
            time_delta_ns: time_delta,
        };
        entry.encode(&mut self.writer)?;
        Ok(())
    }

    /// Toggles checksum generation for subsequent files.
    pub fn set_crc_enabled(&mut self, enabled: bool) -> std::io::Result<()> {
        if self.crc_enabled != enabled {
            let op = RawEntry::Meta {
                has_crc: enabled,
                time_base: self.current_time_base,
            };
            op.encode(&mut self.writer)?;
            self.crc_enabled = enabled;
        }
        Ok(())
    }

    /// Updates the base timestamp (e.g. for a new folder of old files).
    pub fn set_base_time(&mut self, new_base_ns: i64) -> std::io::Result<()> {
        if self.current_time_base != new_base_ns {
            let op = RawEntry::Meta {
                has_crc: self.crc_enabled,
                time_base: new_base_ns,
            };
            op.encode(&mut self.writer)?;
            self.current_time_base = new_base_ns;
        }
        Ok(())
    }
}
