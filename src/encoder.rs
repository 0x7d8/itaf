use crate::spec::{
    CRC64, FORMAT_VERSION, MAGIC, Opcode, put_dir_enter, put_dir_exit, put_file, put_link,
    put_meta, put_unix_attr, validate_name, validate_target,
};
use std::{
    io::{Error, ErrorKind, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const COPY_CHUNK: usize = 64 * 1024;
/// Files up to this size are staged in memory together with their header and
/// checksum, so they reach the writer in a single call.
const INLINE_MAX: u64 = 32 * 1024;

fn read_full(content: &mut dyn Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match content.read(buf) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "source reader ended before declared size",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn expect_end(content: &mut dyn Read) -> std::io::Result<()> {
    let mut probe = [0u8; 1];
    loop {
        match content.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "declared file size shorter than actual source length",
                ));
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

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

    open_dirs: usize,
    scratch: Vec<u8>,
    /// Set once a write failed or a file payload was left incomplete: the
    /// output can no longer be continued into a valid archive.
    poisoned: bool,

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

        let mut header = [0u8; 14];
        header[..4].copy_from_slice(MAGIC);
        header[4] = FORMAT_VERSION;
        header[5..13].copy_from_slice(&base_ts.to_le_bytes());
        header[13] = options.crc_enabled as u8;
        writer.write_all(&header)?;

        Ok(Self {
            writer,
            open_dirs: 0,
            scratch: Vec::new(),
            poisoned: false,
            current_uid: 0,
            current_gid: 0,
            current_mode: 0o644,
            current_time_base: base_ts,
            crc_enabled: options.crc_enabled,
        })
    }

    /// Closes every directory still open and returns the writer.
    ///
    /// Fails if an earlier call left the archive incomplete (see
    /// [`Self::add_file`]).
    pub fn finish(mut self) -> std::io::Result<W> {
        self.begin()?;
        for _ in 0..self.open_dirs {
            put_dir_exit(&mut self.scratch);
        }
        self.flush_scratch()?;
        Ok(self.writer)
    }

    fn begin(&mut self) -> std::io::Result<()> {
        if self.poisoned {
            return Err(Error::other(
                "encoder is unusable: an earlier error left the archive incomplete",
            ));
        }
        self.scratch.clear();
        Ok(())
    }

    fn flush_scratch(&mut self) -> std::io::Result<()> {
        let result = self.writer.write_all(&self.scratch);
        self.poisoned |= result.is_err();
        result
    }

    fn stage_metadata(&mut self, meta: &Metadata) {
        if meta.uid != self.current_uid
            || meta.gid != self.current_gid
            || meta.mode != self.current_mode
        {
            put_unix_attr(&mut self.scratch, meta.uid, meta.gid, meta.mode);
        }
    }

    fn commit_metadata(&mut self, meta: &Metadata) {
        self.current_uid = meta.uid;
        self.current_gid = meta.gid;
        self.current_mode = meta.mode;
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
    /// `InvalidInput` ("declared size shorter than source"). Detecting the
    /// latter reads one byte past `size`, so pass `content.take(size)` when the
    /// source is a longer stream that must not be consumed further.
    ///
    /// If this fails after part of the file has reached the writer, the
    /// archive cannot be completed and every later call on this encoder,
    /// including [`Self::finish`], returns an error. Small files are checked
    /// against `size` before anything is written, so a size mismatch on one
    /// leaves the encoder usable.
    pub fn add_file(
        &mut self,
        name: &str,
        meta: &Metadata,
        size: u64,
        content: &mut dyn Read,
    ) -> std::io::Result<()> {
        validate_name(name)?;
        self.begin()?;
        self.stage_metadata(meta);
        let time_delta = self.calculate_time_delta(meta.modified);
        put_file(&mut self.scratch, name, size, time_delta);

        if size <= INLINE_MAX {
            let payload_at = self.scratch.len();
            self.scratch.resize(payload_at + size as usize, 0);
            read_full(content, &mut self.scratch[payload_at..])?;
            expect_end(content)?;
            if self.crc_enabled {
                let crc = CRC64.checksum(&self.scratch[payload_at..]);
                self.scratch.extend_from_slice(&crc.to_le_bytes());
            }
            self.flush_scratch()?;
            self.commit_metadata(meta);
            return Ok(());
        }

        self.flush_scratch()?;
        self.commit_metadata(meta);

        let result = self.copy_payload(size, content);
        self.poisoned |= result.is_err();
        result
    }

    fn copy_payload(&mut self, size: u64, content: &mut dyn Read) -> std::io::Result<()> {
        let mut digest = self.crc_enabled.then(|| CRC64.digest());

        self.scratch.resize(COPY_CHUNK, 0);
        let mut remaining = size;
        while remaining > 0 {
            let limit = std::cmp::min(COPY_CHUNK as u64, remaining) as usize;
            let n = match content.read(&mut self.scratch[..limit]) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "source reader ended before declared size",
                    ));
                }
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };

            self.writer.write_all(&self.scratch[..n])?;
            if let Some(d) = &mut digest {
                d.update(&self.scratch[..n]);
            }
            remaining -= n as u64;
        }

        expect_end(content)?;

        if let Some(d) = digest {
            self.writer.write_all(&d.finalize().to_le_bytes())?;
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
        self.begin()?;
        self.stage_metadata(meta);
        let time_delta = self.calculate_time_delta(meta.modified);
        put_dir_enter(&mut self.scratch, name, time_delta);
        self.flush_scratch()?;
        self.commit_metadata(meta);

        self.open_dirs += 1;
        Ok(())
    }

    /// Pops the current directory from the stack, leaving every level a
    /// compressed [`Self::enter_dir`] name opened.
    pub fn exit_dir(&mut self) -> std::io::Result<()> {
        if self.open_dirs == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot exit dir: Root reached",
            ));
        }
        self.begin()?;
        put_dir_exit(&mut self.scratch);
        self.flush_scratch()?;
        self.open_dirs -= 1;
        Ok(())
    }

    fn add_link(
        &mut self,
        opcode: Opcode,
        name: &str,
        target: &str,
        meta: &Metadata,
    ) -> std::io::Result<()> {
        validate_name(name)?;
        validate_target(target)?;
        self.begin()?;
        self.stage_metadata(meta);
        let time_delta = self.calculate_time_delta(meta.modified);
        put_link(&mut self.scratch, opcode, name, target, time_delta);
        self.flush_scratch()?;
        self.commit_metadata(meta);
        Ok(())
    }

    pub fn add_symlink(
        &mut self,
        name: &str,
        target: &str,
        target_is_dir: bool,
        meta: &Metadata,
    ) -> std::io::Result<()> {
        let opcode = if target_is_dir {
            Opcode::SymDir
        } else {
            Opcode::SymFile
        };
        self.add_link(opcode, name, target, meta)
    }

    pub fn add_hardlink(
        &mut self,
        name: &str,
        target: &str,
        meta: &Metadata,
    ) -> std::io::Result<()> {
        self.add_link(Opcode::HardLink, name, target, meta)
    }

    /// Toggles checksum generation for subsequent files.
    pub fn set_crc_enabled(&mut self, enabled: bool) -> std::io::Result<()> {
        if self.crc_enabled != enabled {
            self.begin()?;
            put_meta(&mut self.scratch, enabled, self.current_time_base);
            self.flush_scratch()?;
            self.crc_enabled = enabled;
        }
        Ok(())
    }

    /// Updates the base timestamp (e.g. for a new folder of old files).
    pub fn set_base_time(&mut self, new_base_ns: i64) -> std::io::Result<()> {
        if self.current_time_base != new_base_ns {
            self.begin()?;
            put_meta(&mut self.scratch, self.crc_enabled, new_base_ns);
            self.flush_scratch()?;
            self.current_time_base = new_base_ns;
        }
        Ok(())
    }
}
