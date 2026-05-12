use crate::spec::{Decode, DecodeLimits, Entry as RawEntry, FORMAT_VERSION, MAGIC};
use crc::{CRC_64_GO_ISO, Crc};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Read},
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static CRC_ALG: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

#[derive(Debug, Clone)]
pub struct Metadata {
    pub uid: u64,
    pub gid: u64,
    pub mode: u32,
    pub modified: SystemTime,
}

fn sanitize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(os_str) => out.push(os_str),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
        }
    }
    out
}

pub struct FileEntry<R: Read> {
    state: Rc<RefCell<DecoderState<R>>>,
    path: PathBuf,
    meta: Metadata,
    size: u64,
}

impl<R: Read> FileEntry<R> {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the verified CRC64 of this file's payload, or `None` if the
    /// archive did not include one. This is **only** populated after the file
    /// has been fully consumed *and* the stored CRC matched the computed CRC.
    /// On mismatch, the corresponding `read()` returns `InvalidData`.
    pub fn crc64(&self) -> Option<u64> {
        let st = self.state.borrow();
        if st.bytes_remaining == 0 && st.checksum_consumed {
            st.last_crc_verified
        } else {
            None
        }
    }
}

impl<R: Read> Read for FileEntry<R> {
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
                "truncated file payload",
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

impl<R: Read> Drop for FileEntry<R> {
    fn drop(&mut self) {
        let _ = self.state.borrow_mut().drain_active_file();
    }
}

pub struct DirEntry {
    pub(crate) path: PathBuf,
    pub(crate) meta: Metadata,
}

impl DirEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }
}

pub struct SymlinkEntry {
    pub(crate) path: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) meta: Metadata,
    pub(crate) is_dir: bool,
}

impl SymlinkEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn is_target_dir(&self) -> bool {
        self.is_dir
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    pub fn enclosed_target(&self) -> PathBuf {
        sanitize_path(&self.target)
    }
}

pub struct HardlinkEntry {
    pub(crate) path: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) meta: Metadata,
}

impl HardlinkEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    pub fn enclosed_target(&self) -> PathBuf {
        sanitize_path(&self.target)
    }
}

pub enum ArchiveEntry<R: Read> {
    File(FileEntry<R>),
    Directory(DirEntry),
    Symlink(SymlinkEntry),
    Hardlink(HardlinkEntry),
}

impl<R: Read> ArchiveEntry<R> {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(e) => &e.path,
            Self::Directory(e) => &e.path,
            Self::Symlink(e) => &e.path,
            Self::Hardlink(e) => &e.path,
        }
    }

    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(self.path())
    }

    pub fn metadata(&self) -> &Metadata {
        match self {
            Self::File(e) => &e.meta,
            Self::Directory(e) => &e.meta,
            Self::Symlink(e) => &e.meta,
            Self::Hardlink(e) => &e.meta,
        }
    }
}

struct DecoderState<R> {
    reader: R,
    path_stack: Vec<String>,
    path_cache: PathBuf,

    uid: u64,
    gid: u64,
    mode: u32,
    time_base: i64,
    has_crc: bool,

    limits: DecodeLimits,

    bytes_remaining: u64,
    checksum_consumed: bool,
    last_crc_verified: Option<u64>,
    active_digest: Option<crc::Digest<'static, u64>>,
}

impl<R: Read> DecoderState<R> {
    fn rebuild_path_cache(&mut self) {
        self.path_cache = PathBuf::from("/");
        for segment in &self.path_stack {
            self.path_cache.push(segment);
        }
    }

    /// Compute a SystemTime from a base + delta using i128 to avoid wrap.
    /// Out-of-range values clamp to UNIX_EPOCH ± Duration::MAX rather than
    /// panic or silently flip sign.
    fn resolve_time(&self, delta_ns: i64) -> SystemTime {
        let abs_ns = (self.time_base as i128).saturating_add(delta_ns as i128);
        if abs_ns >= 0 {
            let secs = (abs_ns / 1_000_000_000) as u64;
            let nanos = (abs_ns % 1_000_000_000) as u32;
            UNIX_EPOCH
                .checked_add(Duration::new(secs, nanos))
                .unwrap_or(UNIX_EPOCH)
        } else {
            let pos = (-abs_ns) as u128;
            let secs = (pos / 1_000_000_000) as u64;
            let nanos = (pos % 1_000_000_000) as u32;
            UNIX_EPOCH
                .checked_sub(Duration::new(secs, nanos))
                .unwrap_or(UNIX_EPOCH)
        }
    }

    fn consume_and_verify_checksum(&mut self) -> std::io::Result<()> {
        if !self.has_crc || self.checksum_consumed {
            return Ok(());
        }
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
        Ok(())
    }

    fn drain_active_file(&mut self) -> std::io::Result<()> {
        if self.bytes_remaining > 0 {
            let mut buf = vec![0; 32 * 1024];
            while self.bytes_remaining > 0 {
                let want = std::cmp::min(buf.len() as u64, self.bytes_remaining) as usize;
                let n = self.reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated file payload while draining",
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

pub struct ItafDecoder<R: Read> {
    state: Rc<RefCell<DecoderState<R>>>,
    pub base_timestamp: i64,
}

impl<R: Read> ItafDecoder<R> {
    /// Read an itaf archive header with default decoder limits.
    pub fn new(reader: R) -> std::io::Result<Self> {
        Self::with_limits(reader, DecodeLimits::default())
    }

    /// Read an itaf archive header with custom decoder limits.
    pub fn with_limits(mut reader: R, limits: DecodeLimits) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "not an itaf archive (bad magic)",
            ));
        }

        let mut ver = [0u8; 1];
        reader.read_exact(&mut ver)?;
        if ver[0] != FORMAT_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
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

        let state = DecoderState {
            reader,
            path_stack: Vec::new(),
            path_cache: PathBuf::from("/"),
            uid: 0,
            gid: 0,
            mode: 0o644,
            time_base: base_timestamp,
            has_crc,
            limits,
            bytes_remaining: 0,
            checksum_consumed: true,
            last_crc_verified: None,
            active_digest: None,
        };

        Ok(Self {
            state: Rc::new(RefCell::new(state)),
            base_timestamp,
        })
    }

    pub fn entries(self) -> Entries<R> {
        Entries { state: self.state }
    }
}

pub struct Entries<R: Read> {
    state: Rc<RefCell<DecoderState<R>>>,
}

impl<R: Read> Iterator for Entries<R> {
    type Item = std::io::Result<ArchiveEntry<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.state.borrow_mut().drain_active_file() {
            return Some(Err(e));
        }

        loop {
            let mut st = self.state.borrow_mut();

            let limits = st.limits;
            let raw_entry = match RawEntry::decode(&mut st.reader, &limits) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                Err(e) => return Some(Err(e)),
            };

            match raw_entry {
                RawEntry::DirExit => {
                    if st.path_stack.pop().is_none() {
                        return Some(Err(Error::new(
                            ErrorKind::InvalidData,
                            "DirExit with empty directory stack",
                        )));
                    }
                    st.rebuild_path_cache();
                    continue;
                }
                RawEntry::Meta { has_crc, time_base } => {
                    st.has_crc = has_crc;
                    st.time_base = time_base;
                    continue;
                }
                RawEntry::UnixAttr { uid, gid, mode } => {
                    st.uid = uid;
                    st.gid = gid;
                    st.mode = mode;
                    continue;
                }
                RawEntry::Ext { .. } => continue,

                RawEntry::File {
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

                    let path = st.path_cache.join(&name);
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode,
                        modified: st.resolve_time(time_delta_ns),
                    };

                    drop(st);
                    return Some(Ok(ArchiveEntry::File(FileEntry {
                        state: self.state.clone(),
                        path,
                        meta,
                        size,
                    })));
                }
                RawEntry::DirEnter {
                    name,
                    time_delta_ns,
                } => {
                    if st.path_stack.len() >= st.limits.max_depth {
                        return Some(Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("directory nesting exceeded limit {}", st.limits.max_depth),
                        )));
                    }
                    st.path_stack.push(name);
                    st.rebuild_path_cache();
                    let path = st.path_cache.clone();
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode,
                        modified: st.resolve_time(time_delta_ns),
                    };
                    drop(st);
                    return Some(Ok(ArchiveEntry::Directory(DirEntry { path, meta })));
                }
                RawEntry::Symlink {
                    name,
                    target,
                    is_dir,
                    time_delta_ns,
                } => {
                    let path = st.path_cache.join(&name);
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode,
                        modified: st.resolve_time(time_delta_ns),
                    };
                    drop(st);
                    return Some(Ok(ArchiveEntry::Symlink(SymlinkEntry {
                        path,
                        target: PathBuf::from(target),
                        is_dir,
                        meta,
                    })));
                }
                RawEntry::Hardlink {
                    name,
                    target,
                    time_delta_ns,
                } => {
                    let path = st.path_cache.join(&name);
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode,
                        modified: st.resolve_time(time_delta_ns),
                    };
                    drop(st);
                    return Some(Ok(ArchiveEntry::Hardlink(HardlinkEntry {
                        path,
                        target: PathBuf::from(target),
                        meta,
                    })));
                }
            }
        }
    }
}
