use crate::{
    payload::Payload,
    spec::{DecodeLimits, Entry as RawEntry, FORMAT_VERSION, InstructionTag, MAGIC, name_depth},
};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Read},
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    generation: u64,
    crc: Option<u64>,
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

    /// The entry's path with `..` traversal resolved away, safe to join onto an
    /// extraction root. Prefer this over [`Self::path`].
    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    /// The entry's path exactly as stored, **unsanitized**.
    ///
    /// Names come from whoever wrote the archive, so this may contain `..`
    /// components and is root-anchored. Never join it onto an extraction root —
    /// use [`Self::enclosed_path`] for that. This accessor is for display and
    /// for callers doing their own containment.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the verified CRC64 of this file's payload, or `None` if the
    /// archive did not include one. This is **only** populated after the file
    /// has been fully consumed *and* the stored CRC matched the computed CRC.
    /// On mismatch, the corresponding `read()` returns `InvalidData`.
    pub fn crc64(&self) -> Option<u64> {
        self.crc
    }
}

/// Reads the file's payload. The entry is only readable until the iterator
/// that produced it is advanced; after that, `read` returns an error rather
/// than bytes of a later file.
impl<R: Read> Read for FileEntry<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let st = &mut *self.state.borrow_mut();
        let n = st.payload.read(&mut st.reader, self.generation, buf)?;
        self.crc = st.payload.verified();
        Ok(n)
    }
}

pub struct DirEntry {
    pub(crate) path: PathBuf,
    pub(crate) meta: Metadata,
}

impl DirEntry {
    /// The entry's path exactly as stored, **unsanitized**. See
    /// [`FileEntry::path`]; prefer [`Self::enclosed_path`] when extracting.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    /// The entry's path with `..` traversal resolved away, safe to join onto an
    /// extraction root.
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
    /// The entry's path exactly as stored, **unsanitized**. See
    /// [`FileEntry::path`]; prefer [`Self::enclosed_path`] when extracting.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The link target exactly as stored, **unsanitized**.
    ///
    /// Targets are unconstrained beyond being non-empty and NUL-free, so this
    /// may be absolute or escape the archive root entirely. Creating a symlink
    /// pointing here is only safe if you intend to reproduce the original link
    /// verbatim; use [`Self::enclosed_target`] to confine it instead.
    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn is_target_dir(&self) -> bool {
        self.is_dir
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    /// The entry's path with `..` traversal resolved away, safe to join onto an
    /// extraction root.
    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    /// The link target with `..` traversal resolved away, confined to the
    /// extraction root.
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
    /// The entry's path exactly as stored, **unsanitized**. See
    /// [`FileEntry::path`]; prefer [`Self::enclosed_path`] when extracting.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The link target exactly as stored, **unsanitized**. See
    /// [`SymlinkEntry::target`]; prefer [`Self::enclosed_target`] when
    /// extracting.
    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    /// The entry's path with `..` traversal resolved away, safe to join onto an
    /// extraction root.
    pub fn enclosed_path(&self) -> PathBuf {
        sanitize_path(&self.path)
    }

    /// The link target with `..` traversal resolved away, confined to the
    /// extraction root.
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
    /// The entry's path exactly as stored, **unsanitized**. See
    /// [`FileEntry::path`]; prefer [`Self::enclosed_path`] when extracting.
    pub fn path(&self) -> &Path {
        match self {
            Self::File(e) => &e.path,
            Self::Directory(e) => &e.path,
            Self::Symlink(e) => &e.path,
            Self::Hardlink(e) => &e.path,
        }
    }

    /// The entry's path with `..` traversal resolved away, safe to join onto an
    /// extraction root. This is the accessor extraction code should use.
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
    /// Per open frame: the length `path_cache` had before it, and the levels
    /// it opened.
    path_stack: Vec<(usize, usize)>,
    path_cache: String,
    /// Directory levels currently open. Not `path_stack.len()`: a single frame
    /// may be a compressed name like `world/region` worth two levels.
    depth: usize,

    uid: u64,
    gid: u64,
    mode: u32,
    time_base: i64,
    has_crc: bool,

    limits: DecodeLimits,

    payload: Payload,
    /// Set after the end of the archive or the first error. Past an error the
    /// stream position is unknown, so nothing further can be decoded.
    done: bool,
}

impl<R: Read> DecoderState<R> {
    fn child_path(&self, name: &str) -> PathBuf {
        let mut path = String::with_capacity(self.path_cache.len() + 1 + name.len());
        path.push_str(&self.path_cache);
        if path.len() > 1 {
            path.push('/');
        }
        path.push_str(name);
        PathBuf::from(path)
    }

    /// Reject a name that would open more directory levels than the limit
    /// allows. `added` is the number of levels the name introduces, which is
    /// every segment for a `DirEnter` and every segment but the last for a
    /// leaf, so that a compressed name cannot outrun the limit that the
    /// equivalent chain of `DirEnter`s would hit.
    fn check_depth(&self, added: usize) -> std::io::Result<()> {
        if self.depth + added > self.limits.max_depth {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("directory nesting exceeded limit {}", self.limits.max_depth),
            ));
        }
        Ok(())
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
}

pub struct ItafDecoder<R: Read> {
    state: Rc<RefCell<DecoderState<R>>>,
    pub base_timestamp: i64,
}

impl<R: Read> ItafDecoder<R> {
    /// Read an itaf archive header with default decoder limits.
    ///
    /// Instructions are decoded with many small reads, so wrap an unbuffered
    /// source such as a `File` or socket in a `BufReader`.
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
            path_cache: String::from("/"),
            depth: 0,
            uid: 0,
            gid: 0,
            mode: 0o644,
            time_base: base_timestamp,
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
        let mut st = self.state.borrow_mut();
        if st.done {
            return None;
        }
        match st.advance() {
            Ok(Some(entry)) => {
                drop(st);
                Some(Ok(self.attach(entry)))
            }
            Ok(None) => {
                st.done = true;
                None
            }
            Err(e) => {
                st.done = true;
                Some(Err(e))
            }
        }
    }
}

enum Decoded {
    File {
        generation: u64,
        path: PathBuf,
        meta: Metadata,
        size: u64,
    },
    Directory(DirEntry),
    Symlink(SymlinkEntry),
    Hardlink(HardlinkEntry),
}

impl<R: Read> Entries<R> {
    fn attach(&self, decoded: Decoded) -> ArchiveEntry<R> {
        match decoded {
            Decoded::File {
                generation,
                path,
                meta,
                size,
            } => ArchiveEntry::File(FileEntry {
                state: self.state.clone(),
                generation,
                crc: None,
                path,
                meta,
                size,
            }),
            Decoded::Directory(e) => ArchiveEntry::Directory(e),
            Decoded::Symlink(e) => ArchiveEntry::Symlink(e),
            Decoded::Hardlink(e) => ArchiveEntry::Hardlink(e),
        }
    }
}

impl<R: Read> DecoderState<R> {
    fn metadata(&self, time_delta_ns: i64) -> Metadata {
        Metadata {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            modified: self.resolve_time(time_delta_ns),
        }
    }

    fn advance(&mut self) -> std::io::Result<Option<Decoded>> {
        self.payload.skip(&mut self.reader)?;

        loop {
            let Some(tag) = InstructionTag::decode_or_eof(&mut self.reader)? else {
                if self.depth > 0 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "archive ended inside {} unclosed directory level(s)",
                            self.depth
                        ),
                    ));
                }
                return Ok(None);
            };

            match RawEntry::decode_body(tag, &mut self.reader, &self.limits)? {
                RawEntry::DirExit => {
                    let Some((parent_len, levels)) = self.path_stack.pop() else {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "DirExit with empty directory stack",
                        ));
                    };
                    self.depth -= levels;
                    self.path_cache.truncate(parent_len);
                }
                RawEntry::Meta { has_crc, time_base } => {
                    self.has_crc = has_crc;
                    self.time_base = time_base;
                }
                RawEntry::UnixAttr { uid, gid, mode } => {
                    self.uid = uid;
                    self.gid = gid;
                    self.mode = mode;
                }
                RawEntry::Ext { .. } => {}

                RawEntry::File {
                    name,
                    size,
                    time_delta_ns,
                } => {
                    self.check_depth(name_depth(&name) - 1)?;
                    return Ok(Some(Decoded::File {
                        generation: self.payload.begin(size, self.has_crc),
                        path: self.child_path(&name),
                        meta: self.metadata(time_delta_ns),
                        size,
                    }));
                }
                RawEntry::DirEnter {
                    name,
                    time_delta_ns,
                } => {
                    let levels = name_depth(&name);
                    self.check_depth(levels)?;

                    self.depth += levels;
                    self.path_stack.push((self.path_cache.len(), levels));
                    if self.path_cache.len() > 1 {
                        self.path_cache.push('/');
                    }
                    self.path_cache.push_str(&name);

                    return Ok(Some(Decoded::Directory(DirEntry {
                        path: PathBuf::from(&self.path_cache),
                        meta: self.metadata(time_delta_ns),
                    })));
                }
                RawEntry::Symlink {
                    name,
                    target,
                    is_dir,
                    time_delta_ns,
                } => {
                    self.check_depth(name_depth(&name) - 1)?;
                    return Ok(Some(Decoded::Symlink(SymlinkEntry {
                        path: self.child_path(&name),
                        target: PathBuf::from(target),
                        is_dir,
                        meta: self.metadata(time_delta_ns),
                    })));
                }
                RawEntry::Hardlink {
                    name,
                    target,
                    time_delta_ns,
                } => {
                    self.check_depth(name_depth(&name) - 1)?;
                    return Ok(Some(Decoded::Hardlink(HardlinkEntry {
                        path: self.child_path(&name),
                        target: PathBuf::from(target),
                        meta: self.metadata(time_delta_ns),
                    })));
                }
            }
        }
    }
}
