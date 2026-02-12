use crate::spec::{Decode, Entry as RawEntry};
use std::{
    cell::RefCell,
    io::{self, Read},
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

    pub fn crc64(&self) -> Option<u64> {
        let st = self.state.borrow();

        if st.bytes_remaining == 0 && st.checksum_consumed {
            st.last_crc_valid
        } else {
            None
        }
    }
}

impl<R: Read> Read for FileEntry<R> {
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
                "Truncated file",
            ));
        }

        st.bytes_remaining -= n as u64;

        if st.bytes_remaining == 0 {
            st.consume_checksum()?;
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

pub enum ArchiveEntry<R: Read> {
    File(FileEntry<R>),
    Directory(DirEntry),
    Symlink(SymlinkEntry),
}

impl<R: Read> ArchiveEntry<R> {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(e) => &e.path,
            Self::Directory(e) => &e.path,
            Self::Symlink(e) => &e.path,
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

    bytes_remaining: u64,
    checksum_consumed: bool,
    last_crc_valid: Option<u64>,
}

impl<R: Read> DecoderState<R> {
    fn rebuild_path_cache(&mut self) {
        self.path_cache = PathBuf::from("/");
        for segment in &self.path_stack {
            self.path_cache.push(segment);
        }
    }

    fn resolve_time(&self, delta_ns: i64) -> SystemTime {
        let abs_ns = self.time_base.wrapping_add(delta_ns);
        if abs_ns >= 0 {
            UNIX_EPOCH + Duration::from_nanos(abs_ns as u64)
        } else {
            UNIX_EPOCH - Duration::from_nanos((-abs_ns) as u64)
        }
    }

    fn consume_checksum(&mut self) -> io::Result<()> {
        if self.has_crc && !self.checksum_consumed {
            let mut buf = [0u8; 8];
            self.reader.read_exact(&mut buf)?;
            self.last_crc_valid = Some(u64::from_le_bytes(buf));
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

pub struct ItafDecoder<R: Read> {
    state: Rc<RefCell<DecoderState<R>>>,
    pub base_timestamp: i64,
}

impl<R: Read> ItafDecoder<R> {
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

        let state = DecoderState {
            reader,
            path_stack: Vec::new(),
            path_cache: PathBuf::from("/"),
            uid: 0,
            gid: 0,
            mode: 0o644,
            time_base: base_timestamp,
            has_crc,
            bytes_remaining: 0,
            checksum_consumed: true,
            last_crc_valid: None,
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
    type Item = io::Result<ArchiveEntry<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.state.borrow_mut().drain_active_file() {
            return Some(Err(e));
        }

        loop {
            let mut st = self.state.borrow_mut();

            let raw_entry = match RawEntry::decode(&mut st.reader) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return None,
                Err(e) => return Some(Err(e)),
            };

            match raw_entry {
                RawEntry::DirExit => {
                    st.path_stack.pop();
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
                    st.last_crc_valid = None;

                    let path = st.path_cache.join(name);
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
                    st.path_stack.push(name);
                    st.rebuild_path_cache();
                    let path = st.path_cache.clone();
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode | 0o111,
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
                    let path = st.path_cache.join(name);
                    let meta = Metadata {
                        uid: st.uid,
                        gid: st.gid,
                        mode: st.mode | 0o20000,
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
                    let path = st.path_cache.join(name);
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
                        is_dir: false,
                        meta,
                    })));
                }
            }
        }
    }
}
