use crate::spec::{CRC64, Crc64Digest};
use std::io::{Error, ErrorKind, Read};

/// Tracks the payload of the file the decoder is currently positioned on.
///
/// Entries handed out by the iterators carry the generation they were created
/// in, so a handle kept across an iterator step cannot read bytes belonging to
/// a later file.
pub(crate) struct Payload {
    remaining: u64,
    crc_pending: bool,
    digest: Option<Crc64Digest>,
    verified: Option<u64>,
    generation: u64,
}

impl Payload {
    pub(crate) fn new() -> Self {
        Self {
            remaining: 0,
            crc_pending: false,
            digest: None,
            verified: None,
            generation: 0,
        }
    }

    pub(crate) fn begin(&mut self, size: u64, has_crc: bool) -> u64 {
        self.remaining = size;
        self.crc_pending = has_crc;
        self.digest = has_crc.then(|| CRC64.digest());
        self.verified = None;
        self.generation
    }

    /// The CRC of the current file, once it was read to the end and matched.
    pub(crate) fn verified(&self) -> Option<u64> {
        self.verified
    }

    pub(crate) fn read<R: Read>(
        &mut self,
        reader: &mut R,
        generation: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        if generation != self.generation {
            return Err(Error::other(
                "file entry is no longer readable: the archive iterator has advanced past it",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            self.verify(reader)?;
            return Ok(0);
        }

        let max = std::cmp::min(buf.len() as u64, self.remaining) as usize;
        let n = reader.read(&mut buf[..max])?;
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "truncated file payload",
            ));
        }
        if let Some(d) = self.digest.as_mut() {
            d.update(&buf[..n]);
        }
        self.remaining -= n as u64;

        if self.remaining == 0 {
            self.verify(reader)?;
        }
        Ok(n)
    }

    fn verify<R: Read>(&mut self, reader: &mut R) -> std::io::Result<()> {
        if !self.crc_pending {
            return Ok(());
        }
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        self.crc_pending = false;
        let stored = u64::from_le_bytes(buf);

        if let Some(d) = self.digest.take() {
            let computed = d.finalize();
            if computed != stored {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "CRC64 mismatch: stored {:016x}, computed {:016x}",
                        stored, computed
                    ),
                ));
            }
            self.verified = Some(stored);
        }
        Ok(())
    }

    /// Moves past whatever is left of the current file and invalidates handles
    /// to it. Skipped bytes are not checksummed: only a file read to the end
    /// is verified.
    pub(crate) fn skip<R: Read>(&mut self, reader: &mut R) -> std::io::Result<()> {
        self.generation += 1;
        self.digest = None;

        if self.remaining > 0 {
            let mut buf = [0u8; 32 * 1024];
            while self.remaining > 0 {
                let want = std::cmp::min(buf.len() as u64, self.remaining) as usize;
                match reader.read(&mut buf[..want]) {
                    Ok(0) => {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated file payload",
                        ));
                    }
                    Ok(n) => self.remaining -= n as u64,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if self.crc_pending {
            let mut crc = [0u8; 8];
            reader.read_exact(&mut crc)?;
            self.crc_pending = false;
        }
        Ok(())
    }
}
