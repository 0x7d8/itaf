use std::io::{Error, ErrorKind, Read, Write};

/// Decoder limits. The decoder enforces these to bound resource usage when
/// reading archives from untrusted sources (network peers, user uploads, etc).
///
/// Limits are intentionally generous for typical workloads but small enough
/// to prevent trivial DoS via crafted archives declaring 2^64-byte strings.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    /// Maximum length, in bytes, of an entry name (file, dir, symlink).
    pub max_name_len: u64,
    /// Maximum length, in bytes, of a symlink/hardlink target.
    pub max_target_len: u64,
    /// Maximum length, in bytes, of an `Ext` instruction payload.
    pub max_ext_len: u64,
    /// Maximum directory nesting depth.
    pub max_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_name_len: 4096,
            max_target_len: 65_536,
            max_ext_len: 1_048_576,
            max_depth: 1024,
        }
    }
}

pub trait Encode {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()>;
}

pub trait Decode: Sized {
    fn decode(reader: &mut dyn Read, limits: &DecodeLimits) -> std::io::Result<Self>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VarUint(pub u64);

impl Encode for VarUint {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        let mut n = self.0;
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
                writer.write_all(&[byte])?;
            } else {
                writer.write_all(&[byte])?;
                break;
            }
        }
        Ok(())
    }
}

impl VarUint {
    /// Decode without consulting limits - used for inherently bounded
    /// numeric fields (mode bits, time deltas, etc.).
    pub fn decode_unchecked(reader: &mut dyn Read) -> std::io::Result<Self> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            let byte = buf[0];

            if shift >= 63 && byte > 1 {
                return Err(Error::new(ErrorKind::InvalidData, "VarUint overflow"));
            }

            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(VarUint(result));
            }
            shift += 7;
        }
    }
}

impl Decode for VarUint {
    fn decode(reader: &mut dyn Read, _limits: &DecodeLimits) -> std::io::Result<Self> {
        Self::decode_unchecked(reader)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VarInt(pub i64);

impl Encode for VarInt {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        let zigged = (self.0 << 1) ^ (self.0 >> 63);
        VarUint(zigged as u64).encode(writer)
    }
}

impl VarInt {
    pub fn decode_unchecked(reader: &mut dyn Read) -> std::io::Result<Self> {
        let raw = VarUint::decode_unchecked(reader)?.0;
        let zagged = (raw >> 1) as i64 ^ -((raw & 1) as i64);
        Ok(VarInt(zagged))
    }
}

impl Decode for VarInt {
    fn decode(reader: &mut dyn Read, _limits: &DecodeLimits) -> std::io::Result<Self> {
        Self::decode_unchecked(reader)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    File = 0x0,
    DirEnter = 0x1,
    DirExit = 0x2,
    Meta = 0x3,
    SymFile = 0x4,
    SymDir = 0x5,
    HardLink = 0x6,
    UnixAttr = 0x7,
    // 0x8..0xE Reserved
    Ext = 0xF,
}

impl Opcode {
    fn from_u8(n: u8) -> std::io::Result<Self> {
        match n {
            0x0 => Ok(Opcode::File),
            0x1 => Ok(Opcode::DirEnter),
            0x2 => Ok(Opcode::DirExit),
            0x3 => Ok(Opcode::Meta),
            0x4 => Ok(Opcode::SymFile),
            0x5 => Ok(Opcode::SymDir),
            0x6 => Ok(Opcode::HardLink),
            0x7 => Ok(Opcode::UnixAttr),
            0xF => Ok(Opcode::Ext),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unknown Opcode: {:x}", n),
            )),
        }
    }
}

#[derive(Debug)]
pub struct InstructionTag {
    pub opcode: Opcode,
    pub immediate: u8,
}

impl Encode for InstructionTag {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        if self.immediate > 15 {
            return Err(Error::new(ErrorKind::InvalidInput, "Immediate > 15"));
        }
        let byte = ((self.opcode as u8) << 4) | (self.immediate & 0x0F);
        writer.write_all(&[byte])
    }
}

impl InstructionTag {
    pub fn decode_unchecked(reader: &mut dyn Read) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        let opcode = Opcode::from_u8(buf[0] >> 4)?;
        let immediate = buf[0] & 0x0F;
        Ok(InstructionTag { opcode, immediate })
    }
}

impl Decode for InstructionTag {
    fn decode(reader: &mut dyn Read, _limits: &DecodeLimits) -> std::io::Result<Self> {
        Self::decode_unchecked(reader)
    }
}

pub fn validate_name(name: &str) -> std::io::Result<()> {
    if name.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "empty entry name"));
    }
    for segment in name.split('/') {
        if segment.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "entry name has an empty path segment",
            ));
        }
        if segment == "." || segment == ".." {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "entry name segment must not be '.' or '..'",
            ));
        }
        if segment.as_bytes().contains(&0) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "entry name contains NUL",
            ));
        }
    }
    Ok(())
}

pub fn name_depth(name: &str) -> usize {
    name.split('/').count()
}

fn validate_target(target: &str) -> std::io::Result<()> {
    if target.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "empty link target"));
    }
    if target.as_bytes().contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "link target contains NUL",
        ));
    }
    Ok(())
}

fn decode_bounded_string(
    reader: &mut dyn Read,
    declared_len: u64,
    cap: u64,
    role: &'static str,
) -> std::io::Result<String> {
    if declared_len > cap {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "declared {} length {} exceeds limit {}",
                role, declared_len, cap
            ),
        ));
    }
    let mut buf = vec![0u8; declared_len as usize];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

pub fn decode_name(
    reader: &mut dyn Read,
    immediate: u8,
    limits: &DecodeLimits,
) -> std::io::Result<String> {
    let len = if immediate < 15 {
        immediate as u64
    } else {
        VarUint::decode_unchecked(reader)?.0
    };
    let s = decode_bounded_string(reader, len, limits.max_name_len, "name")?;
    validate_name(&s)?;
    Ok(s)
}

pub fn encode_string_parts(name: &str) -> (u8, Option<VarUint>) {
    let len = name.len() as u64;
    if len < 15 {
        (len as u8, None)
    } else {
        (15, Some(VarUint(len)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    File {
        name: String,
        size: u64,
        time_delta_ns: i64,
    },
    DirEnter {
        name: String,
        time_delta_ns: i64,
    },
    DirExit,
    Meta {
        has_crc: bool,
        time_base: i64,
    },
    UnixAttr {
        uid: u64,
        gid: u64,
        mode: u32,
    },
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
    Ext {
        type_id: u8,
        data: Vec<u8>,
    },
}

impl Encode for Entry {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        match self {
            Entry::File {
                name,
                size,
                time_delta_ns,
            } => {
                validate_name(name)?;
                let (imm, extra) = encode_string_parts(name);
                InstructionTag {
                    opcode: Opcode::File,
                    immediate: imm,
                }
                .encode(writer)?;
                if let Some(v) = extra {
                    v.encode(writer)?;
                }
                writer.write_all(name.as_bytes())?;
                VarUint(*size).encode(writer)?;
                VarInt(*time_delta_ns).encode(writer)?;
                Ok(())
            }
            Entry::DirEnter {
                name,
                time_delta_ns,
            } => {
                validate_name(name)?;
                let (imm, extra) = encode_string_parts(name);
                InstructionTag {
                    opcode: Opcode::DirEnter,
                    immediate: imm,
                }
                .encode(writer)?;
                if let Some(v) = extra {
                    v.encode(writer)?;
                }
                writer.write_all(name.as_bytes())?;
                VarInt(*time_delta_ns).encode(writer)?;
                Ok(())
            }
            Entry::DirExit => InstructionTag {
                opcode: Opcode::DirExit,
                immediate: 0,
            }
            .encode(writer),
            Entry::Meta { has_crc, time_base } => {
                let imm = if *has_crc { 1 } else { 0 };
                InstructionTag {
                    opcode: Opcode::Meta,
                    immediate: imm,
                }
                .encode(writer)?;
                VarInt(*time_base).encode(writer)?;
                Ok(())
            }
            Entry::UnixAttr { uid, gid, mode } => {
                InstructionTag {
                    opcode: Opcode::UnixAttr,
                    immediate: 0,
                }
                .encode(writer)?;
                VarUint(*uid).encode(writer)?;
                VarUint(*gid).encode(writer)?;
                writer.write_all(&mode.to_le_bytes())?;
                Ok(())
            }
            Entry::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            } => {
                validate_name(name)?;
                validate_target(target)?;
                let opcode = if *is_dir {
                    Opcode::SymDir
                } else {
                    Opcode::SymFile
                };
                let (imm, extra) = encode_string_parts(name);
                InstructionTag {
                    opcode,
                    immediate: imm,
                }
                .encode(writer)?;
                if let Some(v) = extra {
                    v.encode(writer)?;
                }
                writer.write_all(name.as_bytes())?;
                VarInt(*time_delta_ns).encode(writer)?;

                VarUint(target.len() as u64).encode(writer)?;
                writer.write_all(target.as_bytes())?;
                Ok(())
            }
            Entry::Hardlink {
                name,
                target,
                time_delta_ns,
            } => {
                validate_name(name)?;
                validate_target(target)?;
                let (imm, extra) = encode_string_parts(name);
                InstructionTag {
                    opcode: Opcode::HardLink,
                    immediate: imm,
                }
                .encode(writer)?;
                if let Some(v) = extra {
                    v.encode(writer)?;
                }
                writer.write_all(name.as_bytes())?;
                VarInt(*time_delta_ns).encode(writer)?;

                VarUint(target.len() as u64).encode(writer)?;
                writer.write_all(target.as_bytes())?;
                Ok(())
            }
            Entry::Ext { type_id, data } => {
                if *type_id > 15 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Ext type_id must fit in 4-bit immediate",
                    ));
                }
                InstructionTag {
                    opcode: Opcode::Ext,
                    immediate: *type_id,
                }
                .encode(writer)?;
                VarUint(data.len() as u64).encode(writer)?;
                writer.write_all(data)?;
                Ok(())
            }
        }
    }
}

impl Decode for Entry {
    fn decode(reader: &mut dyn Read, limits: &DecodeLimits) -> std::io::Result<Self> {
        let tag = InstructionTag::decode_unchecked(reader)?;

        match tag.opcode {
            Opcode::File => {
                let name = decode_name(reader, tag.immediate, limits)?;
                let size = VarUint::decode_unchecked(reader)?.0;
                let time_delta_ns = VarInt::decode_unchecked(reader)?.0;
                Ok(Entry::File {
                    name,
                    size,
                    time_delta_ns,
                })
            }
            Opcode::DirEnter => {
                let name = decode_name(reader, tag.immediate, limits)?;
                let time_delta_ns = VarInt::decode_unchecked(reader)?.0;
                Ok(Entry::DirEnter {
                    name,
                    time_delta_ns,
                })
            }
            Opcode::DirExit => Ok(Entry::DirExit),
            Opcode::Meta => {
                let has_crc = (tag.immediate & 1) != 0;
                let time_base = VarInt::decode_unchecked(reader)?.0;
                Ok(Entry::Meta { has_crc, time_base })
            }
            Opcode::UnixAttr => {
                let uid = VarUint::decode_unchecked(reader)?.0;
                let gid = VarUint::decode_unchecked(reader)?.0;
                let mut mode_buf = [0u8; 4];
                reader.read_exact(&mut mode_buf)?;
                let mode = u32::from_le_bytes(mode_buf);
                Ok(Entry::UnixAttr { uid, gid, mode })
            }
            Opcode::SymFile | Opcode::SymDir => {
                let name = decode_name(reader, tag.immediate, limits)?;
                let time_delta_ns = VarInt::decode_unchecked(reader)?.0;
                let target_len = VarUint::decode_unchecked(reader)?.0;
                let target =
                    decode_bounded_string(reader, target_len, limits.max_target_len, "target")?;
                validate_target(&target)?;
                Ok(Entry::Symlink {
                    name,
                    target,
                    is_dir: tag.opcode == Opcode::SymDir,
                    time_delta_ns,
                })
            }
            Opcode::HardLink => {
                let name = decode_name(reader, tag.immediate, limits)?;
                let time_delta_ns = VarInt::decode_unchecked(reader)?.0;
                let target_len = VarUint::decode_unchecked(reader)?.0;
                let target =
                    decode_bounded_string(reader, target_len, limits.max_target_len, "target")?;
                validate_target(&target)?;
                Ok(Entry::Hardlink {
                    name,
                    target,
                    time_delta_ns,
                })
            }
            Opcode::Ext => {
                let len = VarUint::decode_unchecked(reader)?.0;
                if len > limits.max_ext_len {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Ext payload {} exceeds limit {}", len, limits.max_ext_len),
                    ));
                }
                let mut data = vec![0u8; len as usize];
                reader.read_exact(&mut data)?;
                Ok(Entry::Ext {
                    type_id: tag.immediate,
                    data,
                })
            }
        }
    }
}

pub const FORMAT_VERSION: u8 = 1;
pub const MAGIC: &[u8; 4] = b"ITAF";
