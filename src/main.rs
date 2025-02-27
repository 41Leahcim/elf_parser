#![warn(clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(
    clippy::must_use_candidate,
    clippy::allow_attributes_without_reason,
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::pattern_type_mismatch,
    clippy::min_ident_chars,
    clippy::arbitrary_source_item_ordering,
    clippy::question_mark_used,
    clippy::single_call_fn,
    clippy::use_debug,
    clippy::print_stdout
)]

//! Source: <https://wiki.osdev.org/ELF>

use core::fmt::{self, Display, Write as _};

use std::{
    env::args,
    fs::File,
    io::{self, BufReader, Read},
};

/// The size of a word/pointer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums)]
pub enum WordSize {
    B32,
    B64,
}

impl Display for WordSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-bit",
            match self {
                Self::B32 => 32,
                Self::B64 => 64,
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElfType {
    Relocatable,
    Executable,
    Shared,
    Core,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Architecture {
    NoSpecific = 0,
    Sparc = 2,
    X86 = 3,
    Mips = 8,
    PowerPc = 0x14,
    Arm = 0x28,
    SuperH = 0x2A,
    Ia64 = 0x32,
    X86_64 = 0x3E,
    Aarch64 = 0xB7,
    RiscV = 0xF3,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums)]
pub enum Offset {
    B32(u32),
    B64(u64),
}

impl Offset {
    /// # Errors
    /// Returns an error if not enough bytes could be read from the reader.
    pub fn from_readable<R: Read>(reader: &mut R, word_size: WordSize) -> io::Result<Self> {
        if word_size == WordSize::B32 {
            read_u32(reader).map(Offset::B32)
        } else {
            read_u64(reader).map(Offset::B64)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u32);

impl Flags {
    pub const fn readable(&self) -> bool {
        (self.0 >> 2) & 1 == 1
    }

    pub const fn writable(&self) -> bool {
        (self.0 >> 1) & 1 == 1
    }

    pub const fn executable(&self) -> bool {
        self.0 & 1 == 1
    }
}

impl Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.readable() {
            f.write_char('r')?;
        } else {
            f.write_char('-')?;
        }
        if self.writable() {
            f.write_char('w')?;
        } else {
            f.write_char('-')?;
        }
        if self.executable() {
            f.write_char('x')
        } else {
            f.write_char('-')
        }
    }
}

/// Reads the requested number of bytes, returns an error when reading fails
fn read_bytes<const SIZE: usize>(reader: &mut impl Read) -> io::Result<[u8; SIZE]> {
    let mut result = [0; SIZE];
    reader.read_exact(&mut result)?;
    Ok(result)
}

/// Reads a single byte
fn read_byte(reader: &mut impl Read) -> io::Result<u8> {
    read_bytes::<1>(reader).map(|result| result[0])
}

/// Reads 2 bytes into a u16
fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    read_bytes::<2>(reader).map(u16::from_ne_bytes)
}

/// Reads 4 bytes into a u32
fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    read_bytes::<4>(reader).map(u32::from_ne_bytes)
}

/// Reads 8 bytes into a u64
fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    read_bytes::<8>(reader).map(u64::from_ne_bytes)
}

/// Error while parsing an ELF file
#[non_exhaustive]
#[derive(Debug)]
pub enum ElfError {
    Io(io::Error),
    InvalidStart([u8; 4]),
    InvalidWordSize(u8),
    InvalidEndian(u8),
    InvalidElfType(u16),
}

impl From<io::Error> for ElfError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// The ELF file header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf {
    /// The size of a word/pointer
    word_size: WordSize,

    /// The endiannes of the system
    endian: Endian,

    /// Version of the header
    header_version: u8,

    /// OS ABI - 0 usually means System V
    os_abi: u8,

    /// Type of the elf file
    elf_type: ElfType,

    /// Architecture of the platform
    architecture: Architecture,

    /// ELF version, this application is based on version 1
    elf_version: u32,

    /// File offset of the program entry
    program_entry_offset: Offset,

    /// File offset of the program header table
    program_header_table_offset: Offset,

    /// File offset of the section header table
    section_header_table_offset: Offset,

    /// Architecture dependent flags
    flags: Flags,

    /// Elf header size
    elf_header_size: u16,

    /// Size of an entry in the program header table
    program_header_table_entry_size: u16,

    /// Number of entries in the program header table
    program_header_table_entry_count: u16,

    /// Size of an entry in the section header table
    section_header_table_entry_size: u16,

    /// Number of entries in the section header table
    section_header_table_entry_count: u16,

    /// Index of the string table in the section header table
    section_header_string_table_index: u16,
}

impl Elf {
    /// # Errors
    /// Returns an error if the reader didn't contain the expected number of bytes, or an invalid
    /// value was found.
    pub fn from_readable<R: Read>(reader: &mut R) -> Result<Self, ElfError> {
        let start = read_bytes::<4>(reader)?;
        if start[0] != 0x7F || &start[1..] != b"ELF" {
            return Err(ElfError::InvalidStart(start));
        }
        let word_size = match read_byte(reader)? {
            1 => WordSize::B32,
            2 => WordSize::B64,
            size => return Err(ElfError::InvalidWordSize(size)),
        };
        let endian = match read_byte(reader)? {
            1 => Endian::Little,
            2 => Endian::Big,
            endian => return Err(ElfError::InvalidEndian(endian)),
        };
        let header_version = read_byte(reader)?;
        let os_abi = read_byte(reader)?;
        let _padding = read_bytes::<8>(reader)?;
        let elf_type = match read_u16(reader)? {
            1 => ElfType::Relocatable,
            2 => ElfType::Executable,
            3 => ElfType::Shared,
            4 => ElfType::Core,
            elf_type => return Err(ElfError::InvalidElfType(elf_type)),
        };
        let architecture = match read_u16(reader)? {
            0 => Architecture::NoSpecific,
            2 => Architecture::Sparc,
            3 => Architecture::X86,
            8 => Architecture::Mips,
            0x14 => Architecture::PowerPc,
            0x28 => Architecture::Arm,
            0x2A => Architecture::SuperH,
            0x32 => Architecture::Ia64,
            0x3E => Architecture::X86_64,
            0xB7 => Architecture::Aarch64,
            0xF3 => Architecture::RiscV,
            _ => Architecture::Unknown,
        };
        Ok(Self {
            word_size,
            endian,
            header_version,
            os_abi,
            elf_type,
            architecture,
            elf_version: read_u32(reader)?,
            program_entry_offset: Offset::from_readable(reader, word_size)?,
            program_header_table_offset: Offset::from_readable(reader, word_size)?,
            section_header_table_offset: Offset::from_readable(reader, word_size)?,
            flags: Flags(read_u32(reader)?),
            elf_header_size: read_u16(reader)?,
            program_header_table_entry_size: read_u16(reader)?,
            program_header_table_entry_count: read_u16(reader)?,
            section_header_table_entry_size: read_u16(reader)?,
            section_header_table_entry_count: read_u16(reader)?,
            section_header_string_table_index: read_u16(reader)?,
        })
    }
}

impl Display for Elf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} ELF version {:?} file for {:?} endian {} {:?}",
            self.elf_type, self.elf_version, self.endian, self.word_size, self.architecture
        )
    }
}

#[expect(clippy::unwrap_used)]
fn main() {
    println!(
        "{}",
        Elf::from_readable(&mut BufReader::new(
            File::open(args().next().unwrap()).unwrap()
        ))
        .unwrap()
    );
}
