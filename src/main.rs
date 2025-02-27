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

impl ElfType {
    /// # Errors
    /// Returns an error if not enough bytes could be read or an invalid value was read
    pub fn from_readable<R: Read>(reader: &mut R) -> Result<Self, ElfError> {
        Ok(match read_u16(reader)? {
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::Shared,
            4 => Self::Core,
            elf_type => return Err(ElfError::InvalidElfType(elf_type)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
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
    Unknown(u16),
}

impl Architecture {
    fn from_readable(reader: &mut impl Read) -> io::Result<Self> {
        Ok(match read_u16(reader)? {
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
            arch => Architecture::Unknown(arch),
        })
    }
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

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum SegmentType {
    /// Ignore the entry
    Null,

    /// Clear `memsz` bytes at `vaddr` to 0, then copy `filesz` bytes from `offset` to `vaddr`.
    Load,

    /// Requires dynamic linking
    Dynamic,

    /// Contains a file path to an executable to use as an interpreter for the following segment
    Interp,

    /// Note section
    Note,

    /// Architecture/environment specific information, which is probably not required for most ELF
    /// files.
    Other(u32),
}

impl SegmentType {
    fn from_readable(reader: &mut impl Read) -> io::Result<Self> {
        Ok(match read_u32(reader)? {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            segment_type => Self::Other(segment_type),
        })
    }
}

#[expect(clippy::exhaustive_enums)]
#[derive(Debug, Clone)]
pub enum ProgramHeader {
    V32 {
        /// Type of the segment
        segment_type: SegmentType,

        /// The offset in the file that the data for this segment can be found
        offset: u32,

        /// Where this segment should start in virtual memory
        virtual_address: u32,

        /// Reserved for segment's physical address
        physical_address: u32,

        /// Size of the segment in the file
        file_size: u32,

        /// Size of the segment in memory
        memory_size: u32,

        /// Flags
        flags: Flags,

        /// Required alignment for this section
        section_alignment: u32,
    },
    V64 {
        /// Type of the segment
        segment_type: SegmentType,

        /// Flags
        flags: Flags,

        /// The offset in the file that the data for this segment can be found
        offset: u64,

        /// The virtual address this segment should start at
        virtual_address: u64,

        /// Reserved for the segment's physical address
        physical_address: u64,

        /// Size of the segment in the file
        file_size: u64,

        /// Size of the segment in memory
        memory_size: u64,

        /// The required alignment for this section
        alignment: u64,
    },
}

impl ProgramHeader {
    pub fn from_readable(reader: &mut impl Read, version: WordSize) -> io::Result<Self> {
        Ok(match version {
            WordSize::B32 => Self::V32 {
                segment_type: SegmentType::from_readable(reader)?,
                offset: read_u32(reader)?,
                virtual_address: read_u32(reader)?,
                physical_address: read_u32(reader)?,
                file_size: read_u32(reader)?,
                memory_size: read_u32(reader)?,
                flags: Flags(read_u32(reader)?),
                section_alignment: read_u32(reader)?,
            },
            WordSize::B64 => Self::V64 {
                segment_type: SegmentType::from_readable(reader)?,
                flags: Flags(read_u32(reader)?),
                offset: read_u64(reader)?,
                virtual_address: read_u64(reader)?,
                physical_address: read_u64(reader)?,
                file_size: read_u64(reader)?,
                memory_size: read_u64(reader)?,
                alignment: read_u64(reader)?,
            },
        })
    }
}

/// The ELF file header
#[derive(Debug, Clone)]
#[expect(dead_code)]
pub struct Elf {
    /// The size of a word/pointer
    word_size: WordSize,

    /// The endianness of the system
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

    program_headers: Vec<ProgramHeader>,
}

impl Elf {
    /// # Errors
    /// Returns an error if the reader didn't contain the expected number of bytes, or an invalid
    /// value was found.
    pub fn from_readable<R: Read>(reader: &mut R) -> Result<Self, ElfError> {
        // Check the first 4 bytes
        let start = read_bytes::<4>(reader)?;
        if start[0] != 0x7F || &start[1..] != b"ELF" {
            return Err(ElfError::InvalidStart(start));
        }

        // Parse the word/pointer size
        let word_size = match read_byte(reader)? {
            1 => WordSize::B32,
            2 => WordSize::B64,
            size => return Err(ElfError::InvalidWordSize(size)),
        };

        // Parse the endianness
        let endian = match read_byte(reader)? {
            1 => Endian::Little,
            2 => Endian::Big,
            endian => return Err(ElfError::InvalidEndian(endian)),
        };

        // Read the header version
        let header_version = read_byte(reader)?;

        // Read the os abi version
        let os_abi = read_byte(reader)?;

        // Skip the padding
        let _: [u8; 8] = read_bytes(reader)?;

        // Parse the elf type
        let elf_type = ElfType::from_readable(reader)?;

        // Parse the architecture
        let architecture = Architecture::from_readable(reader)?;

        let elf_version = read_u32(reader)?;
        let program_entry_offset = Offset::from_readable(reader, word_size)?;
        let program_header_table_offset = Offset::from_readable(reader, word_size)?;
        let section_header_table_offset = Offset::from_readable(reader, word_size)?;
        let flags = Flags(read_u32(reader)?);
        let elf_header_size = read_u16(reader)?;
        let program_header_table_entry_size = read_u16(reader)?;
        let program_header_table_entry_count = read_u16(reader)?;
        let section_header_table_entry_size = read_u16(reader)?;
        let section_header_table_entry_count = read_u16(reader)?;
        let section_header_string_table_index = read_u16(reader)?;

        // Parse the other sections and return the result
        Ok(Self {
            word_size,
            endian,
            header_version,
            os_abi,
            elf_type,
            architecture,
            elf_version,
            program_entry_offset,
            program_header_table_offset,
            section_header_table_offset,
            flags,
            elf_header_size,
            program_header_table_entry_size,
            program_header_table_entry_count,
            section_header_table_entry_size,
            section_header_table_entry_count,
            section_header_string_table_index,
            program_headers: {
                match program_entry_offset {
                    Offset::B32(offset) => {
                        reader.bytes().take((offset - 52) as usize).for_each(|_| {});
                    }
                    Offset::B64(offset) => {
                        reader.bytes().take((offset - 52) as usize).for_each(|_| {});
                    }
                }
                (0..program_header_table_entry_count)
                    .map(|_| ProgramHeader::from_readable(reader, word_size))
                    .collect::<io::Result<Vec<_>>>()?
            },
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
    let elf = Elf::from_readable(&mut BufReader::new(
        File::open(args().next().unwrap()).unwrap(),
    ))
    .unwrap();
    println!("{elf:?}\n{elf}",);
}
