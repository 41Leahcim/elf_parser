/// Source: https://wiki.osdev.org/ELF
use std::{
    env::args,
    fmt::{Display, Write},
    fs::File,
    io::{self, BufReader, Read},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordSize {
    B32,
    B64,
}

impl Display for WordSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-bit",
            match self {
                WordSize::B32 => 32,
                WordSize::B64 => 64,
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    Relocatable,
    Executable,
    Shared,
    Core,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub enum Offset {
    B32(u32),
    B64(u64),
}

impl Offset {
    pub fn from_readable(reader: &mut impl Read, word_size: WordSize) -> io::Result<Self> {
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf {
    word_size: WordSize,
    endian: Endian,
    header_version: u8,
    os_abi: u8,
    elf_type: ElfType,
    architecture: Architecture,
    elf_version: u32,
    program_entry_offset: Offset,
    program_header_table_offset: Offset,
    section_header_table_offset: Offset,
    flags: Flags,
    elf_header_size: u16,
    program_header_table_entry_size: u16,
    program_header_table_entry_count: u16,
    section_header_table_entry_size: u16,
    section_header_table_entry_count: u16,
    section_header_string_table_index: u16,
}

fn read_bytes<const SIZE: usize>(reader: &mut impl Read) -> io::Result<[u8; SIZE]> {
    let mut result = [0; SIZE];
    reader.read_exact(&mut result)?;
    Ok(result)
}

fn read_byte(reader: &mut impl Read) -> io::Result<u8> {
    read_bytes::<1>(reader).map(|result| result[0])
}

fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    read_bytes::<2>(reader).map(u16::from_ne_bytes)
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    read_bytes::<4>(reader).map(u32::from_ne_bytes)
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    read_bytes::<8>(reader).map(u64::from_ne_bytes)
}

impl Elf {
    pub fn from_readable(reader: &mut impl Read) -> io::Result<Self> {
        assert_eq!(read_byte(reader)?, 0x7F);
        assert_eq!(read_bytes::<3>(reader)?.as_slice(), b"ELF");
        let word_size = match read_byte(reader)? {
            1 => WordSize::B32,
            2 => WordSize::B64,
            size => panic!("Invalid word size: {size}"),
        };
        let endian = match read_byte(reader)? {
            1 => Endian::Little,
            2 => Endian::Big,
            endian => panic!("Invalid endian byte: {endian}"),
        };
        let header_version = read_byte(reader)?;
        let os_abi = read_byte(reader)?;
        let _padding = read_bytes::<8>(reader)?;
        let elf_type = match read_u16(reader)? {
            1 => ElfType::Relocatable,
            2 => ElfType::Executable,
            3 => ElfType::Shared,
            4 => ElfType::Core,
            elf_type => panic!("Invalid elf type value: {elf_type}"),
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} ELF version {:?} file for {:?} endian {} {:?}",
            self.elf_type, self.elf_version, self.endian, self.word_size, self.architecture
        )
    }
}

fn main() {
    println!(
        "{}",
        Elf::from_readable(&mut BufReader::new(
            File::open(args().next().unwrap()).unwrap()
        ))
        .unwrap()
    );
}
