use clap::Parser as _;
use elf_parser::Elf;
use std::{fs::File, io::BufReader, path::PathBuf, time::Instant};

/// This application Parses the ELF file passed as argument.
#[derive(Debug, clap::Parser)]
struct Args {
    /// The ELF file to parse
    file: PathBuf,
}

fn main() {
    let args = Args::parse();
    let start = Instant::now();
    let elf = Elf::from_readable(&mut BufReader::new(
        File::open(args.file).expect("Passed argument is not a file"),
    ))
    .expect("Parsed argument is not a valid ELF file");
    let performance = start.elapsed();
    println!("{elf:?}\n{elf}",);
    println!("{performance:?}");
}
