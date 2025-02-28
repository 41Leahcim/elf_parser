use std::{env::args, fs::File, io::BufReader, time::Instant};

use elf_parser::Elf;

fn main() {
    let start = Instant::now();
    let elf = Elf::from_readable(&mut BufReader::new(
        File::open(args().nth(1).expect("Expected an ELF file as argument"))
            .expect("Passed argument is not a file"),
    ))
    .expect("Parsed argument is not a valid ELF file");
    let performance = start.elapsed();
    println!("{elf:?}\n{elf}",);
    println!("{performance:?}");
}
