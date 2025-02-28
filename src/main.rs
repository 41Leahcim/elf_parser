use std::{env::args, fs::File, io::BufReader, time::Instant};

use elf_parser::Elf;

#[expect(clippy::unwrap_used)]
fn main() {
    let start = Instant::now();
    let elf = Elf::from_readable(&mut BufReader::new(
        File::open(args().next().unwrap()).unwrap(),
    ))
    .unwrap();
    let performance = start.elapsed();
    println!("{elf:?}\n{elf}",);
    println!("{performance:?}");
}
