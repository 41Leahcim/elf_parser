use std::{env::args, fs::File, io::BufReader};

use elf_parser::Elf;

#[expect(clippy::unwrap_used)]
fn main() {
    let elf = Elf::from_readable(&mut BufReader::new(
        File::open(args().next().unwrap()).unwrap(),
    ))
    .unwrap();
    println!("{elf:?}\n{elf}",);
}
