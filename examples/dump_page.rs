//! Dumps one guest physical page of a running VirtualBox VM to a file.
//! Usage: dump_page <vm name> <guest physical address, hex with 0x or decimal> <output file>

use std::error::Error;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(format!("usage: {} <vm name> <paddr> <output file>", args[0]).into());
    }
    let paddr = match args[2].strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16)?,
        None => args[2].parse()?,
    };
    let vm = vboxapi::Vm::attach(&args[1])?;
    let mut page = vec![0u8; 4096];
    vm.read_physical(paddr, &mut page)?;
    std::fs::write(&args[3], &page)?;
    println!("dumped page {:#x} to {}", paddr, args[3]);
    Ok(())
}
