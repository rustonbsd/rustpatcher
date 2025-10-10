use anyhow::{anyhow, Result};
use goblin::mach::{Mach, MachO};

pub fn exclude_code_signature(data: &[u8]) -> Result<Vec<u8>> {
    let mach = Mach::parse(data)?;

    match mach {
        Mach::Binary(macho) => exclude_from_macho(data, &macho),
        Mach::Fat(_) => Err(anyhow!("Fat/Universal binaries not supported")),
    }
}

fn exclude_from_macho(data: &[u8], macho: &MachO) -> Result<Vec<u8>> {
    for lc in &macho.load_commands {
        if let goblin::mach::load_command::CommandVariant::CodeSignature(cmd) = lc.command {
            let offset = cmd.dataoff as usize;

            if offset > data.len() {
                return Err(anyhow!(
                    "Code signature offset out of bounds: offset={}, file_len={}",
                    offset, data.len()
                ));
            }

            // Cut the binary at the signature offset
            // this makes the hash independent of signature size changes
            // (resigning leeds to a new signature of a different size)
            return Ok(data[..offset].to_vec());
        }
    }

    // No code signature found, return original
    Ok(data.to_vec())
}