pub mod helios;

pub const ETHEREUM_LIGHT_CLIENT_ELF: &[u8] =
    include_bytes!("../../programs/helios/elf/helios-program");
pub const HYPERLANE_MERKLE_ELF: &[u8] =
    include_bytes!("../../programs/evm-hyperlane-merkle/elf/evm-hyperlane-merkle-program");
