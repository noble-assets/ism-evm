#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolValue;
use sp1_cc_client_executor::io::EvmSketchInput;

mod circuit;

fn main() {
    let encoded_inputs = sp1_zkvm::io::read_vec();
    let state_sketch: EvmSketchInput = serde_cbor::from_slice(&encoded_inputs)
        .expect("failed to encode EVM state sketch inputs");

    let output_bytes = circuit::verify_hyperlane_merkle_root(&state_sketch)
        .abi_encode();

    sp1_zkvm::io::commit_slice(&output_bytes);
}
