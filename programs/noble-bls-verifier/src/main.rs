#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm;

use alloy_sol_types::SolValue;
use crate::circuit::BLSVerifierInputs;

mod circuit;

fn main() {
    let encoded_inputs = sp1_zkvm::io::read_vec();
    let circuit_inputs: BLSVerifierInputs = serde_cbor::from_slice(&encoded_inputs)
        .expect("failed to unmarshal proof inputs");

    let outputs = circuit::prove(&circuit_inputs)
        .expect("failed to prove");

    sp1_zkvm::io::commit_slice(
        &outputs
            .abi_encode()
    );
}
