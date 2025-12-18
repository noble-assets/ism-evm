#![no_main]
sp1_zkvm::entrypoint!(main);

mod circuit;

fn main() {
    let encoded_inputs = sp1_zkvm::io::read_vec();

    let output = circuit::verify_light_client_update(encoded_inputs);

    sp1_zkvm::io::commit_slice(&output);
}
