use alloy_primitives::{Address, B256};
use alloy_sol_types::SolValue;
use primitives::hyperlane::{
    ETHEREUM_MERKLE_HOOK_CONTRACT, Output, SEPOLIA_MERKLE_HOOK_CONTRACT, rootCall
};
use sp1_cc_client_executor::{ClientExecutor, ContractInput, Genesis, io::EvmSketchInput};

pub fn verify_hyperlane_merkle_root(encoded_inputs: Vec<u8>) -> Vec<u8> {
    // Decode the inputs
    let state_sketch: EvmSketchInput = serde_cbor::from_slice(&encoded_inputs).unwrap();

    let hook_contract = match state_sketch.genesis {
        Genesis::Mainnet => ETHEREUM_MERKLE_HOOK_CONTRACT,
        Genesis::Sepolia => SEPOLIA_MERKLE_HOOK_CONTRACT,
        _ => unimplemented!(),
    };

    // Initialize the client executor with the state sketch.
    // This step also validates all of the storage against the provided state root.
    let executor = ClientExecutor::eth(&state_sketch).unwrap();

    let call = ContractInput::new_call(hook_contract, Address::default(), rootCall);
    // Execute the root call using the client executor
    let result = executor.execute(call).unwrap();

    // Decode the bytes32 root from contractOutput (it's ABI-encoded)
    let root = B256::abi_decode_validate(&result.contractOutput).unwrap();

    Output {
        root,
        stateRoot: state_sketch.anchor.header().state_root,
        blockNumber: state_sketch.anchor.header().number,
    }
    .abi_encode()
}
