use alloy_primitives::Address;
use alloy_sol_types::SolType;
use sp1_cc_host_executor::EvmSketch;
use url::Url;

use crate::circuit::{
    ETHEREUM_MERKLE_HOOK_CONTRACT, Output, rootCall, verify_hyperlane_merkle_root,
};

async fn setup_hyperlane_merkle_circuit_input() -> (Vec<u8>, u64) {
    dotenvy::dotenv().ok();

    let rpc_url =
        std::env::var("ETH_EXECUTION_RPC").expect("ETH_EXECUTION_RPC must be set in .env");

    let sketch = EvmSketch::builder()
        .el_rpc_url(Url::parse(&rpc_url).unwrap())
        .build()
        .await
        .unwrap();

    let block_number: u64 = sketch.anchor.resolve().id.try_into().unwrap();

    sketch
        .call(ETHEREUM_MERKLE_HOOK_CONTRACT, Address::default(), rootCall)
        .await
        .unwrap();
    let input = sketch.finalize().await.unwrap();
    let encoded_inputs = serde_cbor::to_vec(&input).unwrap();

    (encoded_inputs, block_number)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires setting ETH_EXECUTION_RPC in .env"]
async fn valid_root_verification() {
    let (input, block_number) = setup_hyperlane_merkle_circuit_input().await;

    let output = verify_hyperlane_merkle_root(input);

    let decoded_output = Output::abi_decode_validate(&output).unwrap();

    assert_eq!(decoded_output.blockNumber, block_number);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires setting ETH_EXECUTION_RPC in .env"]
#[should_panic]
async fn invalid_root_verification() {
    let (mut input, _) = setup_hyperlane_merkle_circuit_input().await;

    // Corrupt some bytes in the inputs
    input[25] ^= 0xAB;
    input[50] ^= 0xFF;
    input[100] ^= 0x12;

    verify_hyperlane_merkle_root(input);
}
