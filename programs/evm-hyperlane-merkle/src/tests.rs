use alloy_primitives::Address;
use alloy_sol_types::SolType;
use primitives::hyperlane::{ETHEREUM_MERKLE_HOOK_CONTRACT, Output, rootCall};
use sp1_cc_client_executor::io::EvmSketchInput;
use sp1_cc_host_executor::EvmSketch;
use url::Url;

use crate::circuit::verify_hyperlane_merkle_root;

async fn setup_hyperlane_merkle_circuit_input() -> (EvmSketchInput, u64) {
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
    let finalized_sketch = sketch.finalize().await.unwrap();

    (finalized_sketch, block_number)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires setting ETH_EXECUTION_RPC in .env"]
async fn valid_root_verification() {
    let (state_sketch, block_number) = setup_hyperlane_merkle_circuit_input().await;

    let output = verify_hyperlane_merkle_root(&state_sketch);

    assert_eq!(output.blockNumber, block_number);
}

// TODO: this test doesn't work with meaningful types for in- and outputs,
// but I think rather we should deploy a faulty contract or something instead.
//
// #[tokio::test(flavor = "multi_thread")]
// #[ignore = "requires setting ETH_EXECUTION_RPC in .env"]
// #[should_panic]
// async fn invalid_root_verification() {
//     let (mut state_sketch, _) = setup_hyperlane_merkle_circuit_input().await;
// 
//     // Corrupt some bytes in the inputs
//     input[25] ^= 0xAB;
//     input[50] ^= 0xFF;
//     input[100] ^= 0x12;
// 
//     verify_hyperlane_merkle_root(&state_sketch);
// }
