use helios_consensus_core::types::bls::Signature;
use helios_ethereum::rpc::ConsensusRpc;
use primitives::helios::Input;
use scripts::{
    ETHEREUM_MAINNET_CHAIN_ID,
    light_client::{get_client, get_updates},
};

use crate::circuit;

async fn setup_light_client_circuit_inputs(valid_checkpoint: bool) -> Input {
    dotenvy::dotenv().ok();

    let rpc_url = std::env::var("ETH_BEACON_RPC")
        .expect("ETH_BEACON_RPC must be set in .env to run this test");

    let client = get_client(None, &rpc_url, ETHEREUM_MAINNET_CHAIN_ID)
        .await
        .expect("Failed to create client");

    let current_finalized_slot = client.store.finalized_header.beacon().slot;
    assert!(
        current_finalized_slot % 32 == 0,
        "Finalized slot must be at epoch boundary"
    );

    let previous_finalized_slot = if valid_checkpoint {
        current_finalized_slot - 32 // Go back 1 epoch
    } else {
        current_finalized_slot - 20 // Invalid: Not at checkpoint
    };

    let client = get_client(
        Some(previous_finalized_slot),
        &rpc_url,
        ETHEREUM_MAINNET_CHAIN_ID,
    )
    .await
    .expect("Failed to create client at previous slot");

    let updates = get_updates(&client).await;
    let finality_update = client.rpc.get_finality_update().await.unwrap();
    let latest_block = finality_update.finalized_header().beacon().slot;
    let expected_current_slot = client.expected_current_slot();

    assert!(
        latest_block.is_multiple_of(32),
        "Latest block must be at epoch boundary"
    );

    Input {
        updates,
        finality_update,
        expected_current_slot,
        store: client.store.clone(),
        genesis_root: client.config.chain.genesis_root,
        forks: client.config.forks.clone(),
    }
}

#[tokio::test]
#[ignore = "requires setting ETH_BEACON_RPC in .env"]
async fn valid_light_client_update() {
    let input = setup_light_client_circuit_inputs(true).await;

    let encoded_circuit_input = serde_cbor::to_vec(&input).unwrap();

    circuit::verify_light_client_update(encoded_circuit_input);
}

#[tokio::test]
#[ignore = "requires setting ETH_BEACON_RPC in .env"]
#[should_panic(expected = "block is not a finalized checkpoint")]
async fn invalid_light_client_update_not_checkpoint() {
    let input = setup_light_client_circuit_inputs(false).await;

    let encoded_circuit_input = serde_cbor::to_vec(&input).unwrap();

    circuit::verify_light_client_update(encoded_circuit_input);
}

#[tokio::test]
#[ignore = "requires setting ETH_BEACON_RPC in .env"]
#[should_panic(expected = "Finality update failed to verify.: invalid timestamp")]
async fn invalid_light_client_update_wrong_input_slot() {
    let mut input = setup_light_client_circuit_inputs(true).await;

    // Set expected slot to be before signature slot
    input.expected_current_slot -= 1;

    let encoded_circuit_input = serde_cbor::to_vec(&input).unwrap();

    circuit::verify_light_client_update(encoded_circuit_input);
}

#[tokio::test]
#[ignore = "requires setting ETH_BEACON_RPC in .env"]
#[should_panic(expected = "Update is invalid!: invalid sync committee signature")]
async fn invalid_light_client_update_tampered_signature() {
    let mut input = setup_light_client_circuit_inputs(true).await;

    // Tamper with the update signature
    let signature = input.updates[0].sync_aggregate_mut();
    signature.sync_committee_signature = Signature::default();

    let encoded_circuit_input = serde_cbor::to_vec(&input).unwrap();
    circuit::verify_light_client_update(encoded_circuit_input);
}

#[tokio::test]
#[ignore = "requires setting ETH_BEACON_RPC in .env"]
#[should_panic(expected = "Update is invalid!: invalid finality proof")]
async fn invalid_light_client_update_tampered_header() {
    let mut input = setup_light_client_circuit_inputs(true).await;

    // Tamper with the state root of the attested header
    let header = input.updates[0].attested_header_mut();
    header.beacon_mut().state_root = [0u8; 32].into();

    let encoded_circuit_input = serde_cbor::to_vec(&input).unwrap();
    circuit::verify_light_client_update(encoded_circuit_input);
}
