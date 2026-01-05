use alloy_primitives::Address;
use scripts::light_client::{self, get_client};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, network::NetworkMode};
use tonic::Status;
use tracing::{error, info, instrument};

use primitives::ETHEREUM_LIGHT_CLIENT_ELF;

#[instrument(skip(beacon_rpc))]
pub async fn prepare_input(
    slot: u64,
    beacon_rpc: &str,
    execution_rpc: &str,
    light_client_contract: &Address,
    chain_id: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    info!("Preparing light client input");

    // Your existing input preparation logic
    todo!()
}

#[instrument(skip(input))]
pub async fn prove(input: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    tokio::task::spawn_blocking(move || {
        info!("Starting light client proof");

        let prover_client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .build();

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input);

        let (pk, vk) = prover_client.setup(ETHEREUM_LIGHT_CLIENT_ELF);
        info!(vk = %vk.bytes32(), "Verification key");

        let proof = prover_client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .map_err(|e| e.to_string())?;

        prover_client
            .verify(&proof, &vk)
            .map_err(|e| e.to_string())?;

        info!("Light client proof complete");
        Ok((proof.bytes().to_vec(), proof.public_values.to_vec()))
    })
    .await
    .map_err(|e| e.to_string())?
}
