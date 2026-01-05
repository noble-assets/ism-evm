use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, network::NetworkMode};
use tracing::{info, instrument};

use primitives::HYPERLANE_MERKLE_ELF;

#[instrument(skip(execution_rpc))]
pub async fn prepare_input(
    block_number: u64,
    execution_rpc: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    info!("Preparing merkle input");

    // Your existing input preparation logic
    todo!()
}

#[instrument(skip(input))]
pub async fn prove(input: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    tokio::task::spawn_blocking(move || {
        info!("Starting merkle proof");

        let prover_client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .build();

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input);

        let (pk, vk) = prover_client.setup(HYPERLANE_MERKLE_ELF);
        info!(vk = %vk.bytes32(), "Verification key");

        let proof = prover_client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .map_err(|e| e.to_string())?;

        prover_client
            .verify(&proof, &vk)
            .map_err(|e| e.to_string())?;

        info!("Merkle proof complete");
        Ok((proof.bytes().to_vec(), proof.public_values.to_vec()))
    })
    .await
    .map_err(|e| e.to_string())?
}
