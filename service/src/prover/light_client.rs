use alloy::{providers::ProviderBuilder, sol};
use alloy_primitives::Address;
use helios_ethereum::rpc::ConsensusRpc;
use scripts::light_client::{get_client, get_updates};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin, network::NetworkMode};
use tracing::{info, instrument};

use primitives::{ETHEREUM_LIGHT_CLIENT_ELF, helios::Input};

sol! {
    #[sol(rpc)]
    interface IEthereumLightClient {
        function latestSlot() external view returns (uint256);
    }
}

#[instrument(skip(beacon_rpc))]
pub async fn prepare_input(
    beacon_rpc: &str,
    execution_rpc: &str,
    light_client_contract: &Address,
    chain_id: u64,
) -> Result<(Vec<u8>, u64), Box<dyn std::error::Error + Send + Sync>> {
    info!("Preparing light client input");

    // Get the latest available slot from the light client contract
    let provider = ProviderBuilder::new()
        .with_cached_nonce_management()
        .with_call_batching()
        .connect_http(execution_rpc.parse()?);

    let light_client = IEthereumLightClient::new(*light_client_contract, provider);
    let latest_contract_slot = light_client.latestSlot().call().await?;
    // Safe to unwrap as latest_contract_slot comes from on-chain uint256
    let latest_contract_slot: u64 = latest_contract_slot.try_into().unwrap();

    // Create client anchored at contract state
    let client = get_client(Some(latest_contract_slot), beacon_rpc, chain_id).await?;

    // Get latest finality update
    let finality_update = client.rpc.get_finality_update().await?;
    let target_slot = finality_update.finalized_header().beacon().slot;
    
    // Get the block number as well
    let block_number = *finality_update
        .finalized_header()
        .execution()
        .map_err(|_| "Finality update missing execution payload")?
        .block_number();

    // Validate there's progress to prove
    if target_slot <= latest_contract_slot {
        return Err(format!(
            "No progress to prove: target slot {} is not greater than latest contract slot {}",
            target_slot, latest_contract_slot
        )
        .into());
    }

    // Validate target slot is at checkpoint boundary
    if target_slot % 32 != 0 {
        return Err(format!(
            "Target slot {} is not a checkpoint slot (multiple of 32)",
            target_slot
        )
        .into());
    }

    let updates = get_updates(&client).await;

    let input = Input {
        updates,
        finality_update,
        expected_current_slot: client.expected_current_slot(),
        store: client.store.clone(),
        genesis_root: client.config.chain.genesis_root,
        forks: client.config.forks.clone(),
    };

    Ok((serde_cbor::to_vec(&input)?, block_number))
}

#[instrument(skip(input))]
pub async fn prove(input: Vec<u8>) -> Result<SP1ProofWithPublicValues, String> {
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
        Ok(proof)
    })
    .await
    .map_err(|e| e.to_string())?
}
