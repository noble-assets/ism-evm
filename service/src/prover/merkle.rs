use alloy::transports::http::reqwest::Url;
use alloy_primitives::Address;
use sp1_cc_client_executor::io::EvmSketchInput;
use sp1_cc_host_executor::{EvmSketch, Genesis};
use sp1_sdk::{Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin, network::NetworkMode};
use tracing::{info, instrument};

use primitives::{
    HYPERLANE_MERKLE_ELF,
    hyperlane::{
        ETHEREUM_MERKLE_HOOK_CONTRACT, NOBLE_DEVNET_CHAIN_ID, NOBLE_DEVNET_MERKLE_HOOK_CONTRACT,
        SEPOLIA_MERKLE_HOOK_CONTRACT, rootCall,
    },
};

#[instrument(skip(execution_rpc))]
pub async fn prepare_input(
    chain_id: u64,
    block_number: u64,
    execution_rpc: &str,
) -> Result<EvmSketchInput, Box<dyn std::error::Error + Send + Sync>> {
    info!("Preparing merkle input");
    let mut sketch = EvmSketch::builder()
        .at_block(block_number)
        .el_rpc_url(Url::parse(execution_rpc).unwrap());

    let hook_contract = match chain_id {
        1 => ETHEREUM_MERKLE_HOOK_CONTRACT,
        11155111 => {
            sketch = sketch.with_genesis(Genesis::Sepolia);
            SEPOLIA_MERKLE_HOOK_CONTRACT
        }
        NOBLE_DEVNET_CHAIN_ID => NOBLE_DEVNET_MERKLE_HOOK_CONTRACT,
        _ => {
            return Err(format!(
                "Unsupported chain ID {} for Hyperlane Merkle Hook contract",
                chain_id
            )
            .into());
        }
    };

    let sketch = sketch.build().await?;

    sketch
        .call(hook_contract, Address::default(), rootCall)
        .await?;

    Ok(sketch.finalize().await?)
}

#[instrument(skip(state_sketch))]
pub async fn prove(state_sketch: EvmSketchInput) -> Result<SP1ProofWithPublicValues, String> {
    tokio::task::spawn_blocking(move || {
        info!("Starting merkle proof");

        let prover_client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .build();

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(
            serde_cbor::to_vec(&state_sketch)
                .map_err(|e| e.to_string())?
        );

        let (pk, _) = prover_client.setup(HYPERLANE_MERKLE_ELF);

        let proof = prover_client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .map_err(|e| e.to_string())?;

        info!("Merkle proof complete");
        Ok(proof)
    })
    .await
    .map_err(|e| e.to_string())?
}
