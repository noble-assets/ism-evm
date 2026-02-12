use std::time::Instant;

use alloy_primitives::Address;
use alloy_sol_types::SolType;
use clap::Parser;
use primitives::{
    HYPERLANE_MERKLE_ELF,
    hyperlane::{ETHEREUM_MERKLE_HOOK_CONTRACT, NOBLE_DEVNET_MERKLE_HOOK_CONTRACT, rootCall},
};
use sp1_cc_client_executor::io::EvmSketchInput;
use sp1_cc_host_executor::EvmSketch;
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin, network::NetworkMode};
use tracing::{debug, info};
use tracing_subscriber;
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "hyperlane-merkle-prover")]
#[command(about = "Generate ZK proofs for Hyperlane merkle root verification", long_about = None)]
struct Args {
    /// Block number to prove at (defaults to latest)
    #[arg(long, value_name = "BLOCK")]
    block: Option<u64>,

    /// Merkle hook contract address (defaults to mainnet contract)
    #[arg(long, value_name = "ADDRESS")]
    contract: Option<String>,

    /// Output path for the proof file
    #[arg(long, default_value = "hyperlane_proof.bin")]
    output_path: String,
}

struct ProverConfig {
    /// Resolved address for the Hyperlane Merkle Hook contract
    /// based on the provided CLI arguments.
    merkle_hook_contract: Address,

    /// URL of the execution layer RPC.
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let args = Args::parse();
    let prover_config = get_prover_config(&args)?;

    let state_sketch = build_evm_sketch(
        prover_config.merkle_hook_contract,
        prover_config.rpc_url,
        args.block
    )?;

    let proof = generate_proof(state_sketch)?;
    
    // Decode and display output
    let output =
        primitives::hyperlane::Output::abi_decode_validate(proof.public_values.as_slice())?;

    info!("=== Proof Output ===");
    info!("Block number: {}", output.blockNumber);
    info!("Merkle root: 0x{}", hex::encode(output.root));
    info!("Proof: 0x{}", hex::encode(proof.bytes()));
    info!(
        "Public values: 0x{}",
        hex::encode(proof.public_values.as_slice())
    );

    // Save proof to file
    info!("Saving proof to {}...", args.output_path);
    proof.save(&args.output_path)?;
    info!("✓ Proof saved successfully");

    Ok(())
}

async fn build_evm_sketch(
    contract: Address,
    rpc_url: Url,
    block: Option<u64>,
) -> Result<EvmSketchInput, Box<dyn std::error::Error>> {
    let mut sketch = EvmSketch::builder().el_rpc_url(rpc_url);

    // Set block if provided
    if let Some(block) = block {
        sketch = sketch.at_block(block);
    };

    let sketch = sketch.build().await?;

    info!("using block number: {}", sketch.anchor.resolve().id);

    sketch.call(contract, Address::default(), rootCall).await?;

    Ok(sketch.finalize().await?)
}

/// Retrieves the prover configuration based on the provided input arguments
/// as well as the environment variables.
///
/// TODO: rather store as e.g. YAML instead of parsing RPC and contract address?
fn get_prover_config(args: &Args) -> Result<ProverConfig, Box<dyn std::error::Error>> {
    let merkle_hook_contract = match args.contract {
        Some(addr) => {
            if addr == "noble".to_string() {
                NOBLE_DEVNET_MERKLE_HOOK_CONTRACT
            } else {
                addr.parse::<Address>()?
            }
        }
        None => ETHEREUM_MERKLE_HOOK_CONTRACT,
    };

    let rpc_url = Url::parse(
        &std::env::var("ETH_EXECUTION_RPC").expect("ETH_EXECUTION_RPC must be set in .env"),
    )?;

    info!("contract: {}", merkle_hook_contract);
    info!("rpc url: {}", rpc_url);

    Ok(ProverConfig {
        merkle_hook_contract,
        rpc_url,
    })
}

async fn generate_proof(state_sketch: &EvmSketchInput) -> Result<SP1ProofWithPublicValues, Box<dyn std::error::Error>> {
    let encoded_input = serde_cbor::to_vec(&state_sketch)?;

    debug!("setting up prover...");
    let prover_client = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .build();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encoded_input);

    let (pk, vk) = prover_client.setup(HYPERLANE_MERKLE_ELF);

    info!("Verification key: {}", vk.bytes32());

    // Generate proof
    debug!("Generating proof...");
    let prove_start = Instant::now();

    let proof = prover_client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Proving failed");

    let prove_duration = prove_start.elapsed();
    info!(
        "✓ Proof generated successfully in {:.2?} seconds",
        prove_duration.as_secs_f64()
    );

    // Verify proof
    debug!("verifying proof...");
    prover_client.verify(&proof, &vk)?;
    info!("✓ Proof verified successfully");

    Ok(proof)
}