use std::time::Instant;

use alloy_primitives::Address;
use alloy_sol_types::SolType;
use clap::Parser;
use evm_hyperlane_merkle_program::circuit::{ETHEREUM_MERKLE_HOOK_CONTRACT, Output, rootCall};
use primitives::HYPERLANE_MERKLE_ELF;
use sp1_cc_host_executor::EvmSketch;
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, network::NetworkMode};
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
    output: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let args = Args::parse();

    // Parse contract address or use default
    let contract = match &args.contract {
        Some(addr) => addr.parse::<Address>()?,
        None => ETHEREUM_MERKLE_HOOK_CONTRACT,
    };

    let rpc_url =
        std::env::var("ETH_EXECUTION_RPC").expect("ETH_EXECUTION_RPC must be set in .env");

    let mut sketch = EvmSketch::builder().el_rpc_url(Url::parse(&rpc_url).unwrap());

    // Set block if provided
    if let Some(block) = args.block {
        sketch = sketch.at_block(block);
    };
    let sketch = sketch.build().await?;
    let block_number: u64 = sketch.anchor.resolve().id.try_into()?;

    sketch.call(contract, Address::default(), rootCall).await?;
    let input = sketch.finalize().await?;
    let encoded_input = serde_cbor::to_vec(&input)?;

    println!("=== Hyperlane Merkle Root Prover ===");
    println!("Contract: {}", contract);
    println!("Block number: {}", block_number);

    // Setup prover
    println!("Setting up prover...");
    let prover_client = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .build();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encoded_input);

    let (pk, vk) = prover_client.setup(HYPERLANE_MERKLE_ELF);

    println!("Verification key: {}", vk.bytes32());

    // Generate proof
    println!("Generating proof...");
    let prove_start = Instant::now();

    let proof = prover_client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Proving failed");

    let prove_duration = prove_start.elapsed();
    println!(
        "✓ Proof generated successfully in {:.2?} seconds",
        prove_duration.as_secs_f64()
    );

    // Verify proof
    println!("Verifying proof...");
    prover_client.verify(&proof, &vk)?;
    println!("✓ Proof verified successfully");

    // Decode and display output
    let output = Output::abi_decode_validate(proof.public_values.as_slice())?;

    println!("=== Proof Output ===");
    println!("Block number: {}", output.blockNumber);
    println!("Merkle root: 0x{}", hex::encode(output.root));
    println!("Proof: 0x{}", hex::encode(proof.bytes()));
    println!(
        "Public values: 0x{}",
        hex::encode(proof.public_values.as_slice())
    );

    // Save proof to file
    println!("Saving proof to {}...", args.output);
    proof.save(&args.output)?;
    println!("✓ Proof saved successfully");

    Ok(())
}
