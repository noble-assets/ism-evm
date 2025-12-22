use std::time::Instant;

use clap::Parser;
use helios_ethereum::rpc::ConsensusRpc;
use primitives::helios::Input;

use scripts::light_client::{get_client, get_updates};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, include_elf, network::NetworkMode};
use tree_hash::TreeHash;

const ETHEREUM_LIGHT_CLIENT_ELF: &[u8] = include_elf!("helios-program");

#[derive(Parser, Debug)]
#[command(name = "ethereum-prover")]
#[command(about = "Generate ZK proofs for Ethereum light client verification", long_about = None)]
struct Args {
    /// Starting slot (checkpoint slot, must be multiple of 32)
    /// If not specified, defaults to current finalized slot - 32
    #[arg(long, value_name = "SLOT")]
    from_slot: Option<u64>,

    /// Output path for the proof file
    #[arg(long, default_value = "proof.bin")]
    output: String,

    /// Chain ID (1 for mainnet, 11155111 for sepolia)
    #[arg(long, default_value = "1")]
    chain_id: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let args = Args::parse();

    let rpc_url = std::env::var("ETH_BEACON_RPC").expect("ETH_BEACON_RPC must be set in .env");

    println!("Connecting to beacon chain RPC...");

    // First, get the current finalized state to determine the target slot
    let current_client = get_client(None, &rpc_url, args.chain_id)
        .await
        .expect("Failed to create client for current state");

    let current_finalized_slot = current_client.store.finalized_header.beacon().slot;

    // Validate current finalized slot is at checkpoint boundary
    if current_finalized_slot % 32 != 0 {
        eprintln!(
            "Error: Current finalized slot ({}) is not a checkpoint slot",
            current_finalized_slot
        );
        std::process::exit(1);
    }

    // Determine starting slot
    let from_slot = match args.from_slot {
        Some(slot) => {
            if slot % 32 != 0 {
                eprintln!(
                    "Error: from-slot ({}) must be a checkpoint slot (multiple of 32)",
                    slot
                );
                std::process::exit(1);
            }
            slot
        }
        None => {
            let default_slot = current_finalized_slot - 32;
            println!(
                "No from-slot specified, using previous epoch checkpoint: {}",
                default_slot
            );
            default_slot
        }
    };

    // Validate slot ordering
    if from_slot >= current_finalized_slot {
        eprintln!(
            "Error: from-slot ({}) must be less than current finalized slot ({})",
            from_slot, current_finalized_slot
        );
        std::process::exit(1);
    }

    println!("=== Ethereum Light Client Prover ===");
    println!("Chain ID: {}", args.chain_id);
    println!("From slot: {} (epoch {})", from_slot, from_slot / 32);
    println!(
        "To slot: {} (epoch {})",
        current_finalized_slot,
        current_finalized_slot / 32
    );

    // Create client starting from the specified slot
    println!("Syncing light client from slot {}...", from_slot);
    let client = get_client(Some(from_slot), &rpc_url, args.chain_id)
        .await
        .expect("Failed to create client at starting slot");

    // Get sync committee updates needed to bridge from from_slot to current
    let updates = get_updates(&client).await;
    println!("Fetched {} sync committee updates", updates.len());

    // Get the finality update for the current finalized header
    let finality_update = client.rpc.get_finality_update().await?;

    let target_slot = finality_update.finalized_header().beacon().slot;
    if target_slot % 32 != 0 {
        eprintln!(
            "Error: Target finalized slot {} is not a checkpoint slot",
            target_slot
        );
        std::process::exit(1);
    }

    // Extract values for logging
    let prev_header = client.store.finalized_header.beacon().tree_hash_root();
    let prev_sync_committee_hash = client.store.current_sync_committee.tree_hash_root();
    let prev_execution_block_number = client
        .store
        .finalized_header
        .execution()
        .expect("Finalized header missing execution payload")
        .block_number();
    let prev_execution_state_root = client
        .store
        .finalized_header
        .execution()
        .expect("Finalized header missing execution payload")
        .state_root();

    let target_header = finality_update.finalized_header().beacon().tree_hash_root();
    let sync_committee_hash = current_client.store.current_sync_committee.tree_hash_root();
    let next_sync_committee_hash = updates
        .last()
        .map(|u| u.next_sync_committee().tree_hash_root())
        .unwrap_or_default();
    let execution_payload = finality_update
        .finalized_header()
        .execution()
        .expect("Finality update missing execution payload");
    let execution_state_root = execution_payload.state_root();
    let execution_block_number = execution_payload.block_number();

    println!("=== Previous State (from_slot: {}) ===", from_slot);
    println!("Header hash: 0x{}", hex::encode(prev_header));
    println!(
        "Execution state root: 0x{}",
        hex::encode(prev_execution_state_root)
    );
    println!("Execution block number: {}", prev_execution_block_number);
    println!(
        "Sync committee hash: 0x{}",
        hex::encode(prev_sync_committee_hash)
    );
    println!("Sync committee period: {}", from_slot / 8192);

    println!("=== Target State (to_slot: {}) ===", target_slot);
    println!("Header hash: 0x{}", hex::encode(target_header));
    println!(
        "Execution state root: 0x{}",
        hex::encode(execution_state_root)
    );
    println!("Execution block number: {}", execution_block_number);
    println!(
        "Sync committee hash: 0x{}",
        hex::encode(sync_committee_hash)
    );
    println!("Sync committee period: {}", target_slot / 8192);
    println!(
        "Next sync committee hash: 0x{}",
        hex::encode(next_sync_committee_hash)
    );

    // Prepare circuit input
    let input = Input {
        updates,
        finality_update,
        expected_current_slot: client.expected_current_slot(),
        store: client.store.clone(),
        genesis_root: client.config.chain.genesis_root,
        forks: client.config.forks.clone(),
    };

    let encoded_input = serde_cbor::to_vec(&input)?;

    // Setup prover
    println!("Setting up prover...");
    let prover_client = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .build();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encoded_input);

    let (pk, vk) = prover_client.setup(ETHEREUM_LIGHT_CLIENT_ELF);

    println!("Verification key: {}", vk.bytes32());

    // Generate proof
    println!("Generating proof (this may take a while)...");
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

    // Output proof data
    println!("=== Proof Output ===");
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
