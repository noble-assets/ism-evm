use std::fs::OpenOptions;
use std::io::Write;

use primitives::{ETHEREUM_LIGHT_CLIENT_ELF, HYPERLANE_MERKLE_ELF};
use scripts::light_client::get_client;
use sp1_sdk::{HashableKey, Prover, ProverClient};
use tree_hash::TreeHash;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(".env")
        .expect("Failed to open .env");

    // --- Verification Keys ---
    println!("Generating verification keys...");
    let prover = ProverClient::builder().cpu().build();

    let (_, eth_vk) = prover.setup(ETHEREUM_LIGHT_CLIENT_ELF);
    let (_, hyp_vk) = prover.setup(HYPERLANE_MERKLE_ELF);

    writeln!(file, "ETHEREUM_LIGHT_CLIENT_VK={}", eth_vk.bytes32())?;
    writeln!(file, "HYPERLANE_MERKLE_VK={}", hyp_vk.bytes32())?;
    println!("✓ VKs appended to .env");

    // --- Beacon Chain Checkpoint ---
    let rpc_url = std::env::var("ETH_BEACON_RPC").expect("ETH_BEACON_RPC must be set");
    let chain_id: u64 = std::env::var("SOURCE_CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Invalid SOURCE_CHAIN_ID");

    println!("Fetching finalized checkpoint from beacon chain...");
    let client = get_client(None, &rpc_url, chain_id).await?;

    let header = &client.store.finalized_header;
    let beacon = header.beacon();
    let execution = header
        .execution()
        .expect("Finalized header missing execution payload");

    let slot = beacon.slot;
    let header_hash = beacon.tree_hash_root();
    let state_root = execution.state_root();
    let block_number = execution.block_number();
    let sync_committee_hash = client.store.current_sync_committee.tree_hash_root();

    writeln!(file, "INITIAL_SLOT={}", slot)?;
    writeln!(file, "INITIAL_HEADER=0x{}", hex::encode(header_hash))?;
    writeln!(file, "INITIAL_STATE_ROOT=0x{}", hex::encode(state_root))?;
    writeln!(file, "INITIAL_BLOCK_NUMBER={}", block_number)?;
    writeln!(
        file,
        "INITIAL_SYNC_COMMITTEE=0x{}",
        hex::encode(sync_committee_hash)
    )?;

    println!(
        "✓ Checkpoint appended to .env (slot {} | epoch {} | period {})",
        slot,
        slot / 32,
        slot / 8192
    );

    Ok(())
}
