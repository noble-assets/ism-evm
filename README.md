# Noble ISM

## Requirements

- [Rust](https://rust-lang.org/tools/install/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install#option-1-prebuilt-binaries-recommended)

## Compilation

Programs will be deterministically compiled and placed in the `/elf` directory in each of the programs subfolder. This is done in the `build.rs` inside `scripts`

## Programs

### Helios

This program generates zero-knowledge proofs for Ethereum beacon chain light client updates using the Helios consensus library.

What it does:

1. Verifies sync committee updates - Processes any pending sync committee rotation updates, ensuring valid BLS signature verification and proper committee transitions across sync periods.

2. Applies finality updates - Verifies and applies finality proofs to advance the light client's finalized head, confirming the beacon chain has reached consensus on new blocks.

3. Extracts execution layer state - Retrieves the execution state root and block number from the finalized beacon block's execution payload.

## Proving scripts

To run the proving scripts make sure to add the `ETH_BEACON_RPC`, `ETH_EXECUTION_RPC` and `NETWORK_PRIVATE_KEY` to an .env file in the project root like the `.env.example` provided. The `NETWORK_PRIVATE_KEY` needs to be [funded](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart) with enough `PROVE` tokens on Ethereum Mainnet to pay for the Succint Prover Network proofs. Check

### Ethereum prover

Generates a ZK proof of Ethereum consensus from a starting slot to the current finalized slot. The starting slot must be a checkpoint (multiple of 32). Defaults to the previous checkpoint slot.

```bash
cargo run --release --bin ethereum-prover
cargo run --release --bin ethereum-prover -- --from-slot <SLOT>
```

To get the current finalized slot:

```bash
curl -s "<ETH_BEACON_RPC>/eth/v1/beacon/headers/head" | jq -r '.data.header.message.slot'
```

### EVM Hyperlane merkle root prover

Generate a proof for a Hyperlane Merkle tree root. The specified hook contract must match one supported by the circuit. Defaults to Ethereum Mainnet hook at the latest block.

```bash
cargo run --release --bin evm-hyperlane-prover
cargo run --release --bin evm-hyperlane-prover -- --block <BLOCK_NUMBER> --contract <HOOK_CONTRACT_ADDRESS>
```
