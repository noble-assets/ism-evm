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
