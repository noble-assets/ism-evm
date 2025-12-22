use alloy_primitives::{B256, U256};
use alloy_sol_types::{SolValue, sol};
use helios_consensus_core::{
    apply_finality_update, apply_update, verify_finality_update, verify_update,
};
use primitives::helios::Input;
use tree_hash::TreeHash;

sol! {
    struct Output {
        /// The slot of the previous head.
        uint256 prevHead;
        /// The previous beacon block header hash.
        bytes32 prevHeader;
        /// The anchor sync committee hash which was used to verify the proof.
        bytes32 prevSyncCommitteeHash;
        /// The slot of the new head.
        uint256 newHead;
        /// The new beacon block header hash.
        bytes32 newHeader;
        /// The sync committee hash of the current period.
        bytes32 syncCommitteeHash;
        /// The sync committee hash of the next period.
        bytes32 nextSyncCommitteeHash;
        /// The execution state root from the execution payload of the new beacon block.
        bytes32 executionStateRoot;
        /// The execution block number.
        uint256 executionBlockNumber;

    }
}

/// Program flow:
/// 1. Apply sync committee updates, if any
/// 2. Apply finality update
/// 3. Verify execution state root proof
/// 4. Assert all updates are valid
/// 5. Commit new state root, header, and sync committees for usage in the on-chain contract
pub fn verify_light_client_update(encoded_inputs: Vec<u8>) -> Vec<u8> {
    // Decode the inputs
    let Input {
        updates,
        finality_update,
        expected_current_slot,
        mut store,
        genesis_root,
        forks,
    } = serde_cbor::from_slice(&encoded_inputs).unwrap();

    // Get the initial sync committee hash.
    let prev_sync_committee_hash = store.current_sync_committee.tree_hash_root();

    let prev_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let prev_head = store.finalized_header.beacon().slot;

    // 1. Verify and apply all generic updates
    for update in updates.iter() {
        verify_update(update, expected_current_slot, &store, genesis_root, &forks)
            .expect("Update is invalid!");
        apply_update(&mut store, update);
    }

    // 2. Verify and apply finality update
    verify_finality_update(
        &finality_update,
        expected_current_slot,
        &store,
        genesis_root,
        &forks,
    )
    .expect("Finality update failed to verify.");
    apply_finality_update(&mut store, &finality_update);

    // Ensure the new head is greater than the previous head. This guarantees that the finality
    // update was correctly applied.
    assert!(
        store.finalized_header.beacon().slot > prev_head,
        "New head is not greater than previous head."
    );
    // Ensure that the we used a checkpoint slot for the new finalized header.
    // This is required because CL nodes prune non-checkpoint slots,
    // and if the new head is not a checkpoint slot because it was missed, then we will run into
    // trouble with future updates if it's not available in the node anymore.
    assert!(
        store.finalized_header.beacon().slot.is_multiple_of(32),
        "New head is not a checkpoint slot."
    );

    // 3. Commit new state root, header, and sync committees.
    let header: B256 = store.finalized_header.beacon().tree_hash_root();
    let sync_committee_hash: B256 = store.current_sync_committee.tree_hash_root();
    let next_sync_committee_hash: B256 = match store.next_sync_committee {
        Some(next_sync_committee) => next_sync_committee.tree_hash_root(),
        None => B256::ZERO,
    };

    let head = store.finalized_header.beacon().slot;
    let execution = store
        .finalized_header
        .execution()
        .expect("Execution payload doesn't exist.");

    let output = Output {
        prevHead: U256::from(prev_head),
        prevHeader: prev_header,
        prevSyncCommitteeHash: prev_sync_committee_hash,
        newHead: U256::from(head),
        newHeader: header,
        syncCommitteeHash: sync_committee_hash,
        nextSyncCommitteeHash: next_sync_committee_hash,
        executionStateRoot: *execution.state_root(),
        executionBlockNumber: U256::from(*execution.block_number()),
    };

    output.abi_encode()
}
