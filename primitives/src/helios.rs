use alloy_primitives::B256;
use alloy_sol_types::sol;
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec,
    types::{FinalityUpdate, Forks, LightClientStore, Update},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Input {
    pub updates: Vec<Update<MainnetConsensusSpec>>,
    pub finality_update: FinalityUpdate<MainnetConsensusSpec>,
    pub expected_current_slot: u64,
    pub store: LightClientStore<MainnetConsensusSpec>,
    pub genesis_root: B256,
    pub forks: Forks,
}

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
