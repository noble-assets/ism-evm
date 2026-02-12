// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20;

/**
 * @title IEvmLightClient
 * @notice Minimal interface for light clients that provide verified EVM execution state roots.
 * @dev Any chain-specific light client (Ethereum, Noble, etc.) should implement this.
 */
interface IEvmLightClient {
    /**
     * @notice Returns the execution state root for a given block number.
     * @param blockNumber The execution layer block number.
     * @return The state root hash, or zero if not set.
     */
    function stateRoots(uint256 blockNumber) external view returns (bytes32);

    /**
     * @notice Returns the execution state root for the latest finalized block.
     * @return The state root hash that can be used for verifying storage proofs.
     */
    function latestStateRoot() external view returns (bytes32);

    /**
     * @notice Returns the latest finalized execution block number.
     * @return The most recent execution block number with a verified state root.
     */
    function latestBlockNumber() external view returns (uint256);
}
