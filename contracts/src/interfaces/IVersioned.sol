// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20;

/**
 * @title IVersioned
 * @notice Interface for contracts that provide version information.
 * @dev This interface enables contracts to expose their version for tracking upgrades,
 *      compatibility checks, and off-chain tooling integration.
 */
interface IVersioned {
    /**
     * @notice Returns the version of the contract.
     * @dev Should follow semantic versioning (e.g., "v1.0.0", "v2.1.3").
     *      This is useful for tracking contract implementations, especially in
     *      upgradeable contract patterns like UUPS or transparent proxies.
     * @return A string representing the semantic version of the contract.
     */
    function version() external pure returns (string memory);
}
