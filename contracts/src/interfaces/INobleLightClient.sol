// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IVersioned } from "./IVersioned.sol";
import { IVkUpdatable } from "./IVkUpdatable.sol";

interface INobleLightClient is IVersioned, IVkUpdatable {
    /// @notice Thrown when an invalid address is passed.
    error InvalidAddress();

    /// @notice Thrown when an invalid block number is passed.
    error InvalidBlockNumber();

    /// @notice Thrown when an invalid public key is passed.
    error InvalidPublicKey();

    /// @notice Thrown when an unexpected public key is used in the verified header.
    error WrongPublicKey();

    /// @notice Thrown when an invalid state root is passed.
    error InvalidStateRoot();

    /// @notice Emitted when a new block height and corresponding state root are
    /// verified.
    event Updated(uint64 blockNumber, bytes32 stateRoot);

    /// @notice The output structure generated from the ZK circuit.
    /// @param blockNumber The block number of the verified header.
    /// @param stateRoot The state root associated with the verified header.
    /// @param publicKey The public key that had signed the (ensures sync between contract and circuit).
    struct BLSVerifierOutputs {
        uint64 blockNumber;
        bytes32 stateRoot;
        bytes publicKey;
    }

    /// @notice Updates the stored variables with the provided trusted information.
    function update(bytes calldata proof, bytes calldata publicValues) external;
}