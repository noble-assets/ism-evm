// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IInterchainSecurityModule } from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import { TREE_DEPTH } from "hyperlane/libs/Merkle.sol";
import { IVersioned } from "./IVersioned.sol";
import { IVkUpdatable } from "./IVkUpdatable.sol";

/// @author Noble Engineering Team
/// @title INobleISM
/// @notice The canonical interface for a Hyperlane Interchain Security Module, which verifies
/// incoming messages based on a provided BLS12-381 signature from Noble's validator set, and
/// a provided SP1 proof for the inclusion of a given message in the Hyperlane Merkle Tree.
interface INobleISM is IInterchainSecurityModule, IVersioned, IVkUpdatable {
    /// @notice Thrown when the contract is instantiated with an invalid trusted public key.
    error InvalidTrustedPublicKey();

    /// @notice Thrown when the provided BLS12-381 signature does not match the trusted public key.
    error WrongSigner();

    /// @notice Thrown when the provided signature bytes are not a valid BLS12-381 signature.
    error InvalidSignature();

    /// @return moduleType The module type of this ISM implementation.
    function moduleType() external view returns (uint8);

    /// @notice Output structure from the Merkle proof verification circuit.
    /// @dev This struct contains the data needed to validate a Merkle tree root against Noble's EVM state.
    struct CircuitOutput {
        bytes32 root;
        bytes32 stateRoot;
        uint64 blockNumber;
    }

    struct MerkleProof {
        bytes32[TREE_DEPTH] branch;
        uint64 index;
    }

    /// @notice Executes the verification of the message and the provided metadata.
    /// @dev Checks that the provided signature bytes correspond to a BLS12-381 signature of the
    /// trusted validator set, and verifies the inclusion of the given Hyperlane message in the
    /// corresponding Merkle tree.
    /// @param _metadata The ABI-encoded BLS12-381 signature and Merkle proof containing the branch
    /// and index.
    /// @param _message The Hyperlane message bytes to verify.
    /// @return True if the provided message and metadata are valid.
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool);
}