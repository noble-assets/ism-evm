/*
 * Copyright 2025 NASD Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.30;

import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ISP1Verifier} from "succinctlabs-sp1-contracts/src/ISP1Verifier.sol";
import {IEthereumISM} from "../interfaces/IEthereumISM.sol";
import {IEthereumLightClient} from "../interfaces/IEthereumLightClient.sol";
import {IInterchainSecurityModule} from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import {Message} from "hyperlane/libs/Message.sol";
import {MerkleLib} from "hyperlane/libs/Merkle.sol";

/**
 * @title EthereumISM
 * @author NASD Inc.
 * @notice Hyperlane Interchain Security Module that uses SP1 zk proofs to verify Hyperlane
 *         Merkle tree hook roots from the Ethereum blockchain
 * @dev This EthereumISM verifies messages by:
 *      1. Accepting SP1 proofs of Ethereum's Merkle tree hook roots via update()
 *      2. Validating Hyperlane messages against these roots via verify(). This will be called by the Hyperlane mailbox.
 */
contract EthereumISM is OwnableUpgradeable, UUPSUpgradeable, PausableUpgradeable, IEthereumISM {
    /// @notice The verification key for the EVM Hyperlane Merkle Tree SP1 program circuit
    bytes32 public programVk;

    /// @notice The SP1 verifier contract used to verify the proofs
    ISP1Verifier public verifier;

    /// @notice The Ethereum light client contract for validating app hashes
    IEthereumLightClient public ethereumLightClient;

    /// @notice Mapping of verified Merkle tree roots that can be used for message verification
    /// @dev A root is added when an SP1 proof is successfully verified via update()
    mapping(bytes32 => bool) public validRoots;

    /**
     * @notice Constructor that disables initializers to prevent implementation contract initialization
     * @dev This follows the UUPS pattern where the implementation should not be initialized
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the EthereumISM contract with required addresses and verification key
     * @dev Can only be called once due to initializer modifier
     * @param _programVk The SP1 program verification key for the Merkle tree circuit
     * @param verifierAddress Address of the SP1 verifier contract
     * @param ethereumLightClientAddress Address of the Noble light client contract
     */
    function initialize(bytes32 _programVk, address verifierAddress, address ethereumLightClientAddress)
        public
        initializer
    {
        __Ownable_init(msg.sender);
        __Pausable_init();

        programVk = _programVk;
        require(verifierAddress != address(0), InvalidAddress());
        verifier = ISP1Verifier(verifierAddress);

        require(ethereumLightClientAddress != address(0), InvalidAddress());
        ethereumLightClient = IEthereumLightClient(ethereumLightClientAddress);
    }

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @dev This function is required by the UUPS pattern and restricted to the contract owner
     * @param newImplementation The address of the new implementation contract
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @notice Updates the set of valid Merkle roots by verifying an SP1 proof
     * @dev This function:
     *      1. Verifies the SP1 proof against the program verification key
     *      2. Decodes the public values to extract the Merkle hook root, state root, and block number
     *      3. Validates the state root matches the Ethereum light client's expected value at the given block number
     *      4. Adds the Merkle hookroot to the set of valid roots
     *      Reverts if the contract is paused.
     * @param proof The SP1 proof bytes
     * @param publicValues The public values from the circuit containing CircuitOutput
     */
    function update(bytes calldata proof, bytes calldata publicValues) external override whenNotPaused {
        verifier.verifyProof(programVk, publicValues, proof);

        CircuitOutput memory output = abi.decode(publicValues, (CircuitOutput));

        // Validate that the state root matches the Ethereum light client's state at this block number
        bytes32 expectedStateRoot = ethereumLightClient.stateRoots(output.blockNumber);
        require(output.stateRoot == expectedStateRoot, InvalidStateRoot());

        // Mark this Merkle hook root as valid for message verification
        validRoots[output.root] = true;

        emit Updated(output.root);
    }

    /**
     * @notice Verifies a Hyperlane message against a previously validated Merkle root
     * @dev This function:
     *      1. Decodes the metadata to extract the Merkle proof (branch and index)
     *      2. Computes the message ID from the message bytes (this is the keccak256 hash of the message)
     *      3. Calculates the Merkle root using the proof
     *      4. Checks if the calculated root exists in validRoots
     *      Reverts if the contract is paused.
     * @param _metadata ABI-encoded MerkleProof containing the branch and index
     * @param _message The Hyperlane message bytes to verify
     * @return True if the message is valid (its Merkle root was previously verified), false otherwise
     */
    function verify(bytes calldata _metadata, bytes calldata _message)
        external
        view
        override
        whenNotPaused
        returns (bool)
    {
        // Decode the Merkle proof from metadata
        MerkleProof memory proof = abi.decode(_metadata, (MerkleProof));

        // Calculate the message ID (leaf in the Merkle tree)
        bytes32 messageId = Message.id(_message);

        // Compute the Merkle hook root from the leaf and proof
        bytes32 calculatedRoot = MerkleLib.branchRoot(messageId, proof.branch, proof.index);

        return validRoots[calculatedRoot];
    }

    /**
     * @notice Returns the module type for this ISM
     * @dev Returns UNUSED type as this is a custom ISM implementation
     * @return The module type as a uint8
     */
    function moduleType() external pure override returns (uint8) {
        return uint8(IInterchainSecurityModule.Types.UNUSED);
    }

    /**
     * @notice Pauses the contract, preventing updates and verifications
     * @dev Can only be called by the contract owner
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses the contract, allowing updates and verifications
     * @dev Can only be called by the contract owner
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Updates the verification key used for proof verification
     * @dev This function can only be called by the contract owner
     * @param newVk The new verification key to be set
     */
    function updateVk(bytes32 newVk) external override onlyOwner {
        programVk = newVk;
        emit VkUpdated(newVk);
    }

    /**
     * @notice Returns the version of the ethereumLightClient contract
     * @return A string representing the version
     */
    function version() external pure override returns (string memory) {
        return "v1.0.0";
    }
}
