// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ISP1Verifier} from "succinctlabs-sp1-contracts/src/ISP1Verifier.sol";
import {IEvmISM} from "../interfaces/IEvmISM.sol";
import {IEvmLightClient} from "../interfaces/IEvmLightClient.sol";
import {IInterchainSecurityModule} from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import {Message} from "hyperlane/libs/Message.sol";
import {MerkleLib} from "hyperlane/libs/Merkle.sol";

/**
 * @title EvmISM
 * @author NASD Inc.
 * @notice Hyperlane Interchain Security Module that uses SP1 zk proofs to verify Hyperlane
 *         Merkle tree hook roots from an EVM source chain.
 * @dev This ISM verifies messages by:
 *      1. Accepting SP1 proofs of the source chain's Merkle tree hook roots via update()
 *      2. Validating Hyperlane messages against these roots via verify(). This will be called by the Hyperlane mailbox.
 */
contract EvmISM is OwnableUpgradeable, UUPSUpgradeable, PausableUpgradeable, IEvmISM {
    /// @notice The verification key for the EVM Hyperlane Merkle Tree SP1 program circuit
    bytes32 public programVk;

    /// @notice The SP1 verifier contract used to verify the proofs
    ISP1Verifier public verifier;

    /// @notice The light client contract for validating source chain state roots
    IEvmLightClient public lightClient;

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
     * @notice Initializes the EvmISM contract with required addresses and verification key
     * @dev Can only be called once due to initializer modifier
     * @param _programVk The SP1 program verification key for the Merkle tree circuit
     * @param verifierAddress Address of the SP1 verifier contract
     * @param lightClientAddress Address of the EVM light client contract
     */
    function initialize(bytes32 _programVk, address verifierAddress, address lightClientAddress) public initializer {
        __Ownable_init(msg.sender);
        __Pausable_init();

        programVk = _programVk;
        require(verifierAddress != address(0), InvalidAddress());
        verifier = ISP1Verifier(verifierAddress);

        require(lightClientAddress != address(0), InvalidAddress());
        lightClient = IEvmLightClient(lightClientAddress);
    }

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @dev This function is required by the UUPS pattern and restricted to the contract owner
     * @param newImplementation The address of the new implementation contract
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @inheritdoc IEvmISM
    function update(bytes calldata proof, bytes calldata publicValues) external override whenNotPaused {
        verifier.verifyProof(programVk, publicValues, proof);

        CircuitOutput memory output = abi.decode(publicValues, (CircuitOutput));

        // Validate that the state root matches the light client's state at this block number
        bytes32 expectedStateRoot = lightClient.stateRoots(output.blockNumber);
        require(expectedStateRoot != bytes32(0) && output.stateRoot == expectedStateRoot, InvalidStateRoot());

        // Mark this Merkle hook root as valid for message verification
        validRoots[output.root] = true;

        emit Updated(output.root, output.blockNumber, output.stateRoot);
    }

    /// @inheritdoc IEvmISM
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
     * @dev Can only be called by the contract owner. See {IVkUpdatable-updateVk}.
     * @param newVk The new verification key to be set
     */
    function updateVk(bytes32 newVk) external override onlyOwner {
        programVk = newVk;
        emit VkUpdated(newVk);
    }

    /**
     * @notice Returns the version of the EvmISM contract
     * @return A string representing the semantic version
     */
    function version() external pure override returns (string memory) {
        return "v1.0.0";
    }
}
