// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { UUPSUpgradeable } from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { OwnableUpgradeable } from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import { ISP1Verifier } from "succinctlabs-sp1-contracts/src/ISP1Verifier.sol";
import { INobleLightClient } from "../interfaces/INobleLightClient.sol";

// TODO: make pausable?
contract NobleLightClient is INobleLightClient, OwnableUpgradeable, UUPSUpgradeable {
    /// @notice The program's verifier key used.
    bytes32 public programVk;

    /// @notice The SP1 verifier contract used to verify the BLS signature proof.
    ISP1Verifier immutable verifier;

    /// @notice Stores the trusted state roots for a given block number.
    mapping(uint64 => bytes32) stateRoots;

    /// @notice The latest block number that was verified.
    uint64 latestBlockNumber = 0;

    /// @notice The trusted, aggregated BLS12-381 public key of the Noble validator set.
    bytes private trustedPublicKey;

    /// @dev Disables initializers to enforce deployment and initialization through a proxy contract.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with the first set of trusted state.
    /// @dev Can only be called through the proxy.
    /// @param _verifier The SP1 verifier contract used to verify the provided proofs.
    /// @param _programVk The verification key of the Noble light client circuit.
    /// @param _trustedPublicKey The trusted public key for this instance of the contract. 
    function initialize(
        address _verifier,
        bytes32 _programVk,
        bytes calldata _trustedPublicKey
    ) public initializer {
        require(_programVk != bytes32(0), InvalidVk());
        programVk = _programVk;

        require(_verifier != address(0), InvalidAddress());
        verifier = ISP1Verifier(_verifier);

        require(_trustedPublicKey.length == 96, "expected MinSig public key to be 96 bytes");
        trustedPublicKey = _trustedPublicKey;
    }

    /// @inheritdoc INobleLightClient
    function update(bytes calldata proof, bytes calldata publicValues) external {
        // ---------
        // Verification
        //
        verifier.verifyProof(programVk, publicValues, proof);

        // ----------
        // Input validation
        //
        BLSVerifierOutputs memory blsOutputs = abi.decode(publicValues, (BLSVerifierOutputs));

        if (blsOutputs.publicKey.length != 96) {
            revert InvalidPublicKey();
        }

        if (keccak256(blsOutputs.publicKey) != keccak256(trustedPublicKey)) {
            revert WrongPublicKey();
        }

        if (blsOutputs.blockNumber < latestBlockNumber) {
            revert OutdatedUpdate(blsOutputs.blockNumber, latestBlockNumber);
        }

        bytes32 storedRoot = stateRoots[blsOutputs.blockNumber];
        if (storedRoot != bytes32(0) && storedRoot != blsOutputs.stateRoot) {
            revert InvalidStateRoot();
        }

        // ----------
        // Updates
        //
        latestBlockNumber = blsOutputs.blockNumber;
        storedRoots[latestBlockNumber] = blsOutputs.stateRoot;

        emit Updated(blsOutputs.blockNumber, blsOutputs.stateRoot);
    }

    /// @notice Expect the correct length for a valid BLS12-381 key in the MinSig variant.
    /// @dev For reference: https://eth2book.info/latest/part2/building_blocks/bls12-381/#swapping-g1-and-g2.
    /// @dev Noble is using the `MinSig` approach as implemented in https://github.com/commonwarexyz/monorepo/blob/v2026.2.0/cryptography/src/bls12381/primitives/variant.rs#L174-L176.
    /// @param _pk The public key bytes.
    function _checkPublicKeySize(bytes memory _pk) internal {
        if (_pk.length != 96) {
            revert InvalidPublicKey();
        }
    }

    /// @notice Authorizes an upgrade to a new implementation.
    /// @dev This function is required by the UUPS pattern and restricted to the contract owner.
    /// @param newImplementation The address of the new implementation contract.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Update the verifier key used in the SP1 proof verification.
    /// @dev Can only be called by the contract owner.
    /// @param newVk The new verifier key.
    function updateVk(bytes32 newVk) external override onlyOwner {
        programVk = newVk;

        emit VkUpdated(newVk);
    }

    /// @notice Returns the version of the contract.
    /// @return version The semantic versioning string of the contract.
    function version() external pure override returns (string memory) {
        return "v1.0.0";
    }
}