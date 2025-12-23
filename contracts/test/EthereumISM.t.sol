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

import {Test} from "forge-std/src/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EthereumISM} from "../src/ism/EthereumISM.sol";
import {IEthereumISM} from "../src/interfaces/IEthereumISM.sol";
import {IVkUpdatable} from "../src/interfaces/IVkUpdatable.sol";
import {EthereumLightClient} from "../src/light-client/EthereumLightClient.sol";
import {MerkleLib} from "hyperlane/libs/Merkle.sol";
import {Message} from "hyperlane/libs/Message.sol";
import {IInterchainSecurityModule} from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import {SP1Verifier} from "succinctlabs-sp1-contracts/src/v5.0.0/SP1VerifierGroth16.sol";

/**
 * @notice Mock contract for testing EthereumISM's verify function
 * @dev Extends EthereumISM with a direct updateRoot method to bypass SP1 proof verification
 */
contract EthereumISMTestable is EthereumISM {
    function updateRoot(bytes32 root) external {
        validRoots[root] = true;
    }
}

contract EthereumISMTest is Test {
    EthereumISMTestable public ethereumIsm;
    EthereumLightClient public lightClient;
    address public sp1Verifier;
    address public owner;
    address public nonOwner;

    bytes32 constant ISM_VK = 0x00365b20d2b06282fb952d075338aebafd24e16bd963be7407c1dc1f5f9b33e9;

    uint256 constant SOURCE_CHAIN_ID = 1;
    bytes32 constant INITIAL_STATE_ROOT = 0xb014207e69c0ebe07351db560343461c8c6b35b4b58cbcd88be3b34f5ded0254; // The state root at INITIAL_BLOCK_NUMBER
    uint256 constant INITIAL_BLOCK_NUMBER = 24_076_150;

    bytes constant PROOF =
        hex"a4594c590eab658bda49262f48d0b16440f95d16eacfc53e0ab006a962ed6369fe3eab9b3061b4f0f4dcb423e147579ff466938ab22fe08eb514c3f132c769eb397871741a9f945ef284e2963ccc13be129d1a5b703ad6ac34ae44bb7673e4199648f4b80f159a9273666808ee4b14485d783e46ce61c09a2437f159fec2d8d94a525b1c28b6280ba558317b17023b49208beed70cc0f7b9d19fc314951c73fe63d794650934ae817221e260f9bad01c71b9deef73ccec99df2c6ea803cf20e8a140bcd721a41365e4f0e913155c309e96b46a9f7f9e5ee494fc9ecbf2955c63927aa8bf08298f8f7ebcd8e59dabfa83c89c4552a232ba03d7b1ffcef5569cb0018fe642";
    bytes constant PUBLIC_VALUES =
        hex"a4f164ed4d13cc1e0b027b7a37eb0bba27cd1590d90c77b2acf40e2f7e0d7d02b014207e69c0ebe07351db560343461c8c6b35b4b58cbcd88be3b34f5ded025400000000000000000000000000000000000000000000000000000000016f5f76";
    bytes32 constant EXPECTED_ROOT = 0xa4f164ed4d13cc1e0b027b7a37eb0bba27cd1590d90c77b2acf40e2f7e0d7d02;

    uint256 constant TREE_DEPTH = 32;

    function setUp() public {
        owner = makeAddr("owner");
        nonOwner = makeAddr("nonOwner");

        sp1Verifier = address(new SP1Verifier());

        // Deploy light client
        lightClient = new EthereumLightClient(SOURCE_CHAIN_ID);
        bytes memory initDataLightClient = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            keccak256(abi.encodePacked("light_client_vk")), // Dummy VK for light client, we won't update the light client
            1, // Dummy slot
            0x0000000000000000000000000000000000000000000000000000000000000001, // Dummy header
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            0x0000000000000000000000000000000000000000000000000000000000000001, // Dummy sync committee
            sp1Verifier,
            owner
        );

        vm.prank(owner);
        ERC1967Proxy proxy1 = new ERC1967Proxy(address(lightClient), initDataLightClient);
        lightClient = EthereumLightClient(address(proxy1));

        // Deploy EthereumISM
        ethereumIsm = new EthereumISMTestable();
        bytes memory initData =
            abi.encodeWithSelector(EthereumISM.initialize.selector, ISM_VK, sp1Verifier, address(lightClient));
        vm.prank(owner);
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(ethereumIsm), initData);
        ethereumIsm = EthereumISMTestable(address(proxy2));
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Initialize_Success() public view {
        assertEq(ethereumIsm.programVk(), ISM_VK);
        assertEq(address(ethereumIsm.verifier()), sp1Verifier);
        assertEq(address(ethereumIsm.ethereumLightClient()), address(lightClient));
        assertEq(ethereumIsm.owner(), owner);
        uint8 moduleType = ethereumIsm.moduleType();
        assertEq(moduleType, uint8(IInterchainSecurityModule.Types.UNUSED));
        assertEq(ethereumIsm.version(), "v1.0.0");
    }

    function test_Initialize_RevertsOnZeroVerifierAddress() public {
        EthereumISM newImplementation = new EthereumISM();

        bytes memory initData =
            abi.encodeWithSelector(EthereumISM.initialize.selector, ISM_VK, address(0), address(lightClient));

        vm.expectRevert(abi.encodeWithSelector(IEthereumISM.InvalidAddress.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_RevertsOnZeroLightClientAddress() public {
        EthereumISM newImplementation = new EthereumISM();

        bytes memory initData = abi.encodeWithSelector(EthereumISM.initialize.selector, ISM_VK, sp1Verifier, address(0));

        vm.expectRevert(abi.encodeWithSelector(IEthereumISM.InvalidAddress.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_CannotReinitialize() public {
        vm.expectRevert();
        ethereumIsm.initialize(ISM_VK, sp1Verifier, address(lightClient));
    }

    /*//////////////////////////////////////////////////////////////
                            PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_OnlyOwnerCanPauseAndUnpause() public {
        // Non-owner attempting to pause should revert
        vm.prank(nonOwner);
        vm.expectRevert();
        ethereumIsm.pause();

        // Owner pauses successfully
        vm.prank(owner);
        ethereumIsm.pause();
        assertTrue(ethereumIsm.paused());

        // Non-owner attempting to unpause should revert
        vm.prank(nonOwner);
        vm.expectRevert();
        ethereumIsm.unpause();

        // Owner unpauses successfully
        vm.prank(owner);
        ethereumIsm.unpause();
        assertFalse(ethereumIsm.paused());
    }

    function test_UpdateWhilePaused_Reverts() public {
        // Pause the contract
        vm.prank(owner);
        ethereumIsm.pause();

        // Attempting to update while paused should revert
        vm.expectRevert();
        ethereumIsm.update(PROOF, PUBLIC_VALUES);

        // Unpause the contract
        vm.prank(owner);
        ethereumIsm.unpause();

        // Now update should succeed
        vm.expectEmit(true, true, true, true);
        emit IEthereumISM.Updated(EXPECTED_ROOT);
        ethereumIsm.update(PROOF, PUBLIC_VALUES);
    }

    function test_VerifyWhilePaused_Reverts() public {
        // Create Hyperlane message
        bytes memory message = createMockHyperlaneMessage(1, 0x1111);
        bytes32 leaf = Message.id(message);

        // Build tree and update EthereumISM
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;
        bytes32 root = buildTreeAndGetRoot(leaves);
        ethereumIsm.updateRoot(root);

        // Create Merkle proof
        IEthereumISM.MerkleProof memory proof = generateProof(leaves, 0);
        bytes memory metadata = abi.encode(proof);

        // Pause the contract
        vm.prank(owner);
        ethereumIsm.pause();

        // Attempting to verify while paused should revert
        vm.expectRevert();
        ethereumIsm.verify(metadata, message);

        // Unpause the contract
        vm.prank(owner);
        ethereumIsm.unpause();

        // Now verify should succeed
        bool isValid = ethereumIsm.verify(metadata, message);
        assertTrue(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                            UPDATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Update_Success() public {
        vm.expectEmit(true, true, true, true);
        emit IEthereumISM.Updated(EXPECTED_ROOT);
        ethereumIsm.update(PROOF, PUBLIC_VALUES);
        assertTrue(ethereumIsm.validRoots(EXPECTED_ROOT));
    }

    function test_Update_RevertsOnInvalidProof() public {
        // Provide an invalid proof (e.g., altered proof data)
        bytes memory invalidProof = PROOF;
        invalidProof[10] ^= 0xFF; // Corrupt a byte in the proof

        vm.expectRevert();
        ethereumIsm.update(invalidProof, PUBLIC_VALUES);
    }

    function test_Update_RevertsOnInvalidStateRoot() public {
        // Deploy a new light client with a different state root to simulate mismatch
        EthereumLightClient newLightClient = new EthereumLightClient(SOURCE_CHAIN_ID);
        bytes memory initDataLightClient = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            keccak256(abi.encodePacked("light_client_vk")), // Dummy VK for light client, we won't update the light client
            1, // Dummy slot
            0x0000000000000000000000000000000000000000000000000000000000000001, // Dummy header
            keccak256(abi.encodePacked("different_state_root")), // Different state root
            INITIAL_BLOCK_NUMBER,
            0x0000000000000000000000000000000000000000000000000000000000000001, // Dummy sync committee
            sp1Verifier,
            owner
        );
        vm.prank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(newLightClient), initDataLightClient);
        newLightClient = EthereumLightClient(address(proxy));

        // Deploy a new EthereumISM pointing to the new light client
        EthereumISM newImplementation = new EthereumISM();
        bytes memory initData =
            abi.encodeWithSelector(EthereumISM.initialize.selector, ISM_VK, sp1Verifier, address(newLightClient));
        vm.prank(owner);
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(newImplementation), initData);
        EthereumISMTestable newEthereumIsm = EthereumISMTestable(address(proxy2));

        vm.expectRevert(IEthereumISM.InvalidStateRoot.selector);
        newEthereumIsm.update(PROOF, PUBLIC_VALUES);
    }

    function test_UpdateVk() public {
        bytes32 newVk = bytes32(uint256(1));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit IVkUpdatable.VkUpdated(newVk);
        ethereumIsm.updateVk(newVk);

        assertEq(ethereumIsm.programVk(), newVk);

        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));
        ethereumIsm.updateVk(newVk);
    }

    /*//////////////////////////////////////////////////////////////
                            VERIFY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Verify_Success() public {
        // Create Hyperlane messages first
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        // Calculate their message IDs (these will be our leaves)
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        // Build the full tree and get the root
        bytes32 root = buildTreeAndGetRoot(leaves);

        // Update the EthereumISM with this root using the testable method
        ethereumIsm.updateRoot(root);

        // Verify the root was added
        assertTrue(ethereumIsm.validRoots(root));

        // Generate proof for message at index 2 (message3)
        IEthereumISM.MerkleProof memory proof = generateProof(leaves, 2);

        // Verify our proof works with branchRoot
        bytes32 calculatedRoot = MerkleLib.branchRoot(leaves[2], proof.branch, proof.index);
        assertEq(calculatedRoot, root, "Proof should reconstruct root");

        // Encode the proof as metadata
        bytes memory metadata = abi.encode(proof);

        // Verify should succeed with message3
        bool isValid = ethereumIsm.verify(metadata, message3);
        assertTrue(isValid);
    }

    function test_Verify_FailsWithInvalidRoot() public view {
        // Create Hyperlane messages
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        // Calculate their message IDs
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        // We do NOT update the EthereumISM with the root

        // Create a valid Merkle proof for leaves[2]
        IEthereumISM.MerkleProof memory proof = generateProof(leaves, 2);

        // Encode the proof as metadata
        bytes memory metadata = abi.encode(proof);

        // Verify should fail because the root is not valid
        bool isValid = ethereumIsm.verify(metadata, message3);
        assertFalse(isValid);
    }

    function test_Verify_FailsWithInvalidProof() public {
        // Create actual Hyperlane messages
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        // Calculate their message IDs
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        // Build tree and update EthereumISM
        bytes32 root = buildTreeAndGetRoot(leaves);
        ethereumIsm.updateRoot(root);

        // Create a WRONG Merkle proof (proof for index 1 when we're verifying index 2)
        IEthereumISM.MerkleProof memory wrongProof = generateProof(leaves, 1);

        // Encode the wrong proof as metadata
        bytes memory metadata = abi.encode(wrongProof);

        // Verify should fail due to proof mismatch (using message3 but proof for message2)
        bool isValid = ethereumIsm.verify(metadata, message3);
        assertFalse(isValid);
    }

    function test_Verify_FailsWithWrongMessage() public {
        // Create actual Hyperlane messages
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        // Calculate their message IDs
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        // Build tree and update EthereumISM
        bytes32 root = buildTreeAndGetRoot(leaves);
        ethereumIsm.updateRoot(root);

        // Create a valid proof for leaves[2] (message3)
        IEthereumISM.MerkleProof memory proof = generateProof(leaves, 2);

        // Create a DIFFERENT message
        bytes memory wrongMessage = createMockHyperlaneMessage(99, 0x9999);

        // Encode the proof as metadata
        bytes memory metadata = abi.encode(proof);

        // Verify should fail because message doesn't match the leaf
        bool isValid = ethereumIsm.verify(metadata, wrongMessage);
        assertFalse(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                            UPGRADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Upgrade_Success() public {
        // Deploy new implementation
        EthereumISM newImplementation = new EthereumISM();

        // Upgrade as owner
        vm.prank(owner);
        ethereumIsm.upgradeToAndCall(address(newImplementation), "");

        // Verify state is preserved after upgrade
        assertEq(ethereumIsm.programVk(), ISM_VK);
        assertEq(address(ethereumIsm.verifier()), sp1Verifier);
    }

    function test_Upgrade_RevertsWhenNotOwner() public {
        EthereumISM newImplementation = new EthereumISM();

        vm.prank(nonOwner);
        vm.expectRevert();
        ethereumIsm.upgradeToAndCall(address(newImplementation), "");
    }

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_TransferOwnership_Success() public {
        vm.prank(owner);
        ethereumIsm.transferOwnership(nonOwner);

        assertEq(ethereumIsm.owner(), nonOwner);
    }

    function test_TransferOwnership_RevertsWhenNotOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        ethereumIsm.transferOwnership(nonOwner);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Builds a Merkle tree and returns the root
     * @dev Memory-efficient implementation using MerkleLib's precomputed zero hashes.
     *
     *      Hyperlane uses a fixed 32-level tree (2^32 leaf capacity).
     *      For a small number of leaves (e.g., 4), we:
     *      1. Build a minimal subtree containing our leaves
     *      2. Extend it to 32 levels by hashing with precomputed empty subtree hashes
     */
    function buildTreeAndGetRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "No leaves");

        bytes32[TREE_DEPTH] memory zeroes = MerkleLib.zeroHashes();

        uint256 numLeaves = leaves.length;

        // We need to pad to the next power of 2 because binary trees require
        // pairs at each level. E.g., 3 leaves → pad to 4, 5 leaves → pad to 8
        //
        // `n` = number of slots at the leaf level (padded to power of 2)
        // `treeLevels` = number of hashing rounds needed for the minimal subtree
        //
        // Example with 4 leaves:
        //   - n = 4 (already power of 2)
        //   - treeLevels = 2 (need 2 rounds: 4→2→1)
        uint256 n = 1;
        uint256 treeLevels = 0;
        while (n < numLeaves) {
            n *= 2;
            treeLevels++;
        }
        // Edge case: single leaf needs at least 1 level to hash with zero sibling
        if (treeLevels == 0) {
            treeLevels = 1;
            n = 2;
        }

        // Build bottom-up, only keeping track of the current level
        bytes32[] memory currentLevel = new bytes32[](n);

        // Initialize with leaves
        for (uint256 i = 0; i < numLeaves; i++) {
            currentLevel[i] = leaves[i];
        }
        // Remaining positions are zero (default)

        // Build tree levels up to treeLevels
        uint256 levelSize = n;
        for (uint256 level = 0; level < treeLevels; level++) {
            uint256 nextLevelSize = levelSize / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelSize);

            for (uint256 i = 0; i < nextLevelSize; i++) {
                nextLevel[i] = keccak256(abi.encodePacked(currentLevel[i * 2], currentLevel[i * 2 + 1]));
            }

            currentLevel = nextLevel;
            levelSize = nextLevelSize;
        }

        // Now currentLevel[0] is the root of the subtree containing our leaves
        // Continue hashing with zero subtrees until we reach depth 32
        bytes32 subtreeRoot = currentLevel[0];

        for (uint256 level = treeLevels; level < TREE_DEPTH; level++) {
            // Our subtree is on the left, right sibling is the precomputed zero hash
            subtreeRoot = keccak256(abi.encodePacked(subtreeRoot, zeroes[level]));
        }

        return subtreeRoot;
    }

    /**
     * @notice Generates a Merkle proof for a leaf at the given index
     * @dev The proof contains siblings at each level from bottom (level 0) to top (level 31).
     *
     *      For branchRoot verification:
     *      - If bit i of index is 0: leaf is on LEFT at level i, sibling is on RIGHT
     *      - If bit i of index is 1: leaf is on RIGHT at level i, sibling is on LEFT
     */
    function generateProof(bytes32[] memory leaves, uint64 index)
        internal
        pure
        returns (IEthereumISM.MerkleProof memory)
    {
        require(index < leaves.length, "Index out of bounds");

        bytes32[TREE_DEPTH] memory branch;
        bytes32[TREE_DEPTH] memory zeroes = MerkleLib.zeroHashes();

        uint256 numLeaves = leaves.length;

        // Pad to next power of 2
        uint256 n = 1;
        uint256 treeLevels = 0;
        while (n < numLeaves) {
            n *= 2;
            treeLevels++;
        }
        // Edge case: single leaf needs at least 1 level
        if (treeLevels == 0) {
            treeLevels = 1;
            n = 2;
        }

        // Build tree and collect proof
        bytes32[] memory currentLevel = new bytes32[](n);
        for (uint256 i = 0; i < numLeaves; i++) {
            currentLevel[i] = leaves[i];
        }

        uint256 currentIndex = index;
        uint256 levelSize = n;

        // At each level:
        //   1. Grab the sibling of our current node (this goes into the proof)
        //   2. Hash all pairs to build the next level up
        //   3. Update currentIndex to track our position in the next level
        for (uint256 level = 0; level < treeLevels; level++) {
            // Get sibling (XOR with 1 flips the last bit)
            uint256 siblingIndex = currentIndex ^ 1;
            branch[level] = currentLevel[siblingIndex];

            // Build next level by hashing pairs
            uint256 nextLevelSize = levelSize / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelSize);

            for (uint256 i = 0; i < nextLevelSize; i++) {
                nextLevel[i] = keccak256(abi.encodePacked(currentLevel[i * 2], currentLevel[i * 2 + 1]));
            }

            currentLevel = nextLevel;
            currentIndex = currentIndex / 2; // Move to parent's index
            levelSize = nextLevelSize;
        }

        // For levels above treeLevels, sibling is a precomputed zero subtree hash
        for (uint256 level = treeLevels; level < TREE_DEPTH; level++) {
            branch[level] = zeroes[level];
        }

        return IEthereumISM.MerkleProof({branch: branch, index: index});
    }

    /**
     * @notice Creates a mock Hyperlane message with a given nonce and body identifier
     * @dev Creates a properly formatted Hyperlane message
     * @param nonce The nonce for the message
     * @param bodyId A unique identifier that will be included in the body
     * @return The encoded Hyperlane message
     */
    function createMockHyperlaneMessage(uint32 nonce, uint16 bodyId) internal pure returns (bytes memory) {
        // Hyperlane message format:
        // version (1 byte) | nonce (4 bytes) | origin domain (4 bytes) | sender (32 bytes) |
        // destination domain (4 bytes) | recipient (32 bytes) | body (variable)

        bytes memory message = abi.encodePacked(
            uint8(1), // version
            nonce, // nonce
            uint32(1), // origin domain
            bytes32(uint256(uint160(address(0x1234)))), // sender
            uint32(2), // destination domain
            bytes32(uint256(uint160(address(0x5678)))), // recipient
            bytes32(uint256(bodyId)) // body (using bodyId to make each message unique)
        );

        return message;
    }
}
