// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EvmISM} from "../src/ism/EvmISM.sol";
import {IEvmISM} from "../src/interfaces/IEvmISM.sol";
import {IVkUpdatable} from "../src/interfaces/IVkUpdatable.sol";
import {EthereumLightClient} from "../src/light-client/EthereumLightClient.sol";
import {MerkleLib} from "hyperlane/libs/Merkle.sol";
import {Message} from "hyperlane/libs/Message.sol";
import {IInterchainSecurityModule} from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import {SP1Verifier} from "succinctlabs-sp1-contracts/src/v5.0.0/SP1VerifierGroth16.sol";

/**
 * @notice Mock contract for testing EvmISM's verify function
 * @dev Extends EvmISM with a direct updateRoot method to bypass SP1 proof verification
 */
contract EvmISMTestable is EvmISM {
    function updateRoot(bytes32 root) external {
        validRoots[root] = true;
    }
}

contract EvmISMTest is Test {
    EvmISMTestable public evmIsm;
    EthereumLightClient public lightClient;
    address public sp1Verifier;
    address public owner;
    address public nonOwner;

    bytes32 constant ISM_VK = 0x00be9919090826ed5b9affde25585edfa03b51d87274863f03192388dc33c405;

    uint256 constant SOURCE_CHAIN_ID = 1;
    bytes32 constant INITIAL_STATE_ROOT = 0x8ba4f9683983d3f77bb3ab2a55c415e655e8b48ec251cac753b7d2ef47df593a;
    uint64 constant INITIAL_BLOCK_NUMBER = 24_175_368;

    bytes constant PROOF =
        hex"a4594c5927d0f6a2b252020b0932b5a70e4ecf0d009d8af2f1c2612751ba7a2a9f66cfcd14eb3266d5efa25f3a8dd45961b3b24252d56bc6222c10f6214b76098668af83184f96006c06eb58bcba8be55a16bcdbea443ebe2010c82320a967586920f40b1b1faa2395f73cc0bf0103d6c8f91b7a3b47913ffb426b12d57fbb8c16941616124f3cdccceff24fa05c2c332a30e995289b70531e10f39ca5e16e5e3556cfdf1a1899e2dddc35fca53c94afc49bf161623ef12c639b4a7a8f1d841923a4030a0a9c0a13fe6d5d4a389c2ca5c9cc309eba6b834a1f906647814c9c99f5e79f6e1076c0d043717d44d04c63018b897e1ab72bd19076ae1da07f1948dcdef35232";
    bytes constant PUBLIC_VALUES =
        hex"de6398da49095a535e5c2b6535913b271ff51d77f1cca6b96350fe7655fa51478ba4f9683983d3f77bb3ab2a55c415e655e8b48ec251cac753b7d2ef47df593a000000000000000000000000000000000000000000000000000000000170e308";
    bytes32 constant EXPECTED_ROOT = 0xde6398da49095a535e5c2b6535913b271ff51d77f1cca6b96350fe7655fa5147;

    uint256 constant TREE_DEPTH = 32;

    function setUp() public {
        owner = makeAddr("owner");
        nonOwner = makeAddr("nonOwner");

        sp1Verifier = address(new SP1Verifier());

        // Deploy light client
        lightClient = new EthereumLightClient(SOURCE_CHAIN_ID);
        bytes memory initDataLightClient = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            keccak256(abi.encodePacked("light_client_vk")),
            1,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            sp1Verifier,
            owner
        );

        vm.prank(owner);
        ERC1967Proxy proxy1 = new ERC1967Proxy(address(lightClient), initDataLightClient);
        lightClient = EthereumLightClient(address(proxy1));

        // Deploy EvmISM
        evmIsm = new EvmISMTestable();
        bytes memory initData =
            abi.encodeWithSelector(EvmISM.initialize.selector, ISM_VK, sp1Verifier, address(lightClient));
        vm.prank(owner);
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(evmIsm), initData);
        evmIsm = EvmISMTestable(address(proxy2));
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Initialize_Success() public view {
        assertEq(evmIsm.programVk(), ISM_VK);
        assertEq(address(evmIsm.verifier()), sp1Verifier);
        assertEq(address(evmIsm.lightClient()), address(lightClient));
        assertEq(evmIsm.owner(), owner);
        uint8 moduleType = evmIsm.moduleType();
        assertEq(moduleType, uint8(IInterchainSecurityModule.Types.UNUSED));
        assertEq(evmIsm.version(), "v1.0.0");
    }

    function test_Initialize_RevertsOnZeroVerifierAddress() public {
        EvmISM newImplementation = new EvmISM();

        bytes memory initData =
            abi.encodeWithSelector(EvmISM.initialize.selector, ISM_VK, address(0), address(lightClient));

        vm.expectRevert(abi.encodeWithSelector(IEvmISM.InvalidAddress.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_RevertsOnZeroLightClientAddress() public {
        EvmISM newImplementation = new EvmISM();

        bytes memory initData = abi.encodeWithSelector(EvmISM.initialize.selector, ISM_VK, sp1Verifier, address(0));

        vm.expectRevert(abi.encodeWithSelector(IEvmISM.InvalidAddress.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_CannotReinitialize() public {
        vm.expectRevert();
        evmIsm.initialize(ISM_VK, sp1Verifier, address(lightClient));
    }

    /*//////////////////////////////////////////////////////////////
                            PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_OnlyOwnerCanPauseAndUnpause() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        evmIsm.pause();

        vm.prank(owner);
        evmIsm.pause();
        assertTrue(evmIsm.paused());

        vm.prank(nonOwner);
        vm.expectRevert();
        evmIsm.unpause();

        vm.prank(owner);
        evmIsm.unpause();
        assertFalse(evmIsm.paused());
    }

    function test_UpdateWhilePaused_Reverts() public {
        vm.prank(owner);
        evmIsm.pause();

        vm.expectRevert();
        evmIsm.update(PROOF, PUBLIC_VALUES);

        vm.prank(owner);
        evmIsm.unpause();

        vm.expectEmit(true, true, true, true);
        emit IEvmISM.Updated(EXPECTED_ROOT, INITIAL_BLOCK_NUMBER, INITIAL_STATE_ROOT);
        evmIsm.update(PROOF, PUBLIC_VALUES);
    }

    function test_VerifyWhilePaused_Reverts() public {
        bytes memory message = createMockHyperlaneMessage(1, 0x1111);
        bytes32 leaf = Message.id(message);

        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;
        bytes32 root = buildTreeAndGetRoot(leaves);
        evmIsm.updateRoot(root);

        IEvmISM.MerkleProof memory proof = generateProof(leaves, 0);
        bytes memory metadata = abi.encode(proof);

        vm.prank(owner);
        evmIsm.pause();

        vm.expectRevert();
        evmIsm.verify(metadata, message);

        vm.prank(owner);
        evmIsm.unpause();

        bool isValid = evmIsm.verify(metadata, message);
        assertTrue(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                            UPDATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Update_Success() public {
        vm.expectEmit(true, true, true, true);
        emit IEvmISM.Updated(EXPECTED_ROOT, INITIAL_BLOCK_NUMBER, INITIAL_STATE_ROOT);
        evmIsm.update(PROOF, PUBLIC_VALUES);
        assertTrue(evmIsm.validRoots(EXPECTED_ROOT));
    }

    function test_Update_RevertsOnInvalidProof() public {
        bytes memory invalidProof = PROOF;
        invalidProof[10] ^= 0xFF;

        vm.expectRevert();
        evmIsm.update(invalidProof, PUBLIC_VALUES);
    }

    function test_Update_RevertsOnInvalidStateRoot() public {
        EthereumLightClient newLightClient = new EthereumLightClient(SOURCE_CHAIN_ID);
        bytes memory initDataLightClient = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            keccak256(abi.encodePacked("light_client_vk")),
            1,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            keccak256(abi.encodePacked("different_state_root")),
            INITIAL_BLOCK_NUMBER,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            sp1Verifier,
            owner
        );
        vm.prank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(newLightClient), initDataLightClient);
        newLightClient = EthereumLightClient(address(proxy));

        EvmISM newImplementation = new EvmISM();
        bytes memory initData =
            abi.encodeWithSelector(EvmISM.initialize.selector, ISM_VK, sp1Verifier, address(newLightClient));
        vm.prank(owner);
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(newImplementation), initData);
        EvmISMTestable newEvmIsm = EvmISMTestable(address(proxy2));

        vm.expectRevert(IEvmISM.InvalidStateRoot.selector);
        newEvmIsm.update(PROOF, PUBLIC_VALUES);
    }

    function test_UpdateVk() public {
        bytes32 newVk = bytes32(uint256(1));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit IVkUpdatable.VkUpdated(newVk);
        evmIsm.updateVk(newVk);

        assertEq(evmIsm.programVk(), newVk);

        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));
        evmIsm.updateVk(newVk);
    }

    /*//////////////////////////////////////////////////////////////
                            VERIFY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Verify_Success() public {
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        bytes32 root = buildTreeAndGetRoot(leaves);
        evmIsm.updateRoot(root);
        assertTrue(evmIsm.validRoots(root));

        IEvmISM.MerkleProof memory proof = generateProof(leaves, 2);

        bytes32 calculatedRoot = MerkleLib.branchRoot(leaves[2], proof.branch, proof.index);
        assertEq(calculatedRoot, root, "Proof should reconstruct root");

        bytes memory metadata = abi.encode(proof);

        bool isValid = evmIsm.verify(metadata, message3);
        assertTrue(isValid);
    }

    function test_Verify_FailsWithInvalidRoot() public view {
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        IEvmISM.MerkleProof memory proof = generateProof(leaves, 2);
        bytes memory metadata = abi.encode(proof);

        bool isValid = evmIsm.verify(metadata, message3);
        assertFalse(isValid);
    }

    function test_Verify_FailsWithInvalidProof() public {
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        bytes32 root = buildTreeAndGetRoot(leaves);
        evmIsm.updateRoot(root);

        IEvmISM.MerkleProof memory wrongProof = generateProof(leaves, 1);
        bytes memory metadata = abi.encode(wrongProof);

        bool isValid = evmIsm.verify(metadata, message3);
        assertFalse(isValid);
    }

    function test_Verify_FailsWithWrongMessage() public {
        bytes memory message1 = createMockHyperlaneMessage(1, 0x1111);
        bytes memory message2 = createMockHyperlaneMessage(2, 0x2222);
        bytes memory message3 = createMockHyperlaneMessage(3, 0x3333);
        bytes memory message4 = createMockHyperlaneMessage(4, 0x4444);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = Message.id(message1);
        leaves[1] = Message.id(message2);
        leaves[2] = Message.id(message3);
        leaves[3] = Message.id(message4);

        bytes32 root = buildTreeAndGetRoot(leaves);
        evmIsm.updateRoot(root);

        IEvmISM.MerkleProof memory proof = generateProof(leaves, 2);
        bytes memory wrongMessage = createMockHyperlaneMessage(99, 0x9999);
        bytes memory metadata = abi.encode(proof);

        bool isValid = evmIsm.verify(metadata, wrongMessage);
        assertFalse(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                            UPGRADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Upgrade_Success() public {
        EvmISM newImplementation = new EvmISM();

        vm.prank(owner);
        evmIsm.upgradeToAndCall(address(newImplementation), "");

        assertEq(evmIsm.programVk(), ISM_VK);
        assertEq(address(evmIsm.verifier()), sp1Verifier);
    }

    function test_Upgrade_RevertsWhenNotOwner() public {
        EvmISM newImplementation = new EvmISM();

        vm.prank(nonOwner);
        vm.expectRevert();
        evmIsm.upgradeToAndCall(address(newImplementation), "");
    }

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_TransferOwnership_Success() public {
        vm.prank(owner);
        evmIsm.transferOwnership(nonOwner);

        assertEq(evmIsm.owner(), nonOwner);
    }

    function test_TransferOwnership_RevertsWhenNotOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        evmIsm.transferOwnership(nonOwner);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function buildTreeAndGetRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "No leaves");

        bytes32[TREE_DEPTH] memory zeroes = MerkleLib.zeroHashes();

        uint256 numLeaves = leaves.length;

        uint256 n = 1;
        uint256 treeLevels = 0;
        while (n < numLeaves) {
            n *= 2;
            treeLevels++;
        }
        if (treeLevels == 0) {
            treeLevels = 1;
            n = 2;
        }

        bytes32[] memory currentLevel = new bytes32[](n);

        for (uint256 i = 0; i < numLeaves; i++) {
            currentLevel[i] = leaves[i];
        }

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

        bytes32 subtreeRoot = currentLevel[0];

        for (uint256 level = treeLevels; level < TREE_DEPTH; level++) {
            subtreeRoot = keccak256(abi.encodePacked(subtreeRoot, zeroes[level]));
        }

        return subtreeRoot;
    }

    function generateProof(bytes32[] memory leaves, uint64 index) internal pure returns (IEvmISM.MerkleProof memory) {
        require(index < leaves.length, "Index out of bounds");

        bytes32[TREE_DEPTH] memory branch;
        bytes32[TREE_DEPTH] memory zeroes = MerkleLib.zeroHashes();

        uint256 numLeaves = leaves.length;

        uint256 n = 1;
        uint256 treeLevels = 0;
        while (n < numLeaves) {
            n *= 2;
            treeLevels++;
        }
        if (treeLevels == 0) {
            treeLevels = 1;
            n = 2;
        }

        bytes32[] memory currentLevel = new bytes32[](n);
        for (uint256 i = 0; i < numLeaves; i++) {
            currentLevel[i] = leaves[i];
        }

        uint256 currentIndex = index;
        uint256 levelSize = n;

        for (uint256 level = 0; level < treeLevels; level++) {
            uint256 siblingIndex = currentIndex ^ 1;
            branch[level] = currentLevel[siblingIndex];

            uint256 nextLevelSize = levelSize / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelSize);

            for (uint256 i = 0; i < nextLevelSize; i++) {
                nextLevel[i] = keccak256(abi.encodePacked(currentLevel[i * 2], currentLevel[i * 2 + 1]));
            }

            currentLevel = nextLevel;
            currentIndex = currentIndex / 2;
            levelSize = nextLevelSize;
        }

        for (uint256 level = treeLevels; level < TREE_DEPTH; level++) {
            branch[level] = zeroes[level];
        }

        return IEvmISM.MerkleProof({branch: branch, index: index});
    }

    function createMockHyperlaneMessage(uint32 nonce, uint16 bodyId) internal pure returns (bytes memory) {
        bytes memory message = abi.encodePacked(
            uint8(1),
            nonce,
            uint32(1),
            bytes32(uint256(uint160(address(0x1234)))),
            uint32(2),
            bytes32(uint256(uint160(address(0x5678)))),
            bytes32(uint256(bodyId))
        );

        return message;
    }
}
