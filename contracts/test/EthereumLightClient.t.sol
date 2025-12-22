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
pragma solidity >=0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EthereumLightClient} from "../src/light-client/EthereumLightClient.sol";
import {IEthereumLightClient} from "../src/interfaces/IEthereumLightClient.sol";
import {IVkUpdatable} from "../src/interfaces/IVkUpdatable.sol";
import {SP1Verifier} from "succinctlabs-sp1-contracts/src/v5.0.0/SP1VerifierGroth16.sol";

contract EthereumLightClientTest is Test {
    EthereumLightClient public lightClient;
    address sp1Verifier;
    address public owner;
    address public nonOwner;

    // Source chain ID for Ethereum mainnet
    uint256 constant SOURCE_CHAIN_ID = 1;

    // VK of our Helios light client circuit
    bytes32 constant PROGRAM_VK = 0x00a47ee58db34832b07fa846172fbce646c3d63d91554c534c2572149fa0b2c6;

    // Initial state - checkpoint from a finalized beacon block
    uint256 constant INITIAL_SLOT = 13_295_584;
    bytes32 constant INITIAL_HEADER = 0x97c775926bc1850b4a3b992c00e5d82af64c4a62c819fc496427701a9daaf279;
    bytes32 constant INITIAL_STATE_ROOT = 0x13f27a01575771657d2e97cf54a3e72cf1adbe2b88d6a42c4f798ece2274755b;
    uint256 constant INITIAL_BLOCK_NUMBER = 24_065_210;
    bytes32 constant INITIAL_SYNC_COMMITTEE = 0x74e7406b0d51ace59849b5ded271f39e44725ca0ed0ca9571650b321a6f9cfb0;

    // Expected values after update
    uint256 constant NEW_SLOT = 13_300_864;
    bytes32 constant NEW_HEADER = 0x932052749e45a1a3470b7ce4f2ed4d584c04e72fba9d3d29d95a06f907097662;
    bytes32 constant NEW_STATE_ROOT = 0x1cd057aa8fda770eb78b24e3016cf68d575160aaed38f8a2b50e277278ab2de6;
    uint256 constant NEW_BLOCK_NUMBER = 24_070_463;
    bytes32 constant NEW_SYNC_COMMITTEE = 0x052ee0fdcb2dfedb68dd2109bffff528eed6bf92572d5d8e2f66dbcc6762de55;
    bytes32 constant NEXT_SYNC_COMMITTEE = 0xe74e77eba2607523561c539915e71bb4b3d2bdc0a5bc80e15809e9b6c0ca4794;

    bytes constant PROOF =
        hex"a4594c5922ecbad2832b7ec21d13e7d2130b158d5e91d124984240b36fc753b2f6bdfb25214f97ea97d2c30edaacd5cd9e85c4c86cb41330cc5d7019abbb1b3b99357830049d1fff3f22470d318400f232254fabb8862071e82320fedf80783b63021686168989f5ce4c9c377f12fc87b5bf8e145bfe22302b02f1a4130a5a28ef60f717293ab77ae7b9d2a07bcbc2b2f80dbeceea6d9ac4f02a4b623c8811b8a637e35014aae9dee9a62988b5a38df267f13abf0ca47f75c33e89fc6d29563f8b9eb17e08aff683c71b820e59e0c58aa93bccfb9fa69c5c86d3c702f7a3a06cf558aac612278710fad1e209751495fbbe69ed51b4a87324d452c1f33db55a0c5e19965c";
    bytes constant PUBLIC_VALUES =
        hex"0000000000000000000000000000000000000000000000000000000000cadfe097c775926bc1850b4a3b992c00e5d82af64c4a62c819fc496427701a9daaf27974e7406b0d51ace59849b5ded271f39e44725ca0ed0ca9571650b321a6f9cfb00000000000000000000000000000000000000000000000000000000000caf480932052749e45a1a3470b7ce4f2ed4d584c04e72fba9d3d29d95a06f907097662052ee0fdcb2dfedb68dd2109bffff528eed6bf92572d5d8e2f66dbcc6762de55e74e77eba2607523561c539915e71bb4b3d2bdc0a5bc80e15809e9b6c0ca47941cd057aa8fda770eb78b24e3016cf68d575160aaed38f8a2b50e277278ab2de600000000000000000000000000000000000000000000000000000000016f493f";

    function setUp() public {
        owner = makeAddr("owner");
        nonOwner = makeAddr("nonOwner");

        sp1Verifier = address(new SP1Verifier());

        // Deploy implementation
        EthereumLightClient implementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            PROGRAM_VK,
            INITIAL_SLOT,
            INITIAL_HEADER,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            INITIAL_SYNC_COMMITTEE,
            sp1Verifier,
            owner
        );

        // Deploy proxy
        vm.prank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        lightClient = EthereumLightClient(address(proxy));
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Initialize_Success() public view {
        assertEq(lightClient.programVk(), PROGRAM_VK);
        assertEq(lightClient.SOURCE_CHAIN_ID(), SOURCE_CHAIN_ID);
        assertEq(lightClient.latestSlot(), INITIAL_SLOT);
        assertEq(lightClient.latestBlockNumber(), INITIAL_BLOCK_NUMBER);
        assertEq(lightClient.headers(INITIAL_SLOT), INITIAL_HEADER);
        assertEq(lightClient.stateRoots(INITIAL_BLOCK_NUMBER), INITIAL_STATE_ROOT);
        assertEq(lightClient.syncCommittees(lightClient.getSyncCommitteePeriod(INITIAL_SLOT)), INITIAL_SYNC_COMMITTEE);
        assertEq(address(lightClient.verifier()), sp1Verifier);
        assertEq(lightClient.owner(), owner);
        assertEq(lightClient.version(), "v1.0.0");
    }

    function test_Initialize_LatestStateRoot() public view {
        assertEq(lightClient.latestStateRoot(), INITIAL_STATE_ROOT);
        assertEq(lightClient.latestBlockNumber(), INITIAL_BLOCK_NUMBER);
    }

    function test_Initialize_SyncCommitteePeriod() public view {
        uint256 expectedPeriod = INITIAL_SLOT / lightClient.SLOTS_PER_PERIOD();
        assertEq(lightClient.getSyncCommitteePeriod(INITIAL_SLOT), expectedPeriod);
    }

    function test_Initialize_CurrentEpoch() public view {
        uint256 expectedEpoch = INITIAL_SLOT / lightClient.SLOTS_PER_EPOCH();
        assertEq(lightClient.getCurrentEpoch(), expectedEpoch);
    }

    function test_Initialize_RevertsOnZeroVerifierAddress() public {
        EthereumLightClient newImplementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        bytes memory initData = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            PROGRAM_VK,
            INITIAL_SLOT,
            INITIAL_HEADER,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            INITIAL_SYNC_COMMITTEE,
            address(0),
            owner
        );

        vm.expectRevert(abi.encodeWithSelector(IEthereumLightClient.InvalidAddress.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_RevertsOnZeroSyncCommittee() public {
        EthereumLightClient newImplementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        bytes memory initData = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            PROGRAM_VK,
            INITIAL_SLOT,
            INITIAL_HEADER,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            bytes32(0), // Zero sync committee
            sp1Verifier,
            owner
        );

        vm.expectRevert(abi.encodeWithSelector(IEthereumLightClient.InvalidSyncCommittee.selector));
        new ERC1967Proxy(address(newImplementation), initData);
    }

    function test_Initialize_CannotReinitialize() public {
        vm.expectRevert();
        lightClient.initialize(
            PROGRAM_VK,
            INITIAL_SLOT,
            INITIAL_HEADER,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            INITIAL_SYNC_COMMITTEE,
            sp1Verifier,
            owner
        );
    }

    function test_Initialize_EmitsUpdatedEvent() public {
        EthereumLightClient newImplementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        bytes memory initData = abi.encodeWithSelector(
            EthereumLightClient.initialize.selector,
            PROGRAM_VK,
            INITIAL_SLOT,
            INITIAL_HEADER,
            INITIAL_STATE_ROOT,
            INITIAL_BLOCK_NUMBER,
            INITIAL_SYNC_COMMITTEE,
            sp1Verifier,
            owner
        );

        vm.expectEmit(true, true, true, true);
        emit IEthereumLightClient.Updated(INITIAL_SLOT, INITIAL_HEADER, INITIAL_STATE_ROOT, INITIAL_BLOCK_NUMBER);
        new ERC1967Proxy(address(newImplementation), initData);
    }

    /*//////////////////////////////////////////////////////////////
                            UPDATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Update_Success() public {
        vm.expectEmit(true, true, true, true);
        emit IEthereumLightClient.Updated(NEW_SLOT, NEW_HEADER, NEW_STATE_ROOT, NEW_BLOCK_NUMBER);
        lightClient.update(PROOF, PUBLIC_VALUES);

        // Verify state updates
        assertEq(lightClient.latestSlot(), NEW_SLOT);
        assertEq(lightClient.latestBlockNumber(), NEW_BLOCK_NUMBER);
        assertEq(lightClient.headers(NEW_SLOT), NEW_HEADER);
        assertEq(lightClient.stateRoots(NEW_BLOCK_NUMBER), NEW_STATE_ROOT);
        assertEq(lightClient.latestStateRoot(), NEW_STATE_ROOT);
        assertEq(lightClient.syncCommittees(lightClient.getSyncCommitteePeriod(NEW_SLOT)), NEW_SYNC_COMMITTEE);
        assertEq(lightClient.syncCommittees(lightClient.getSyncCommitteePeriod(NEW_SLOT) + 1), NEXT_SYNC_COMMITTEE);
    }

    function test_Update_RevertsOnInvalidProof() public {
        // Corrupt public values to make the proof verification fail
        bytes memory invalidPublicValues = PUBLIC_VALUES;
        invalidPublicValues[32] = 0xff;

        vm.expectRevert();
        lightClient.update(PROOF, invalidPublicValues);
    }

    /*//////////////////////////////////////////////////////////////
                            VK UPDATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateVk_Success() public {
        bytes32 newVk = bytes32(uint256(1));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit IVkUpdatable.VkUpdated(newVk);
        lightClient.updateVk(newVk);

        assertEq(lightClient.programVk(), newVk);
    }

    function test_UpdateVk_RevertsWhenNotOwner() public {
        bytes32 newVk = bytes32(uint256(1));

        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));
        lightClient.updateVk(newVk);
    }

    /*//////////////////////////////////////////////////////////////
                            PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_OnlyOwnerCanPause() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        lightClient.pause();

        vm.prank(owner);
        lightClient.pause();
        assertTrue(lightClient.paused());
    }

    function test_OnlyOwnerCanUnpause() public {
        vm.prank(owner);
        lightClient.pause();

        vm.prank(nonOwner);
        vm.expectRevert();
        lightClient.unpause();

        vm.prank(owner);
        lightClient.unpause();
        assertFalse(lightClient.paused());
    }

    function test_UpdateWhilePaused_Reverts() public {
        vm.prank(owner);
        lightClient.pause();
        assertTrue(lightClient.paused());

        vm.expectRevert();
        lightClient.update(PROOF, PUBLIC_VALUES);

        // Unpause and verify update works
        vm.prank(owner);
        lightClient.unpause();
        assertFalse(lightClient.paused());

        lightClient.update(PROOF, PUBLIC_VALUES);
        assertEq(lightClient.latestSlot(), NEW_SLOT);
    }

    /*//////////////////////////////////////////////////////////////
                            UPGRADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Upgrade_Success() public {
        EthereumLightClient newImplementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        vm.prank(owner);
        lightClient.upgradeToAndCall(address(newImplementation), "");

        // Verify state is preserved after upgrade
        assertEq(lightClient.latestSlot(), INITIAL_SLOT);
        assertEq(lightClient.latestBlockNumber(), INITIAL_BLOCK_NUMBER);
        assertEq(lightClient.headers(INITIAL_SLOT), INITIAL_HEADER);
        assertEq(lightClient.stateRoots(INITIAL_BLOCK_NUMBER), INITIAL_STATE_ROOT);
    }

    function test_Upgrade_RevertsWhenNotOwner() public {
        EthereumLightClient newImplementation = new EthereumLightClient(SOURCE_CHAIN_ID);

        vm.prank(nonOwner);
        vm.expectRevert();
        lightClient.upgradeToAndCall(address(newImplementation), "");
    }

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_TransferOwnership_Success() public {
        vm.prank(owner);
        lightClient.transferOwnership(nonOwner);

        assertEq(lightClient.owner(), nonOwner);
    }

    function test_TransferOwnership_RevertsWhenNotOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        lightClient.transferOwnership(nonOwner);
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constants() public view {
        assertEq(lightClient.SECONDS_PER_SLOT(), 12);
        assertEq(lightClient.SLOTS_PER_EPOCH(), 32);
        assertEq(lightClient.SLOTS_PER_PERIOD(), 8192);
    }

    function test_GetSyncCommitteePeriod() public view {
        assertEq(lightClient.getSyncCommitteePeriod(0), 0);
        assertEq(lightClient.getSyncCommitteePeriod(8191), 0);
        assertEq(lightClient.getSyncCommitteePeriod(8192), 1);
        assertEq(lightClient.getSyncCommitteePeriod(16384), 2);
    }
}
