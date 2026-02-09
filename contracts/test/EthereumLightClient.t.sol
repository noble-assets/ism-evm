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
    bytes32 constant PROGRAM_VK = 0x00862abdca6bf17694f52e03ba97cf0a48826b57897bbbe8ef6bbc861a1ceb51;

    // Initial state - checkpoint from a finalized beacon block
    uint256 constant INITIAL_SLOT = 13_397_920;
    bytes32 constant INITIAL_HEADER = 0xb0c047351a1cc4b012b6b187c5c457357363e538d4f5a6566ead2eee9e19b192;
    bytes32 constant INITIAL_STATE_ROOT = 0xd70b2265d8b0909911b4c0ae39063cd6b1cae20f388fa9cd303368200f16715b;
    uint256 constant INITIAL_BLOCK_NUMBER = 24_167_047;
    bytes32 constant INITIAL_SYNC_COMMITTEE = 0xa5e323a8c2dc1621b5960a1be6ec02f2f692d6cb066caf9dee2faa6d903b7045;

    // Expected values after update
    uint256 constant NEW_SLOT = 13_406_176;
    bytes32 constant NEW_HEADER = 0x8dfd669188d67a83536c2348962856f5c1e37c62694da2924bf9864121a1e35f;
    bytes32 constant NEW_STATE_ROOT = 0xe5b50095daea1b238826077c0ec5c15372c77b2924ab67c8112c9ba216357a1e;
    uint256 constant NEW_BLOCK_NUMBER = 24_175_273;
    bytes32 constant NEW_SYNC_COMMITTEE = 0xa34e009b09ea955e15873dfd037373b8d1d628a136ffd5ea4ea0988c9fa6eae6;
    bytes32 constant NEXT_SYNC_COMMITTEE = 0x8492352b2b72731494ee6e7906e6a3ecb8d3232f0c62fc21e8ee1d8d4f1792b7;

    bytes constant PROOF =
        hex"a4594c592f78bea254adf44775b8993b660ca576e9e3bc1151457076ba17f038847ece422974771e6c91e1a198090d55337de05373bb28d8622703c694fdba12c63e8da617a34605f7fbee084a1bf7db6391f589e28fbd11df76394a664541c07e6971552bc848f61b58c9b5de8d1735d5b557dfc4249bfd13f362458affafea3db93c5027946a5ceb3282729c6f82cd422133f393d61c2e502c974c3a163bfe9bff7af518b7d8e84336f0e792a1a610d4821210a2d83e0dfc891509f3d924107460048a02d548cd21f529149df0d266e81096919bfc124dc4383cd541f8db5a5fa290a20b6a31b08436c68ca02dfc8759a85ac3e4a70ecd7af7cdb1d451595e8c3448f0";
    bytes constant PUBLIC_VALUES =
        hex"0000000000000000000000000000000000000000000000000000000000cc6fa0b0c047351a1cc4b012b6b187c5c457357363e538d4f5a6566ead2eee9e19b192a5e323a8c2dc1621b5960a1be6ec02f2f692d6cb066caf9dee2faa6d903b70450000000000000000000000000000000000000000000000000000000000cc8fe08dfd669188d67a83536c2348962856f5c1e37c62694da2924bf9864121a1e35fa34e009b09ea955e15873dfd037373b8d1d628a136ffd5ea4ea0988c9fa6eae68492352b2b72731494ee6e7906e6a3ecb8d3232f0c62fc21e8ee1d8d4f1792b7e5b50095daea1b238826077c0ec5c15372c77b2924ab67c8112c9ba216357a1e000000000000000000000000000000000000000000000000000000000170e2a9";

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

    function test_Update_Skipped() public {
        // First update to set the state to NEW_SLOT
        lightClient.update(PROOF, PUBLIC_VALUES);

        // Attempt to update with the same proof again, which should be skipped
        vm.expectEmit(true, true, true, true);
        emit IEthereumLightClient.UpdateSkipped(NEW_SLOT, NEW_BLOCK_NUMBER);
        lightClient.update(PROOF, PUBLIC_VALUES);
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
