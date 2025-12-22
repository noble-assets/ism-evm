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
    // TODO: Replace with actual program VK once circuit is finalized
    bytes32 constant PROGRAM_VK = 0x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    // Initial state - checkpoint from a finalized beacon block
    // TODO: Replace with actual values from a checkpoint sync
    uint256 constant INITIAL_SLOT = 10_000_000;
    bytes32 constant INITIAL_HEADER = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant INITIAL_STATE_ROOT = 0x2222222222222222222222222222222222222222222222222222222222222222;
    uint256 constant INITIAL_BLOCK_NUMBER = 21_000_000;
    bytes32 constant INITIAL_SYNC_COMMITTEE = 0x3333333333333333333333333333333333333333333333333333333333333333;

    // Expected values after update
    // TODO: Replace with actual expected values from test proof
    uint256 constant NEW_SLOT = 10_000_032; // One epoch later (checkpoint slot)
    bytes32 constant NEW_HEADER = 0x4444444444444444444444444444444444444444444444444444444444444444;
    bytes32 constant NEW_STATE_ROOT = 0x5555555555555555555555555555555555555555555555555555555555555555;
    uint256 constant NEW_BLOCK_NUMBER = 21_000_010;
    bytes32 constant NEW_SYNC_COMMITTEE = 0x3333333333333333333333333333333333333333333333333333333333333333;
    bytes32 constant NEXT_SYNC_COMMITTEE = bytes32(0);

    // TODO: Replace with actual proof and public values from the Helios circuit prover
    bytes constant PROOF_PLACEHOLDER = hex"aabbccdd";
    bytes constant PUBLIC_VALUES_PLACEHOLDER = hex"";

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
        assertEq(lightClient.latestExecutionBlockNumber(), INITIAL_BLOCK_NUMBER);
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
        lightClient.update(PROOF_PLACEHOLDER, PUBLIC_VALUES_PLACEHOLDER);

        // Verify state updates
        assertEq(lightClient.latestSlot(), NEW_SLOT);
        assertEq(lightClient.latestBlockNumber(), NEW_BLOCK_NUMBER);
        assertEq(lightClient.headers(NEW_SLOT), NEW_HEADER);
        assertEq(lightClient.stateRoots(NEW_BLOCK_NUMBER), NEW_STATE_ROOT);
        assertEq(lightClient.latestStateRoot(), NEW_STATE_ROOT);
    }

    function test_Update_RevertsOnInvalidProof() public {
        vm.expectRevert();
        lightClient.update(PROOF_PLACEHOLDER, PUBLIC_VALUES_PLACEHOLDER);
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
        lightClient.update(PROOF_PLACEHOLDER, PUBLIC_VALUES_PLACEHOLDER);

        // Unpause and verify update works
        vm.prank(owner);
        lightClient.unpause();
        assertFalse(lightClient.paused());

        lightClient.update(PROOF_PLACEHOLDER, PUBLIC_VALUES_PLACEHOLDER);
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
