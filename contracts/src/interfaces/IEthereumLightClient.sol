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
pragma solidity >=0.8.0;

import {IVersioned} from "./IVersioned.sol";
import {IVkUpdatable} from "./IVkUpdatable.sol";

interface IEthereumLightClient is IVersioned, IVkUpdatable {
    error InvalidAddress();
    error InvalidHeader();
    error InvalidSyncCommittee();
    error SyncCommitteeMismatch(bytes32 expected, bytes32 actual);

    struct CircuitOutput {
        uint256 prevHead;
        bytes32 prevHeader;
        bytes32 prevSyncCommitteeHash;
        uint256 newHead;
        bytes32 newHeader;
        bytes32 syncCommitteeHash;
        bytes32 nextSyncCommitteeHash;
        bytes32 executionStateRoot;
        uint256 executionBlockNumber;
    }

    event Updated(uint256 indexed newHead, bytes32 newHeader, bytes32 executionStateRoot, uint256 executionBlockNumber);
    event SyncCommitteeUpdated(uint256 indexed period, bytes32 syncCommitteeHash);

    function update(bytes calldata proof, bytes calldata publicValues) external;
    function latestSlot() external view returns (uint256);
    function latestStateRoot() external view returns (bytes32);
    function latestBlockNumber() external view returns (uint256);
    function getSyncCommitteePeriod(uint256 slot) external pure returns (uint256);
    function getCurrentEpoch() external view returns (uint256);
}
