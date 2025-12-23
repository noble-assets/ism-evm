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
pragma solidity ^0.8.0;

import {IInterchainSecurityModule} from "hyperlane/interfaces/IInterchainSecurityModule.sol";
import {TREE_DEPTH} from "hyperlane/libs/Merkle.sol";
import {IVersioned} from "./IVersioned.sol";
import {IVkUpdatable} from "./IVkUpdatable.sol";

interface IEthereumISM is IInterchainSecurityModule, IVersioned, IVkUpdatable {
    error InvalidAddress();
    error InvalidStateRoot();

    event Updated(bytes32 root);

    struct CircuitOutput {
        bytes32 root;
        bytes32 stateRoot;
        uint64 blockNumber;
    }

    struct MerkleProof {
        bytes32[TREE_DEPTH] branch;
        uint64 index;
    }

    function update(bytes calldata proof, bytes calldata publicValues) external;
}
