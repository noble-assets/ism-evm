// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { INobleISM } from "../interfaces/INobleISM.sol";

contract NobleISM is INobleISM {
    bytes private TRUSTED_PUBLIC_KEY;

    constructor(
        // TODO: also accept light client contract address here
        bytes memory _trusted_public_key
    ) {
        // TODO: verify public key here?
        TRUSTED_PUBLIC_KEY = _trusted_public_key;
    }

    /// @inheritdoc INobleISM
    function moduleType() external view returns (uint8) {
        // TODO: check if this ID is fine? which ID should be used?
        return 255;
    }

    /// @inheritdoc INobleISM
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool) {
        require(false, "implement me!");

        return false;
    }

    /// @inheritdoc IVkUpdateable
    function updateVk(bytes32 newVk) external override onlyOwner {
        programVk = newVk;

        emit VkUpdated(newVk);
    }

    /// @inheritdoc IVersioned
    function version() external pure override returns (string memory) {
        return "v1.0.0";
    }
}