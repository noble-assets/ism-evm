// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {Script, console} from "forge-std/src/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EthereumLightClient} from "../src/light-client/EthereumLightClient.sol";
import {EvmISM} from "../src/ism/EvmISM.sol";

/**
 * @title Deploy
 * @notice Deploys the EthereumLightClient and EvmISM behind UUPS proxies.
 *
 * @dev Required environment variables:
 *   ETHEREUM_LIGHT_CLIENT_VK   - SP1 verification key for the Helios circuit
 *   HYPERLANE_MERKLE_VK        - SP1 verification key for the Merkle tree circuit
 *   INITIAL_SLOT               - Beacon chain slot of the trusted checkpoint
 *   INITIAL_HEADER             - Beacon block header hash at the initial slot
 *   INITIAL_STATE_ROOT         - Execution layer state root at the initial block
 *   INITIAL_BLOCK_NUMBER       - Execution layer block number for the initial slot
 *   INITIAL_SYNC_COMMITTEE     - Sync committee hash for the period containing the initial slot
 *   OWNER                      - Address that will own both contracts
 */
contract Deploy is Script {
    function run() public {
        // --- Read environment variables ---
        bytes32 lightClientVk = vm.envBytes32("ETHEREUM_LIGHT_CLIENT_VK");
        bytes32 merkleVk = vm.envBytes32("HYPERLANE_MERKLE_VK");
        uint256 initialSlot = vm.envUint("INITIAL_SLOT");
        bytes32 initialHeader = vm.envBytes32("INITIAL_HEADER");
        bytes32 initialStateRoot = vm.envBytes32("INITIAL_STATE_ROOT");
        uint256 initialBlockNumber = vm.envUint("INITIAL_BLOCK_NUMBER");
        bytes32 initialSyncCommittee = vm.envBytes32("INITIAL_SYNC_COMMITTEE");
        address owner = vm.envAddress("OWNER");

        uint256 sourceChainId = 1; // Ethereum mainnet
        address sp1Verifier = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;

        // --- Sanity checks ---
        require(lightClientVk != bytes32(0), "ETHEREUM_LIGHT_CLIENT_VK not set");
        require(merkleVk != bytes32(0), "HYPERLANE_MERKLE_VK not set");
        require(initialSlot != 0, "INITIAL_SLOT not set");
        require(initialHeader != bytes32(0), "INITIAL_HEADER not set");
        require(initialStateRoot != bytes32(0), "INITIAL_STATE_ROOT not set");
        require(initialBlockNumber != 0, "INITIAL_BLOCK_NUMBER not set");
        require(initialSyncCommittee != bytes32(0), "INITIAL_SYNC_COMMITTEE not set");
        require(owner != address(0), "OWNER not set");

        console.log("=== Deploying EthereumLightClient ===");
        console.log("  Initial slot:", initialSlot);
        console.log("  Initial block number:", initialBlockNumber);
        console.log("  Owner:", owner);

        vm.startBroadcast();

        // ============ Light Client ============

        EthereumLightClient lcImpl = new EthereumLightClient(sourceChainId);
        console.log("  Implementation:", address(lcImpl));

        ERC1967Proxy lcProxy = new ERC1967Proxy(
            address(lcImpl),
            abi.encodeCall(
                EthereumLightClient.initialize,
                (
                    lightClientVk,
                    initialSlot,
                    initialHeader,
                    initialStateRoot,
                    initialBlockNumber,
                    initialSyncCommittee,
                    sp1Verifier,
                    owner
                )
            )
        );
        console.log("  Proxy:", address(lcProxy));

        // ============ ISM ============

        console.log("=== Deploying EvmISM ===");

        EvmISM ismImpl = new EvmISM();
        console.log("  Implementation:", address(ismImpl));

        ERC1967Proxy ismProxy = new ERC1967Proxy(
            address(ismImpl), abi.encodeCall(EvmISM.initialize, (merkleVk, sp1Verifier, address(lcProxy)))
        );
        console.log("  Proxy:", address(ismProxy));

        vm.stopBroadcast();

        // ============ Post-deploy verification ============

        EthereumLightClient lc = EthereumLightClient(address(lcProxy));
        require(lc.latestSlot() == initialSlot, "latestSlot mismatch");
        require(lc.latestBlockNumber() == initialBlockNumber, "latestBlockNumber mismatch");
        require(lc.programVk() == lightClientVk, "lc programVk mismatch");
        require(lc.headers(initialSlot) == initialHeader, "header mismatch");
        require(lc.stateRoots(initialBlockNumber) == initialStateRoot, "stateRoot mismatch");

        EvmISM ism = EvmISM(address(ismProxy));
        require(ism.programVk() == merkleVk, "ism programVk mismatch");
        require(address(ism.lightClient()) == address(lcProxy), "light client address mismatch");
        require(address(ism.verifier()) == sp1Verifier, "ism verifier mismatch");

        console.log("=== Deployment verified successfully ===");
        console.log("  LightClient proxy:", address(lcProxy));
        console.log("  ISM proxy:", address(ismProxy));
    }
}
