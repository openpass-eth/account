// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import {Script, console2} from "forge-std/Script.sol";

import "forge-std/console.sol";
import "account-abstraction/core/EntryPoint.sol";
import "../src/WalletFactory.sol";
import "./BaseDeployer.sol";

contract Deployer is Script, BaseDeployer {
    function setUp() external {}

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address exitedEntryPoint = vm.envAddress("ENTRY_POINT");
        vm.startBroadcast(deployerPrivateKey);

        WalletFactory walletFactory = new WalletFactory(exitedEntryPoint);
        console.log("WalletFactory: ", address(walletFactory));

        vm.stopBroadcast();
    }
}
