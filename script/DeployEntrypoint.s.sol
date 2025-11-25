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
        bytes32 salt = vm.envBytes32("SALT");
        vm.startBroadcast(deployerPrivateKey);

        bytes memory code = type(EntryPoint).creationCode;
        address entryPoint = genericFactory.create2(code, salt);
        console.log("EntryPoint: ", entryPoint);

        vm.stopBroadcast();
    }
}
