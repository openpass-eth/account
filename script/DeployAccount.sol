// SPDX-License-Identifier: Apache
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import "forge-std/console.sol";
import "account-abstraction/core/EntryPoint.sol";
import "../src/Account.sol";
import "./BaseDeployer.sol";

contract Deployer is Script, BaseDeployer {
    function setUp() external {}

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address exitedEntryPoint = vm.envAddress("ENTRY_POINT");
        vm.startBroadcast(deployerPrivateKey);

        DelegateAccount account = new DelegateAccount(exitedEntryPoint);
        console.log("account: ", address(account));

        vm.stopBroadcast();
    }
}
