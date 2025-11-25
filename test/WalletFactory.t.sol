// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "account-abstraction/core/EntryPoint.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

import "../src/WalletFactory.sol";
import "../src/Wallet.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract WalletFactoryTest is Test {
    EntryPoint entryPoint;
    WalletFactory walletFactory;

    function setUp() external {
        entryPoint = new EntryPoint();
        walletFactory = new WalletFactory(address(entryPoint));
    }

    function test_calculateWalletAddress() external {
        uint256 x = 1;
        uint256 y = 1;

        address predictedAddress = walletFactory.getWalletAddress(x, y);
        console.log("Predicted Wallet Address: ", predictedAddress);
        Wallet deployedWallet = walletFactory.createWallet(bytes32(0), x, y);
        assertEq(predictedAddress, address(deployedWallet));
    }
}
