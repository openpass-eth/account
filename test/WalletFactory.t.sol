// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "account-abstraction/core/EntryPoint.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

import "../src/WalletFactory.sol";
import "../src/libraries/CustomERC1967.sol";
import "../src/Wallet.sol";
import "../src/modules/Passkey.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract WalletFactoryTest is Test {
    EntryPoint entryPoint;
    WalletFactory walletFactory;
    PasskeyModule passkey;

    function setUp() external {
        entryPoint = new EntryPoint();
        walletFactory = new WalletFactory(address(entryPoint));
        passkey = new PasskeyModule();
    }

    function test_calculateWalletAddress() external {
        uint256 x = 123456789;
        uint256 y = 987654321;

        address predictedAddress = walletFactory.getWalletAddress(x, y);
        Wallet deployedWallet = walletFactory.createWallet(x, y);
        assertEq(predictedAddress, address(deployedWallet));
    }
}
