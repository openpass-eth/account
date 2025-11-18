// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "account-abstraction/core/EntryPoint.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../src/WalletFactory.sol";
import "../src/modules/Passkey.sol";
import "../src/Wallet.sol";
import "./utils/ERC4337Utils.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

using ERC4337Utils for EntryPoint;

contract WalletTest is Test {
    EntryPoint entryPoint;
    WalletFactory walletFactory;
    Wallet wallet;

    address owner;
    uint256 ownerKey;

    address payable beneficiary;

    function setUp() external {
        ownerKey = uint256(keccak256("owner"));
        owner = vm.addr(ownerKey);
        entryPoint = new EntryPoint();

        walletFactory = new WalletFactory(address(entryPoint));
    }
}
