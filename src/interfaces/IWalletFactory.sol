// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

interface IWalletFactory {
    event WalletCreated(bytes32 indexed keyId, address walletAddress);
}
