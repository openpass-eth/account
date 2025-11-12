// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import "openzeppelin/utils/Create2.sol";

import "./interfaces/IWalletFactory.sol";
import "./libraries/CustomERC1967.sol";

import "./Wallet.sol";

/**
 * @title Wallet Factory
 * @author imduchuyyy
 * @notice wallet factory use to create new wallet base on our custom ERC1967Proxy
 */
contract WalletFactory is IWalletFactory {
    Wallet public immutable walletImplement;

    mapping(bytes32 => address) public wallets;

    constructor(address entryPoint) {
        walletImplement = new Wallet(entryPoint);
    }

    function createWallet(
        bytes32 username,
        uint256 x,
        uint256 y,
        string memory walletData
    ) external returns (Wallet) {
        /*
        address payable walletAddress = getWalletAddress(username);
        uint256 codeSize = walletAddress.code.length;
        if (codeSize > 0) {
            return Wallet(walletAddress);
        }

        CustomERC1967 proxy = new CustomERC1967{salt: username}();
        proxy.initialize(address(walletImplement));
        Wallet(walletAddress).__Wallet_init(
            keyId,
            signer,
            x,
            y,
            recoveryAddress,
            walletData
        );

        wallets[username] = walletAddress;

        return Wallet(walletAddress);
        */
    }

    function getWalletCreationCodeHash() public pure returns (bytes32) {
        return keccak256(type(CustomERC1967).creationCode);
    }

    function etWalletAddress(
        bytes32 username
    ) public view returns (address payable) {
        return
            payable(
                Create2.computeAddress(
                    username,
                    keccak256(type(CustomERC1967).creationCode)
                )
            );
    }
}
