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

    constructor(address entryPoint) {
        walletImplement = new Wallet(entryPoint);
    }

    function createWallet(
        uint256 x,
        uint256 y
    ) external returns (Wallet) {
        bytes32 salt = keccak256(abi.encodePacked(x, y));
        address payable walletAddress = getWalletAddress(x, y);
        uint256 codeSize = walletAddress.code.length;
        if (codeSize > 0) {
            return Wallet(walletAddress);
        }

        CustomERC1967 proxy = new CustomERC1967{salt: salt}();
        proxy.initialize(address(walletImplement));
        Wallet(walletAddress).__Wallet_init(
            x,
            y
        );

        return Wallet(walletAddress);
    }

    function getWalletCreationCodeHash() public pure returns (bytes32) {
        return keccak256(type(CustomERC1967).creationCode);
    }

    function getWalletAddress(
        uint256 x,
        uint256 y
    ) public view returns (address payable) {
        bytes32 salt = keccak256(abi.encodePacked(x, y));
        return
            payable(
                Create2.computeAddress(
                    salt,
                    keccak256(type(CustomERC1967).creationCode)
                )
            );
    }
}
