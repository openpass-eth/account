// SPDX-License-Identifier: Apache
pragma solidity 0.8.28;

import {LibClone} from "solady/utils/LibClone.sol";
import "./interfaces/IWalletFactory.sol";
import "./Wallet.sol";

/**
 * @title Wallet Factory
 * @author imduchuyyy
 * @notice wallet factory use to create new wallet base on our custom ERC1967Proxy
 */
contract WalletFactory is IWalletFactory {
    address public immutable implementation;

    constructor(address entryPoint) {
        implementation = address(new Wallet(entryPoint));
    }

    function createWallet(
        bytes32 keyId,
        uint256 x,
        uint256 y
    ) external payable returns (Wallet) {
        bytes32 salt = keccak256(abi.encodePacked(x, y));

        (, address walletAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, salt);

        Wallet(payable(walletAddress)).__Wallet_init(x, y);

        emit WalletCreated(keyId, walletAddress);
        return Wallet(payable(walletAddress));
    }

    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    function getWalletAddress(
        uint256 x,
        uint256 y
    ) public view returns (address payable) {
        bytes32 salt = keccak256(abi.encodePacked(x, y));
        return payable(LibClone.predictDeterministicAddress(initCodeHash(), salt, address(this)));
    }

}
