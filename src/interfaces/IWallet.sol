// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

interface IWallet {
    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external;

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, uint256[] calldata values, bytes[] calldata func) external;

    event Execute();
}
