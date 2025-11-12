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

    /**
     * update signer public key
     */
    function updateSigner(uint256 newX, uint256 newY) external;

    /**
     * update guardian address
     */
    function updateGuardian(address newGuardian) external;

    /**
     * update recovery wallet and delay time
     */
    function updateRecovery(address recoveryWallet, uint256 delayTime) external;

    /**
     * request account recovery
     */
    function requestRecovery(uint256 newX, uint256 newY) external;

    /**
     * reject account recovery
     */
    function rejectRecovery() external;

    /**
     * complete account recovery
     */
    function completeRecovery() external;

    event Execute();
    event SignerUpdated(uint256 newX, uint256 newY);
    event GuardianUpdated(address newGuardian);
    event RecoveryUpdated(address recoveryWallet, uint256 delayTime);
    event RequestRecovery(uint256 newX, uint256 newY, uint256 timestamp);
    event RejectRecovery();
    event RecoverCompleted(uint256 newX, uint256 newY);
}
