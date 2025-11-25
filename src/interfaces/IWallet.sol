// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

interface IWallet {
    /**
     * update signer public key
     */
    function updateSigner(bytes32 keyId, uint256 newX, uint256 newY) external;

    /**
     * update recovery wallet and delay time
     */
    function updateRecovery(address recoveryWallet, uint256 delayTime) external;

    /**
     * request account recovery
     */
    function requestRecovery(bytes32 keyId, uint256 newX, uint256 newY) external;

    /**
     * reject account recovery
     */
    function rejectRecovery() external;

    /**
     * complete account recovery
     */
    function completeRecovery() external;

    event Execute();
    event SignerUpdated(bytes32 keyId, uint256 newX, uint256 newY);
    event GuardianUpdated(address newGuardian);
    event RecoveryUpdated(address recoveryWallet, uint256 delayTime);
    event RequestRecovery(bytes32 keyId, uint256 newX, uint256 newY, uint256 timestamp);
    event RejectRecovery();
    event RecoverCompleted(bytes32 keyId, uint256 newX, uint256 newY);
}
