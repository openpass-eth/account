// SPDX-License-Identifier: Apache
pragma solidity 0.8.28;

interface IAccount {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    struct Transactions {
        // @dev An encode of function on accounts encode from Call[]
        bytes executionData;
        // @dev The token used to pay for the transaction gas cost.
        address paymentToken;
        // @dev gas fee in payment token
        uint256 paymentAmount;
        // @dev unique value to prevent replay attacks
        uint256 nonce;

        // @dev chain id (0 for replay across chains)
        uint256 chainId;

        // @dev wallet base
        bytes32 keyId;
    }

    function executeTransaction(Transactions calldata txn, bytes calldata signature, address feeReceiver) external;
}
