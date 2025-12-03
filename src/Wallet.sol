// SPDX-License-Identifier: Apache
pragma solidity 0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol";
import "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import "openzeppelin/utils/StorageSlot.sol";
import "openzeppelin/proxy/utils/UUPSUpgradeable.sol";
import "openzeppelin/interfaces/IERC1271.sol";
import "openzeppelin/utils/cryptography/SignatureChecker.sol";
import "openzeppelin/utils/Address.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";

import "./interfaces/IWallet.sol";
import "./libraries/DefaultCallbackHandler.sol";

import {WebAuthn} from "./libraries/WebAuthn.sol";

/**
 * @title Wallet
 * @author imduchuyyy
 * @notice This contract represents a Wallet in the system.
 */
contract Wallet is
    IWallet,
    IERC1271,
    BaseAccount,
    Initializable,
    DefaultCallbackHandler,
    UUPSUpgradeable
{
    using Address for address;

    IEntryPoint private immutable _entryPoint;

    struct SigningKey {
        uint256 x; // for passkey
        uint256 y;
    }

    struct Recovery {
        address recoveryWallet;
        uint256 delayTime;
    }

    struct RecoveryRequest {
        uint256 requestTime;
        bytes32 keyId;
        SigningKey newSigner;
    }

    SigningKey private _signer;
    Recovery private _recovery;
    RecoveryRequest private _recoveryRequest;

    constructor(address entryPointAddress) {
        _entryPoint = IEntryPoint(entryPointAddress);
    }

    /**
     * @notice This function is used to initialize the wallet with an initial key.
     */
    function __Wallet_init(
        uint256 x,
        uint256 y
    ) external initializer {
        _signer.x = x;
        _signer.y = y;
    }

    modifier authorized() {
        require(_isValidCaller(), "Wallet: Invalid Caller");
        _;
    }

    function _authorizeUpgrade(address) internal override authorized {}

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes calldata signature = userOp.signature;
        if (bytes4(userOp.callData[:4]) == IWallet.requestRecovery.selector) {
            // In case of recovery request, verify recovery address signature
            bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
                userOpHash
            );
            if (SignatureChecker.isValidSignatureNow(
                _recovery.recoveryWallet,
                messageHash,
                signature[:65]
            )) {
                validationData = 0;
            } else {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            SigningKey memory signer = _signer;
            if (bytes4(userOp.callData[:4]) == IWallet.completeRecovery.selector) {
                // In case of completing recovery, use the new signer from recovery request
                signer = _recoveryRequest.newSigner;
            }
            WebAuthn.WebAuthnAuth memory auth = abi.decode(
                signature,
                (WebAuthn.WebAuthnAuth)
            );
            if (
                WebAuthn.verify({
                    challenge: abi.encode(userOpHash),
                    requireUV: false,
                    webAuthnAuth: auth,
                    x: signer.x,
                    y: signer.y
                })
            ) {
                validationData = 0;
            } else {
                validationData = SIG_VALIDATION_FAILED;
            }
        }
    }

    /**
     * @notice only accept entrypoint or self call
     */
    function _isValidCaller() internal view returns (bool) {
        return
            msg.sender == address(entryPoint()) || msg.sender == address(this);
    }

    function updateSigner(
        bytes32 keyId,
        uint256 newX,
        uint256 newY
    ) external override(IWallet) authorized {
        _signer.x = newX;
        _signer.y = newY;
        emit SignerUpdated(keyId, newX, newY);
    }

    function updateRecovery(
        address recoveryWallet,
        uint256 delayTime
    ) external override(IWallet) authorized {
        _recovery = Recovery({
            recoveryWallet: recoveryWallet,
            delayTime: delayTime
        });

        emit RecoveryUpdated(recoveryWallet, delayTime);
    }

    function requestRecovery(
        bytes32 keyId,
        uint256 newX,
        uint256 newY
    ) external override(IWallet) authorized {
        require(_recovery.recoveryWallet != address(0), "No recovery set");
        _recoveryRequest = RecoveryRequest({
            keyId: keyId,
            newSigner: SigningKey({x: newX, y: newY}),
            requestTime: block.timestamp
        });

        emit RequestRecovery(keyId, newX, newY, block.timestamp);
    }

    function rejectRecovery() external override(IWallet) authorized {
        delete _recoveryRequest;
        emit RejectRecovery();
    }

    function completeRecovery()
        external
        override(IWallet)
        authorized
    {
        require(_recovery.recoveryWallet != address(0), "No recovery set");
        require(
            _recoveryRequest.requestTime != 0,
            "No recovery request"
        );
        require(
            block.timestamp >=
                _recoveryRequest.requestTime + _recovery.delayTime,
            "Recovery delay not passed"
        );

        _signer = _recoveryRequest.newSigner;

        emit RecoverCompleted(_recoveryRequest.keyId, _signer.x, _signer.y);

        delete _recoveryRequest;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * validate signature base on IERC1271
     */
    function isValidSignature(
        bytes32 signMessage,
        bytes calldata signature
    ) public view override returns (bytes4 magicValue) {
        WebAuthn.WebAuthnAuth memory auth = abi.decode(
            signature,
            (WebAuthn.WebAuthnAuth)
        );
        if (
            WebAuthn.verify({
                challenge: abi.encode(signMessage),
                requireUV: false,
                webAuthnAuth: auth,
                x: _signer.x,
                y: _signer.y
            })
        ) {
            magicValue = this.isValidSignature.selector;
        } else {
            magicValue = 0x00000000;
        }
    }

    function getSigner() external view returns (uint256 x, uint256 y) {
        x = _signer.x;
        y = _signer.y;
    }

    function getRecovery()
        external
        view
        returns (address recoveryWallet, uint256 delayTime)
    {
        recoveryWallet = _recovery.recoveryWallet;
        delayTime = _recovery.delayTime;
    }

    function getRecoveryRequest()
        external
        view
        returns (
            bytes32 keyId,
            uint256 newX,
            uint256 newY,
            uint256 requestTime
        )
    {
        keyId = _recoveryRequest.keyId;
        newX = _recoveryRequest.newSigner.x;
        newY = _recoveryRequest.newSigner.y;
        requestTime = _recoveryRequest.requestTime;
    }
}
