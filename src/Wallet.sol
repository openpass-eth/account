// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import "account-abstraction/core/BaseAccount.sol";
import "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import "openzeppelin/utils/StorageSlot.sol";
import "openzeppelin/proxy/utils/UUPSUpgradeable.sol";
import "openzeppelin/interfaces/IERC1271.sol";

import "./interfaces/IModule.sol";
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
    using ECDSA for bytes32;
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
        SigningKey newSigner;
        uint256 requestTime;
    }

    SigningKey private _signer;
    Recovery private _recovery;
    RecoveryRequest private _recoveryRequest;

    address private _guardian;

    constructor(address entryPointAddress) {
        _entryPoint = IEntryPoint(entryPointAddress);
    }

    /**
     * @notice This function is used to initialize the wallet with an initial key.
     */
    function __Wallet_init(
        uint256 x,
        uint256 y,
        string memory walletData
    ) external initializer {
        _signer.x = x;
        _signer.y = y;
        _walletData = walletData;
    }

    modifier authorized() {
        require(_isValidCaller(), "Wallet: Invalid Caller");
        _;
    }

    function _authorizeUpgrade(address) internal override authorized {}

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes calldata signature = userOp.signature;
        if (_guardian != address(0)) {
            // Verify guardian signature first for all operations
            bytes32 messageHash = userOpHash.toEthSignedMessageHash();
            address recoveredGuardian = messageHash.recover(
                signature[:65]
            );
            if (recoveredGuardian != _guardian) {
                // immediate failure if guardian signature is invalid
                return SIG_VALIDATION_FAILED;
            }
            signature = signature[65:];
        }
        if (bytes4(userOp.callData[:4]) == IWallet.requestRecovery.selector) {
            // In case of recovery request, verify recovery address signature
            bytes32 messageHash = userOpHash.toEthSignedMessageHash();
            address recoveredRecoveryAddress = messageHash.recover(
                signature[:65]
            );
            if (recoveredRecoveryAddress == address(0) || recoveredRecoveryAddress != _recovery.recoveryWallet) {
                // immediate failure if recovery address signature is invalid
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

    /**
     * execute a transactions
     */
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc IWallet
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external override(IWallet) authorized {
        _call(dest, value, func);
        emit Execute();
    }

    /// @inheritdoc IWallet
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external override(IWallet) authorized {
        require(dest.length == func.length, "Wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
        }
        emit Execute();
    }

    function updateSigner(
        uint256 newX,
        uint256 newY
    ) external override(IWallet) authorized {
        _signer.x = newX;
        _signer.y = newY;
        emit SignerUpdated(newX, newY);
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

    function updateGuardian(
        address newGuardian
    ) external override(IWallet) authorized {
        _guardian = newGuardian;
        emit GuardianUpdated(newGuardian);
    }

    function requestRecovery(
        uint256 newX,
        uint256 newY
    ) external override(IWallet) authorized {
        require(_recovery.recoveryWallet != address(0), "No recovery set");
        _recoveryRequest = RecoveryRequest({
            newSigner: SigningKey({x: newX, y: newY}),
            requestTime: block.timestamp
        });

        emit RequestRecovery(newX, newY, block.timestamp);
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
        delete _recoveryRequest;

        emit RecoverCompleted(_signer.x, _signer.y);
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
        if (_guardian != address(0)) {
            bytes32 messageHash = signMessage.toEthSignedMessageHash();
            address recoveredGuardian = messageHash.recover(
                signature[:65]
            );
            if (recoveredGuardian != _guardian) {
                // immediate failure if guardian signature is invalid
                return 0x00000000;
            }
            signature = signature[65:];
        }
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
}
