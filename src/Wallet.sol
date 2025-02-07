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
        address signer; // for address
        uint256 x; // for passkey
        uint256 y;
    }

    mapping(bytes32 => SigningKey) private _signingKeys;
    address private _recoveryAddress;
    string private _walletData;

    constructor(address entryPointAddress) {
        _entryPoint = IEntryPoint(entryPointAddress);
    }

    /**
     * @notice This function is used to initialize the wallet with an initial key.
     */
    function __Wallet_init(
        bytes32 keyId,
        address signer,
        uint256 x,
        uint256 y,
        address recoveryAddress,
        string memory walletData
    ) external initializer {
        _signingKeys[keyId].signer = signer;
        _signingKeys[keyId].x = x;
        _signingKeys[keyId].y = y;

        _recoveryAddress = recoveryAddress;
        _walletData = walletData;
    }

    modifier authorized() {
        require(_isValidCaller(), "Wallet: Invalid Caller");
        _;
    }

    modifier authorizedOrRecoveryAddress() {
        require(
            _isValidCaller() || msg.sender == _recoveryAddress,
            "Wallet: Invalid Caller"
        );
        _;
    }

    function _authorizeUpgrade(address) internal override authorized {}

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes32 keyId = bytes32(userOp.signature[:32]);
        bytes memory trueSignature = userOp.signature[32:];

        if (_signingKeys[keyId].signer != address(0)) {
            bytes32 hash = userOpHash.toEthSignedMessageHash();
            if (hash.recover(trueSignature) == _signingKeys[keyId].signer) {
                validationData = 0;
            } else {
                validationData = SIG_VALIDATION_FAILED;
            }
        } else {
            WebAuthn.WebAuthnAuth memory auth = abi.decode(
                trueSignature,
                (WebAuthn.WebAuthnAuth)
            );
            if (
                WebAuthn.verify({
                    challenge: abi.encode(userOpHash),
                    requireUV: false,
                    webAuthnAuth: auth,
                    x: _signingKeys[keyId].x,
                    y: _signingKeys[keyId].y
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

    function addKey(
        bytes32 keyId,
        SigningKey memory signingKey,
        string memory walletData
    ) external authorizedOrRecoveryAddress {
        _signingKeys[keyId] = signingKey;
        _walletData = walletData;
    }

    function removeKey(
        bytes32 keyId,
        string memory walletData
    ) external authorizedOrRecoveryAddress {
        delete _signingKeys[keyId];
        _walletData = walletData;
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
        bytes32 keyId = bytes32(signature[:32]);
        bytes memory trueSignature = signature[32:];

        if (_signingKeys[keyId].signer != address(0)) {
            bytes32 hash = signMessage.toEthSignedMessageHash();
            if (hash.recover(trueSignature) == _signingKeys[keyId].signer) {
                magicValue = this.isValidSignature.selector;
            } else {
                magicValue = 0;
            }
        } else {
            WebAuthn.WebAuthnAuth memory auth = abi.decode(
                trueSignature,
                (WebAuthn.WebAuthnAuth)
            );
            if (
                WebAuthn.verify({
                    challenge: abi.encode(signMessage),
                    requireUV: false,
                    webAuthnAuth: auth,
                    x: _signingKeys[keyId].x,
                    y: _signingKeys[keyId].y
                })
            ) {
                magicValue = this.isValidSignature.selector;
            } else {
                magicValue = 0;
            }
        }
    }
}
