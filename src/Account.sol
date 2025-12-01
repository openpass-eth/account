// SPDX-License-Identifier: Apache
pragma solidity 0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import "openzeppelin/utils/StorageSlot.sol";
import "openzeppelin/proxy/utils/UUPSUpgradeable.sol";
import "openzeppelin/interfaces/IERC1271.sol";
import "openzeppelin/utils/cryptography/SignatureChecker.sol";
import "openzeppelin/utils/Address.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";

import "./libraries/DefaultCallbackHandler.sol";

import {WebAuthn} from "./libraries/WebAuthn.sol";

/**
 * @title Account
 * @author imduchuyyy
 * @notice This contract represents a Wallet in the system.
 */
contract Account is
    IERC1271,
    BaseAccount,
    DefaultCallbackHandler
{
    using Address for address;

    IEntryPoint private immutable _entryPoint;

    bytes32 constant SET_SIGNING_KEY_TYPEHASH =
        keccak256(
            "SetSigningKey(bytes signers,uint256 nonce)"
        );

    bytes32 constant SET_SPEND_LIMITS_TYPEHASH =
        keccak256(
            "SetSpendLimits(bytes spendLimits,uint256 nonce)"
        );

    struct SigningKey {
        uint256 x; // for passkey
        uint256 y;
    }

    struct SpendLimit {
        address token;
        uint256 amount;
        uint256 period; // in seconds
        uint256 spentAmount;
    }

    struct Signers {
        uint256 nonce;
        SigningKey[] keys;
    }

    struct SpendLimits {
        uint256 nonce;
        SpendLimit[] limits;
    }

    struct AccountStorage {
        bool initialized;
        Signers signers;
        SpendLimits spendLimits;
    }

    constructor(address entryPointAddress) {
        _entryPoint = IEntryPoint(entryPointAddress);
    }

    function _getAccountStorage() internal pure returns (AccountStorage storage ds) {
        bytes32 position = keccak256("account.storage");
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice This function is used to initialize the wallet with an initial key.
     */
    function initialize(
        bytes memory signers,
        uint256 nonce,
        bytes calldata ownerSignature
    ) external {
        AccountStorage storage ds = _getAccountStorage();
        require(!ds.initialized, "Wallet: already initialized");

        setSigningKey(signers, nonce, ownerSignature);

        ds.initialized = true;
    }

    modifier authorized() {
        require(_isValidCaller(), "Wallet: Invalid Caller");
        _;
    }

    function setSigningKey(
        bytes memory signers,
        uint256 nonce,
        bytes calldata ownerSignature
    ) public {
        AccountStorage storage ds = _getAccountStorage();
        require(nonce > ds.signers.nonce, "Wallet: invalid nonce");

        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encode(
                    SET_SIGNING_KEY_TYPEHASH, 
                    signers, 
                    nonce
                )
            )
        );

        require(
            SignatureChecker.isValidSignatureNow(
                address(this),
                messageHash,
                ownerSignature
            ),
            "Wallet: invalid owner signature"
        );

        SigningKey[] memory initialSigners = abi.decode(signers, (SigningKey[]));
        for (uint256 i = 0; i < initialSigners.length; i++) {
            ds.signers.keys.push(initialSigners[i]);
        }
        ds.signers.nonce = nonce;
    }

    function setSpendLimits(
        bytes memory spendLimits,
        uint256 nonce,
        bytes calldata ownerSignature
    ) external {
        AccountStorage storage ds = _getAccountStorage();
        require(nonce > ds.spendLimits.nonce, "Wallet: invalid nonce");

        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encode(
                    SET_SPEND_LIMITS_TYPEHASH, 
                    spendLimits, 
                    nonce
                )
            )
        );

        require(
            SignatureChecker.isValidSignatureNow(
                address(this),
                messageHash,
                ownerSignature
            ),
            "Wallet: invalid owner signature"
        );

        SpendLimit[] memory limits = abi.decode(spendLimits, (SpendLimit[]));
        for (uint256 i = 0; i < limits.length; i++) {
            ds.spendLimits.limits.push(limits[i]);
        }
        ds.spendLimits.nonce = nonce;
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        uint8 keyId = uint8(bytes1(userOp.signature[:1]));
        bytes calldata signature = userOp.signature[1:];
        if (keyId == uint8(0)) {
            // use address(this) as a signer
            bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
                userOpHash
            );

            if (
                SignatureChecker.isValidSignatureNow(
                    address(this),
                    messageHash,
                    signature[:65]
                )
            ) {
                return 0;
            } else {
                return 1;
            }
        } else {
            AccountStorage storage ds = _getAccountStorage();
            SigningKey memory signer = ds.signers.keys[keyId];
            if (signer.x == 0 && signer.y == 0) {
                return 1;
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
                validationData = 1;
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
        uint8 keyId = uint8(bytes1(signature[:1]));
        bytes memory trueSignature = signature[1:];
        if (keyId == uint8(0)) {
            // use address(this) as a signer
            bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
                signMessage
            );

            if (
                SignatureChecker.isValidSignatureNow(
                    address(this),
                    messageHash,
                    trueSignature
                )
            ) {
                return IERC1271.isValidSignature.selector;
            } else {
                return 0xffffffff;
            }
        } else {
            AccountStorage storage ds = _getAccountStorage();
            SigningKey memory signer = ds.signers.keys[keyId];
            if (signer.x == 0 && signer.y == 0) {
                return 0xffffffff;
            }
            WebAuthn.WebAuthnAuth memory auth = abi.decode(
                trueSignature,
                (WebAuthn.WebAuthnAuth)
            );
            if (
                WebAuthn.verify({
                    challenge: abi.encode(signMessage),
                    requireUV: false,
                    webAuthnAuth: auth,
                    x: signer.x,
                    y: signer.y
                })
            ) {
                return IERC1271.isValidSignature.selector;
            } else {
                return 0xffffffff;
            }
        }
    }
}
