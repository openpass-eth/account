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
contract DelegateAccount is IERC1271, BaseAccount, DefaultCallbackHandler {
    using Address for address;

    IEntryPoint private immutable _entryPoint;

    bytes32 constant SET_SIGNING_KEY_TYPEHASH =
        keccak256(
            "SetSigningKey(bytes signers,uint256 nonce)"
        );

    struct SigningKey {
        uint256 x; // for passkey
        uint256 y;
    }

    struct AccountStorage {
        uint256 nonce;
        SigningKey[] keys;
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

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes4 magic = isValidSignature(
            userOpHash,
            userOp.signature
        );

        if (magic == IERC1271.isValidSignature.selector) {
            return 0;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    /**
     * @notice only accept entrypoint or self call
     */
    function _isValidCaller() internal view returns (bool) {
        return
            msg.sender == address(entryPoint()) || msg.sender == address(this);
    }

    modifier authorized() {
        require(_isValidCaller(), "Wallet: Invalid Caller");
        _;
    }

    function setSigningKey(
        bytes memory signers,
        uint256 nonce,
        bytes memory ownerSignature
    ) public {
        AccountStorage storage ds = _getAccountStorage();
        require(ds.nonce < nonce, "Wallet: invalid nonce");

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
            ds.keys.push(initialSigners[i]);
        }
        ds.nonce = nonce;
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
            SigningKey memory signer = ds.keys[keyId];
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
