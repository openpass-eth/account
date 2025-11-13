// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

abstract contract KeyManager {
    struct SigningKey {
        uint256 x; // for passkey
        uint256 y;
    }

    // passkey owner and recovery
    struct OwnerData {
        SigningKey ownerKey;
        uint256 changeDelay; // in seconds
        // for changing owner
        address recoveryAddress;
        SigningKey newOwnerKey;
        uint256 requestTime;
    }

    // 2fa guardian
    struct GuardianData {
        address guardianAddress;
        uint256 changeDelay; // in seconds
        // for changing guardian
        address newGuardianAddress;
        uint256 requestTime;
    }

    GuardianData internal _guardianData;
    OwnerData internal _ownerData;

    event GuardianChange(address indexed newGuardian);
    event GuardianChangeCancelled();
    event GuardianChangeRequested(address indexed newGuardian, uint256 requestTime);

    function _setGuardian(address initialGuardian, uint256 changeDelay) internal {
        require(initialGuardian != address(0), "Guardian: initial guardian is the zero address");
        require(guardian == address(0), "Guardian: guardian already set");
        _guardianData.guardianAddress = initialGuardian;
        _guardianData.changeDelay = changeDelay;
        _guardianData.newGuardianAddress = address(0);
        _guardianData.requestTime = 0;
    }

    // with guardian approval
    function _updateGuardian(address newGuardian) internal {
        require(newGuardian != address(0), "Guardian: new guardian is the zero address");
        _guardianData.guardianAddress = newGuardian;
        emit GuardianChanged(newGuardian);
    }

    function _requestUpdateGuardian(address newGuardian) internal {
        require(newGuardian != address(0), "Guardian: new guardian is the zero address");
        _guardianData.newGuardianAddress = newGuardian;
        _guardianData.requestTime = block.timestamp;
        emit GuardianChangeRequested(newGuardian, block.timestamp);
    }

    function _cancelUpdateGuardian() internal {
        require(
            _guardianData.newGuardianAddress != address(0),
            "Guardian: no guardian change requested"
        );
        // reset request data
        _guardianData.newGuardianAddress = address(0);
        _guardianData.requestTime = 0;

        emit GuardianChangeCancelled();
    }

    function _confirmUpdateGuardian() internal {
        require(
            _guardianData.newGuardianAddress != address(0),
            "Guardian: no guardian change requested"
        );
        require(
            block.timestamp >=
                _guardianData.requestTime + _guardianData.changeDelay,
            "Guardian: change delay not passed"
        );

        _guardianData.guardianAddress = _guardianData.newGuardianAddress;

        // reset request data
        _guardianData.newGuardianAddress = address(0);
        _guardianData.requestTime = 0;

        emit GuardianChanged(newGuardian);
    }

    function _setRecovery(address recoveryAddress, uint256 changeDelay) internal {
        require(recoveryAddress != address(0), "Guardian: recovery address is the zero address");
        require(changeDelay > 1 days, "Guardian: change delay too short");
        _ownerData.recoveryAddress = recoveryAddress;
        _ownerData.changeDelay = changeDelay;
    }

    function _requestOwnerKeyChange(SigningKey memory newOwnerKey) internal {
        _ownerData.newOwnerKey = newOwnerKey;
        _ownerData.requestTime = block.timestamp;
    }

    function _cancelOwnerKeyChange() internal {
        require(
            _ownerData.newOwnerKey.x != 0 && _ownerData.newOwnerKey.y != 0,
            "Guardian: no owner key change requested"
        );
        // reset request data
        _ownerData.newOwnerKey = SigningKey({x: 0, y: 0});
        _ownerData.requestTime = 0;
    }

    function _confirmOwnerKeyChange() internal {
        require(
            _ownerData.newOwnerKey.x != 0 && _ownerData.newOwnerKey.y != 0,
            "Guardian: no owner key change requested"
        );
        require(
            block.timestamp >=
                _ownerData.requestTime + _ownerData.changeDelay,
            "Guardian: change delay not passed"
        );

        _ownerData.ownerKey = _ownerData.newOwnerKey;

        // reset request data
        _ownerData.newOwnerKey = SigningKey({x: 0, y: 0});
        _ownerData.requestTime = 0;
    }
}
