// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

library KeyManage {
    struct Key {
        address keyAddress;
        uint256 changeDelay; // in seconds
        // for changing key
        address newKeyAddress;
        uint256 requestTime;
    }

    function createKey(
        Key storage self,
        address keyAddress,
        uint256 changeDelay
    ) internal {
        require(self.keyAddress == address(0), "Key already initialized");
        require(keyAddress != address(0), "Key address cannot be zero");
        self.keyAddress = keyAddress;
        self.changeDelay = changeDelay;
        self.newKeyAddress = address(0);
        self.requestTime = 0;
    }


    function requestKeyChange(Key storage self, address newKeyAddress) internal {
        self.newKeyAddress = newKeyAddress;
        self.requestTime = block.timestamp;
    }

    function confirmKeyChange(Key storage self) internal {
        require(
            self.newKeyAddress != address(0),
            "No key change requested"
        );
        require(
            block.timestamp >= self.requestTime + self.changeDelay,
            "Change delay not passed"
        );

        self.keyAddress = self.newKeyAddress;
        self.newKeyAddress = address(0);
        self.requestTime = 0;
    }

    function cancelKeyChange(Key storage self) internal {
        self.newKeyAddress = address(0);
        self.requestTime = 0;
    }
}
