// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "openzeppelin/utils/introspection/ERC165.sol";
import "openzeppelin/interfaces/IERC721Receiver.sol";
import "openzeppelin/interfaces/IERC1155Receiver.sol";
import "openzeppelin/interfaces/IERC777Recipient.sol";

contract DefaultCallbackHandler is IERC721Receiver, IERC1155Receiver, IERC777Recipient, ERC165 {
    event ReceiveETH(address sender, uint256 amount);
  
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return 0xbc197c81;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return 0x150b7a02;
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {
        // We implement this for completeness, doesn't really have any value
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC165) returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId || super.supportsInterface(interfaceId);
    }

    fallback() external payable {}
    receive() external payable {
        emit ReceiveETH(msg.sender, msg.value);
    }
}
