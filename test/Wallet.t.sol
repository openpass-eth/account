// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "account-abstraction/core/EntryPoint.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../src/WalletFactory.sol";
import "../src/modules/Passkey.sol";
import "../src/Wallet.sol";
import "./utils/ERC4337Utils.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

using ERC4337Utils for EntryPoint;

contract WalletTest is Test {
    EntryPoint entryPoint;
    WalletFactory walletFactory;
    Wallet wallet;

    address owner;
    uint256 ownerKey;

    address payable beneficiary;

    // function setUp() external {
    //     ownerKey = uint256(keccak256("owner"));
    //     owner = vm.addr(ownerKey);
    //     entryPoint = new EntryPoint();

    //     walletFactory = new WalletFactory(address(entryPoint));
    //     beneficiary = payable(address(vm.addr(uint256(keccak256("beneficiary")))));

    //     wallet = Wallet(walletFactory.getWalletAddress(bytes32(uint256(1))));

    //     vm.deal(address(wallet), 1 ether);

    //     UserOperation memory op = entryPoint.fillUserOp(address(wallet), "");
    //     op.initCode = abi.encodePacked(
    //         bytes20(address(walletFactory)),
    //         abi.encodeWithSelector(walletFactory.createWallet.selector, owner, bytes32(uint256(1)))
    //     );
    //     op.signature = abi.encodePacked(bytes20(owner), entryPoint.signUserOpHash(vm, ownerKey, op));

    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;

    //     entryPoint.handleOps(ops, beneficiary);
    // }

    // function testWalletPasskey() external {
    //     bytes32 salt = keccak256("testCreateWalletWithPasskey");
    //     PasskeyModule passkeyModule = walletFactory.createPasskey(
    //         28203248099655634232680422976510411012986437076966613883671554831358983509938,
    //         79473938854726638551736530376995476499049493858003728502280535141260854783821,
    //         salt
    //     );

    //     UserOperation memory op = entryPoint.fillUserOp(address(0), "");
    //     bytes memory signature =
    //         hex"00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001eb6f6689e7b96f60dcae3542888f9d094a9abb8e04bd391104d6ee79a9f0967d3bc293dc51c51b23f9063ae81bb2e4a99b520f5f04cda804f0dd80b4c8d7f353000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000867b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22644c4836595a6f78345332616a6f4e4a384c374d47734657436c75584c6258514a62306e466c7377685930222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303030222c2263726f73734f726967696e223a66616c73657d0000000000000000000000000000000000000000000000000000";
    //     op.signature = abi.encodePacked(address(passkeyModule), signature);
        
    //     vm.startPrank(address(entryPoint));

    //     wallet.addKey(address(passkeyModule));
    //     uint256 valid = wallet.validateUserOp(op, 0x74b1fa619a31e12d9a8e8349f0becc1ac1560a5b972db5d025bd27165b30858d, 0);

    //     console.log("valid", valid);

    // }

    // function test_SendEth() external {
    //     vm.deal(address(wallet), 1 ether);

    //     UserOperation memory op = entryPoint.fillUserOp(address(wallet), "");
    //     op.callData = abi.encodeWithSelector(wallet.execute.selector, beneficiary, 1, "");
    //     op.signature = abi.encodePacked(bytes20(owner), entryPoint.signUserOpHash(vm, ownerKey, op));

    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;

    //     entryPoint.handleOps(ops, beneficiary);
    // }

    // function test_setKey() external {
    //     uint256 owner2 = uint256(keccak256("owner2"));
    //     address owner2Address = vm.addr(owner2);

    //     vm.deal(address(wallet), 1 ether);

    //     UserOperation memory op = entryPoint.fillUserOp(address(wallet), "");
    //     op.callData = abi.encodeWithSelector(wallet.addKey.selector, owner2Address, uint256(0));
    //     op.signature = abi.encodePacked(bytes20(owner), entryPoint.signUserOpHash(vm, ownerKey, op));

    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;

    //     entryPoint.handleOps(ops, beneficiary);
    //     require(wallet.isValidKey(owner2Address), "Fail to add key");
    //     _logKey();
    // }

    // function test_removeKey() external {
    //     uint256 owner2 = uint256(keccak256("owner2"));
    //     address owner2Address = vm.addr(owner2);

    //     vm.deal(address(wallet), 1 ether);

    //     UserOperation memory op = entryPoint.fillUserOp(address(wallet), "");
    //     op.callData = abi.encodeWithSelector(wallet.addKey.selector, owner2Address, uint256(0));
    //     op.signature = abi.encodePacked(bytes20(owner), entryPoint.signUserOpHash(vm, ownerKey, op));

    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;

    //     entryPoint.handleOps(ops, beneficiary);
    //     require(wallet.isValidKey(owner2Address), "Fail to add key");
    //     _logKey();

    //     op.nonce = entryPoint.getNonce(address(wallet), 0);
    //     op.initCode = "";
    //     op.callData = abi.encodeWithSelector(wallet.removeKey.selector, address(0x1), owner2Address, uint256(0));
    //     op.signature = abi.encodePacked(bytes20(owner), entryPoint.signUserOpHash(vm, ownerKey, op));
    //     ops[0] = op;

    //     entryPoint.handleOps(ops, beneficiary);
    //     require(!wallet.isValidKey(owner2Address), "Fail to add key");
    //     _logKey();
    // }

    // // function testPasskeySigner() external {
    // //     bytes32 salt = 0x928c5170d19f5bfc6e4e688388ee5698d6433f0629b216ee89bab1fe65aa92e1;
    // //     console.logBytes32(salt);
    // //     uint256 x = 57354212301228404074007314998280670312526661933892141818826008780783055520895;
    // //     uint256 y = 25303925085401504347584682025814887674906274142473434094161374620451608452689;

    // //     EntryPoint realWorldEntryPoint = EntryPoint(payable(0x7e33db170e8b1FF05599064405fdF1F06b7d7D75));
    // //     WalletFactory realWorldFactory = WalletFactory(0x4077317dbD603DB74a96808C70545302f833965E);

    // //     Wallet realWorldWallet = Wallet(realWorldFactory.getWalletAddress(salt));
    // //     PasskeyModule realWorldPasskey = realWorldFactory.createPasskey(x, y, salt);

    // //     console.log(address(realWorldPasskey));

    // //     UserOperation memory op = entryPoint.fillUserOp(address(realWorldWallet), "");
    // //     op.initCode = hex'2094DC38C48F12BFd6B3732695Ba23673e2Bd38480d1bfde7ecd55725b011adf060acd7d4ea294360d148717f9f9567d6920c5861fc7c47f37f18399a20f8fa5deac08f455d6e56b32d3aabf8f889bb04c1ccc9bfe5bde51928c5170d19f5bfc6e4e688388ee5698d6433f0629b216ee89bab1fe65aa92e1';
    // //     op.callData = hex'b61d27f6000000000000000000000000674a25787b18938919bd84f37f0f774651a0c40f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000';
    // //     op.signature = hex'F1cBf96412c21F66C31eC93cE43E86fEd8473dE100000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001bde8ddcdc6b370a2d51cf9e0c33cd1af2b3db4c2cac6137da3220e03d48a707e84c9df7c4b2fb740de3e2095f16a2f6b408efb65580faee269e7250fd2aaa6b5000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000867b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226a5f4361324730484c656959344f6a38444152356643536c3552483776424253514e734141722d57763877222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303030222c2263726f73734f726967696e223a66616c73657d0000000000000000000000000000000000000000000000000000';

    // //     bytes32 digest = realWorldEntryPoint.getUserOpHash(op);

    // //     console.logBytes32(digest);

    // //     UserOperation[] memory ops = new UserOperation[](1);
    // //     ops[0] = op;

    // //     uint256 value = realWorldPasskey.validateUserOp(op, 0x8ff09ad86d072de898e0e8fc0c04797c24a5e511fbbc105240db0002bf96bfcc);
    // //     console.log(value);

    // //     // realWorldEntryPoint.handleOps(ops, beneficiary);
    // // }

    // function _logKey() internal view {
    //     address[] memory keys = wallet.getKeys();

    //     console.log("Keys of", address(wallet));
    //     for (uint256 i; i < keys.length; i++) {
    //         console.log("-----", keys[i]);
    //     }
    // }
}
