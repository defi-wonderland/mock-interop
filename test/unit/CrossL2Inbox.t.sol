// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';
import {Initializable} from '@openzeppelin/contracts/proxy/utils/Initializable.sol';
import {CrossL2Inbox, Identifier, InvalidHash, InvalidRelayer, OwnableUpgradeable} from 'contracts/CrossL2Inbox.sol';
import {Test} from 'forge-std/Test.sol';

contract ForTestCrossL2Inbox is CrossL2Inbox {
  /// @notice Test helper function to set the relayer status.
  function forTest_setRelayer(address _RELAYER, bool _status) public {
    validRelayers[_RELAYER] = _status;
  }

  /// @notice Test helper function to set the hash status.
  function forTest_setValidHash(bytes32 _hash, bool _status) public {
    validHashes[_hash] = _status;
  }

  function forTest_authorizeUpgrade(
    address _newOwner
  ) external {
    _authorizeUpgrade(_newOwner);
  }
}

abstract contract Base is Test {
  event UpdatedRelayer(address indexed account, bool isRelayer);
  event RegisteredHash(bytes32 indexed hash);

  address internal immutable _INBOX_OWNER = makeAddr('Inbox Owner');
  address internal immutable _RELAYER = makeAddr('Relayer');
  address internal immutable _UNAUTHORIZED_CALLER = makeAddr('Unauthorized Caller');
  ForTestCrossL2Inbox internal _inbox;
  address internal _implementation;

  function setUp() public virtual {
    _implementation = address(new ForTestCrossL2Inbox());

    _inbox = ForTestCrossL2Inbox(
      address(new ERC1967Proxy(_implementation, abi.encodeWithSelector(CrossL2Inbox.initialize.selector, _INBOX_OWNER)))
    );

    vm.prank(_INBOX_OWNER);
    _inbox.enableRelayer(_RELAYER);
  }
}

contract CrossL2Inbox_Unit_Initialize is Base {
  /// @notice Test that the `initialize` function sets the owner of the inbox.
  function test_intializeNewProxy() public {
    // Deploy a new inbox proxy.
    ForTestCrossL2Inbox _newInbox = ForTestCrossL2Inbox(address(new ERC1967Proxy(_implementation, bytes(''))));

    // Ensure the owner is not set.
    assertEq(_newInbox.owner(), address(0));

    // Initialize the inbox.
    _newInbox.initialize(_INBOX_OWNER);

    // Ensure the owner is set.
    assertEq(_newInbox.owner(), _INBOX_OWNER);
  }

  /// @notice Test that the constructor disables the initialize function on implementation contract.
  function test_initializeAfterDeployment() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    ForTestCrossL2Inbox(_implementation).initialize(_INBOX_OWNER);
  }

  /// @notice Test that the `initialize` function reverts when the inbox is already initialized.
  function test_initializeWhenAlreadyInitialized(
    address _newOwner
  ) public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    _inbox.initialize(_newOwner);
  }

  /// @notice Test that the `initialize` called on `upgradeToAndcall` in the setup function sets the owner of the inbox.
  function test_initializeSetsOwner() public view {
    assertEq(_inbox.owner(), _INBOX_OWNER);
  }
}

contract CrossL2Inbox_Unit_ValidateMessage is Base {
  event ExecutingMessage(bytes32 indexed msgHash, Identifier id);

  /// @notice Test that the `validateMessage` function reverts when the hash is invalid.
  function test_validateCheckHashIsNotTrue(Identifier calldata _id, bytes32 _msgHash) public {
    // it reverts
    // Ensure the hash is not valid.
    _inbox.forTest_setValidHash(keccak256(abi.encode(_id, _msgHash)), false);

    vm.expectRevert(abi.encodeWithSelector(InvalidHash.selector));
    _inbox.validateMessage(_id, _msgHash);
  }

  function test_validateMessageWhenSucceedsEmits(Identifier calldata _id, bytes32 _msgHash) public {
    /// Ensure the hash is valid.
    _inbox.forTest_setValidHash(keccak256(abi.encode(_id, _msgHash)), true);

    vm.expectEmit(address(_inbox));
    emit ExecutingMessage(_msgHash, _id);

    vm.prank(_RELAYER);
    _inbox.validateMessage(_id, _msgHash);
  }
}

contract CrossL2Inbox_Unit_EnableRelayer is Base {
  /// @notice Test that the `enableRelayer` function reverts when the caller is not the owner.
  function test_enableRelayerWhenCallerNotOwner(
    address _newRelayer
  ) public {
    vm.prank(_UNAUTHORIZED_CALLER);
    // it reverts
    vm.expectRevert(
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _UNAUTHORIZED_CALLER)
    );
    _inbox.enableRelayer(_newRelayer);
  }

  /// @notice Test that the `enableRelayer` function sets the relayer status to true.
  function test_enableRelayerWhenSucceeds(
    address _newRelayer
  ) public {
    // it should set validRelayers[_newRelayer] to true
    // Ensure the relayer is not enabled.
    _inbox.forTest_setRelayer(_newRelayer, false);

    vm.expectEmit();
    emit UpdatedRelayer(_newRelayer, true);

    vm.prank(_INBOX_OWNER);
    _inbox.enableRelayer(_newRelayer);
    assertTrue(_inbox.validRelayers(_newRelayer), 'Relayer not enabled');
  }
}

contract CrossL2Inbox_Unit_DisableRelayer is Base {
  /// @notice Test that the `disableRelayer` function reverts when the caller is not the owner.
  function test_disableRelayerWhenCallerNotOwner(
    address _relayerToDisable
  ) public {
    vm.prank(_UNAUTHORIZED_CALLER);
    // it reverts
    vm.expectRevert(
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _UNAUTHORIZED_CALLER)
    );
    _inbox.disableRelayer(_relayerToDisable);
  }

  /// @notice Test that the `disableRelayer` function sets the relayer status to false.
  function test_disableRelayerWhenSucceeds(
    address _relayerToDisable
  ) public {
    // it should set validRelayers[_RELAYER] to false
    // Ensure the relayer is enabled.
    _inbox.forTest_setRelayer(_relayerToDisable, true);

    vm.expectEmit();
    emit UpdatedRelayer(_relayerToDisable, false);

    vm.prank(_INBOX_OWNER);
    _inbox.disableRelayer(_relayerToDisable);
    assertFalse(_inbox.validRelayers(_relayerToDisable), 'Relayer not disabled');
  }
}

contract CrossL2Inbox_Unit_RegisterValidHash is Base {
  /// @notice Test that the `registerValidHash` function reverts when the caller is not a relayer.
  function test_registerValidHashWhenCallerNotRelayer(
    bytes32 _hash
  ) public {
    _inbox.forTest_setValidHash(_hash, false);
    // it reverts
    vm.prank(_UNAUTHORIZED_CALLER);
    vm.expectRevert(abi.encodeWithSelector(InvalidRelayer.selector));
    _inbox.registerValidHash(_hash);
  }

  /// @notice Test that the `registerValidHash` function registers a valid hash.
  function test_registerValidHashWhenSucceeds(
    bytes32 _hash
  ) public {
    vm.expectEmit();
    emit RegisteredHash(_hash);

    vm.prank(_RELAYER);
    _inbox.registerValidHash(_hash);
    assertTrue(_inbox.validHashes(_hash), 'Hash not registered');
  }
}

contract CrossL2Inbox_Unit_AuthorizeUpgrade is Base {
  /// @notice Test authorizeUpgrade reverts if the sender is not the owner
  function test_authorizeUpgradeWhenNotOwner(
    address _sender
  ) external {
    vm.prank(_UNAUTHORIZED_CALLER);
    vm.expectRevert(
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _UNAUTHORIZED_CALLER)
    );
    _inbox.forTest_authorizeUpgrade(_sender);
  }

  /// @notice Test authorizeUpgrade if the sender is the owner
  function test_authorizeUpgradeWhenOwner() external {
    vm.prank(_INBOX_OWNER);
    _inbox.forTest_authorizeUpgrade(_INBOX_OWNER);
  }
}
