// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Helpers} from '../utils/Helpers.sol';
import {CrossL2Inbox, Identifier, InvalidHash} from 'contracts/CrossL2Inbox.sol';
import {L2ToL2CrossDomainMessenger, TargetCallFailed} from 'contracts/L2ToL2CrossDomainMessenger.sol';
import {Test} from 'forge-std/Test.sol';

/// @notice A simple contract to act as target for the message in a different chain
contract ForTestCounter {
  uint256 internal _a;

  function increaseCounter() external {
    _a++;
  }

  function getCounter() external view returns (uint256 counter_) {
    counter_ = _a;
  }
}

contract IntegrationTest is Test {
  uint256 internal constant _NUM_MESSAGES = 50;

  address internal immutable _RELAYER = makeAddr('Relayer');
  address internal immutable _INBOX_OWNER = makeAddr('Owner');
  address internal immutable _CROSS_L2_INBOX = makeAddr('CrossL2Inbox');
  address internal immutable _L2_TO_L2_CROSS_DOMAIN_MESSENGER = makeAddr('L2ToL2CrossDomainMessenger');
  address internal immutable _TARGET = makeAddr('TargetContract');

  uint256 internal _unichain;
  uint256 internal _optimism;
  uint256 internal _unichainId;
  uint256 internal _optimismId;

  function setUp() external {
    _unichain = vm.createFork(vm.rpcUrl('unichain'), 3_015_172);
    _optimism = vm.createFork(vm.rpcUrl('optimism'), 19_032_508);

    bytes memory _crossL2Inbox = address(new CrossL2Inbox()).code;
    bytes memory _l2ToL2Cdm = address(new L2ToL2CrossDomainMessenger(_CROSS_L2_INBOX)).code;
    bytes memory _target = address(new ForTestCounter()).code;

    // Unichain setup
    vm.selectFork(_unichain);
    _unichainId = block.chainid;
    vm.etch(_CROSS_L2_INBOX, _crossL2Inbox);
    vm.etch(_L2_TO_L2_CROSS_DOMAIN_MESSENGER, _l2ToL2Cdm);
    vm.etch(_TARGET, _target);

    CrossL2Inbox(_CROSS_L2_INBOX).initialize(_INBOX_OWNER);
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).initialize(_INBOX_OWNER);

    vm.prank(_INBOX_OWNER);
    CrossL2Inbox(_CROSS_L2_INBOX).enableRelayer(_RELAYER);

    // Optimism setup
    vm.selectFork(_optimism);
    _optimismId = block.chainid;
    vm.etch(_CROSS_L2_INBOX, _crossL2Inbox);
    vm.etch(_L2_TO_L2_CROSS_DOMAIN_MESSENGER, _l2ToL2Cdm);
    vm.etch(_TARGET, _target);

    CrossL2Inbox(_CROSS_L2_INBOX).initialize(_INBOX_OWNER);
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).initialize(_INBOX_OWNER);

    vm.prank(_INBOX_OWNER);
    CrossL2Inbox(_CROSS_L2_INBOX).enableRelayer(_RELAYER);
  }

  /// @notice Test relaying messages when the hash is valid but the target call fails.
  function test_Integration_invalidTarget() external {
    bytes memory _message = abi.encodeWithSignature('notAFunction()');

    vm.selectFork(_optimism);
    uint256 _nonce = L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).messageNonce();
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).sendMessage(_unichainId, _TARGET, _message);

    // Build Identifier
    Identifier memory _identifier = Identifier({
      origin: _L2_TO_L2_CROSS_DOMAIN_MESSENGER,
      blockNumber: block.number,
      logIndex: 0,
      timestamp: block.timestamp,
      chainId: _optimismId
    });

    bytes memory _payload = Helpers.encodePayload(_unichainId, _TARGET, _nonce, address(this), _message);
    bytes32 _messageHash = keccak256(abi.encode(_identifier, keccak256(_payload)));

    vm.selectFork(_unichain);

    vm.prank(_RELAYER);
    CrossL2Inbox(_CROSS_L2_INBOX).registerValidHash(_messageHash);

    vm.expectRevert(TargetCallFailed.selector);
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).relayMessage(_identifier, _payload);
  }

  /// @notice Test relaying messages between chains when the hash is not registered.
  function test_Integration_invalidHash() external {
    bytes memory _message = abi.encodeCall(ForTestCounter.increaseCounter, ());

    vm.selectFork(_optimism);
    uint256 _nonce = L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).messageNonce();
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).sendMessage(_unichainId, _TARGET, _message);

    // Build Identifier
    Identifier memory _identifier = Identifier({
      origin: _L2_TO_L2_CROSS_DOMAIN_MESSENGER,
      blockNumber: block.number,
      logIndex: 0,
      timestamp: block.timestamp,
      chainId: _optimismId
    });

    bytes memory _payload = Helpers.encodePayload(_unichainId, _TARGET, _nonce, address(this), _message);

    vm.selectFork(_unichain);

    vm.expectRevert(InvalidHash.selector);
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).relayMessage(_identifier, _payload);

    assertEq(ForTestCounter(_TARGET).getCounter(), 0, 'Counter should not have been increased');
  }

  /// @notice Test sending a message from optimism to unichain, the message has a target contract.
  function test_Integration_sendInterchainMessage() external {
    bytes memory _message = abi.encodeCall(ForTestCounter.increaseCounter, ());

    vm.selectFork(_optimism);
    uint256 _nonce = L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).messageNonce();
    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).sendMessage(_unichainId, _TARGET, _message);

    // Build Identifier
    Identifier memory _identifier = Identifier({
      origin: _L2_TO_L2_CROSS_DOMAIN_MESSENGER,
      blockNumber: block.number,
      logIndex: 0,
      timestamp: block.timestamp,
      chainId: _optimismId
    });

    bytes memory _payload = Helpers.encodePayload(_unichainId, _TARGET, _nonce, address(this), _message);
    bytes32 _messageHash = keccak256(abi.encode(_identifier, keccak256(_payload)));

    vm.selectFork(_unichain);

    vm.prank(_RELAYER);
    CrossL2Inbox(_CROSS_L2_INBOX).registerValidHash(_messageHash);

    L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).relayMessage(_identifier, _payload);

    assertEq(ForTestCounter(_TARGET).getCounter(), 1, 'Counter should have been increased');
  }

  function test_sendMultiInterchainMessages(
    bool[_NUM_MESSAGES] memory _shouldMessageSucceed,
    address[_NUM_MESSAGES] memory _accounts
  ) external {
    vm.selectFork(_optimism);

    Identifier[_NUM_MESSAGES] memory _identifiers;
    bytes[_NUM_MESSAGES] memory _payloads;
    bytes32[_NUM_MESSAGES] memory _hashes;

    // counter we can use to compare with _TARGET contract state
    uint256 _successfulMessages;

    for (uint256 _i = 0; _i < _NUM_MESSAGES; _i++) {
      bytes memory _message = _shouldMessageSucceed[_i]
        ? abi.encodeCall(ForTestCounter.increaseCounter, ())
        : abi.encodeWithSignature('InexistentFunction()');

      uint256 _nonce = L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).messageNonce();
      L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).sendMessage(_unichainId, _TARGET, _message);

      // Build Identifier
      Identifier memory _identifier = Identifier({
        origin: _L2_TO_L2_CROSS_DOMAIN_MESSENGER,
        blockNumber: block.number,
        logIndex: 0,
        timestamp: block.timestamp,
        chainId: _optimismId
      });

      _identifiers[_i] = _identifier;

      bytes memory _payload = Helpers.encodePayload(_unichainId, _TARGET, _nonce, address(this), _message);
      _payloads[_i] = _payload;
      _hashes[_i] = keccak256(abi.encode(_identifier, keccak256(_payload)));

      if (_shouldMessageSucceed[_i]) _successfulMessages++;
    }

    vm.selectFork(_unichain);
    for (uint256 _i = 0; _i < _NUM_MESSAGES; _i++) {
      vm.prank(_RELAYER);
      CrossL2Inbox(_CROSS_L2_INBOX).registerValidHash(_hashes[_i]);

      if (!_shouldMessageSucceed[_i]) vm.expectRevert();

      vm.prank(_accounts[_i]);
      L2ToL2CrossDomainMessenger(_L2_TO_L2_CROSS_DOMAIN_MESSENGER).relayMessage(_identifiers[_i], _payloads[_i]);
    }

    assertEq(ForTestCounter(_TARGET).getCounter(), _successfulMessages, 'Counter should have been increased');
  }
}
