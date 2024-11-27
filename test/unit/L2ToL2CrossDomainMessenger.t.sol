// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Helpers} from '../utils/Helpers.sol';
import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';
import {Initializable} from '@openzeppelin/contracts/proxy/utils/Initializable.sol';
import {CrossL2Inbox, Identifier, InvalidHash} from 'contracts/CrossL2Inbox.sol';
import {
  EventPayloadNotSentMessage,
  IdOriginNotL2ToL2CrossDomainMessenger,
  L2ToL2CrossDomainMessenger,
  MessageAlreadyRelayed,
  MessageDestinationNotRelayChain,
  MessageDestinationSameChain,
  MessageTargetCrossL2Inbox,
  MessageTargetL2ToL2CrossDomainMessenger,
  OwnableUpgradeable,
  TargetCallFailed,
  TransientReentrancyAware
} from 'contracts/L2ToL2CrossDomainMessenger.sol';
import {Test} from 'forge-std/Test.sol';
import {Hashing} from 'optimism/src/libraries/Hashing.sol';

contract ForTestL2ToL2CrossDomainMessenger is L2ToL2CrossDomainMessenger {
  constructor(
    address _inbox
  ) L2ToL2CrossDomainMessenger(_inbox) {}

  function forTest_setSuccessfulMessage(bytes32 _messageHash, bool _relayed) external {
    successfulMessages[_messageHash] = _relayed;
  }

  function forTest_storeMessageMetadata(uint256 _source, address _sender) external {
    assembly {
      tstore(CROSS_DOMAIN_MESSAGE_SENDER_SLOT, _sender)
      tstore(CROSS_DOMAIN_MESSAGE_SOURCE_SLOT, _source)
    }
  }

  function forTest_setEntered(
    uint256 _entered
  ) external {
    assembly {
      tstore(ENTERED_SLOT, _entered)
    }
  }

  function forTest_entered() external view returns (bool entered_) {
    entered_ = _entered();
  }

  function forTest_authorizeUpgrade(
    address _newOwner
  ) external {
    _authorizeUpgrade(_newOwner);
  }
}

abstract contract Base is Test {
  /// @notice Added so we can filter out these as valid targets for messages
  address internal constant _CHEATCODES_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
  address internal constant _CONSOLE_ADDRESS = 0x000000000000000000636F6e736F6c652e6c6f67;

  address internal immutable _MESSENGER_OWNER = makeAddr('Messenger Owner');
  address internal immutable _UNAUTHORIZED_CALLER = makeAddr('Unauthorized Caller');
  address internal immutable _MOCK_INBOX = makeAddr('CrossL2Inbox');
  ForTestL2ToL2CrossDomainMessenger internal _cdm;
  address internal _implementation;

  function setUp() external {
    _implementation = address(new ForTestL2ToL2CrossDomainMessenger(_MOCK_INBOX));

    _cdm = ForTestL2ToL2CrossDomainMessenger(
      address(
        new ERC1967Proxy(
          _implementation, abi.encodeWithSelector(L2ToL2CrossDomainMessenger.initialize.selector, _MESSENGER_OWNER)
        )
      )
    );
  }

  function _mockAndExpect(address _target, bytes memory _calldata, bytes memory _returnValue) internal {
    vm.mockCall(_target, _calldata, _returnValue);
    vm.expectCall(_target, _calldata);
  }
}

contract L2ToL2CrossDomainMessenger_Unit_Constructor is Base {
  /// @notice Test constructor sets CROSS_L2_INBOX
  function test_constructor(
    address _crossL2Inbox
  ) external {
    vm.assume(_crossL2Inbox != address(0));
    L2ToL2CrossDomainMessenger _crossDomainMessenger = new L2ToL2CrossDomainMessenger(_crossL2Inbox);

    assertEq(_crossDomainMessenger.CROSS_L2_INBOX(), _crossL2Inbox, 'Incorrect CROSS_L2_INBOX');
  }
}

contract L2ToL2CrossDomainMessenger_Unit_Intialize is Base {
  /// @notice Test that the `initialize` function sets the owner of the inbox.
  function test_intializeNewProxy() public {
    // Deploy a new messenger proxy.
    ForTestL2ToL2CrossDomainMessenger _newMessenger =
      ForTestL2ToL2CrossDomainMessenger(address(new ERC1967Proxy(_implementation, bytes(''))));

    // Ensure the owner is not set.
    assertEq(_newMessenger.owner(), address(0));

    // Initialize the inbox.
    _newMessenger.initialize(_MESSENGER_OWNER);

    // Ensure the owner is set.
    assertEq(_newMessenger.owner(), _MESSENGER_OWNER);
  }

  /// @notice Test that the constructor disables the initialize function on implentation contract.
  function test_initializeAfterDeployment() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    L2ToL2CrossDomainMessenger(_implementation).initialize(_MESSENGER_OWNER);
  }

  /// @notice Test initialize reverts if the contract is already initialized
  function test_initializeWhenIsInitialized() external {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    _cdm.initialize(_MESSENGER_OWNER);
  }

  /// @notice Test initialize sets the owner at deployment
  function test_initializeSetsOwner() external view {
    assertEq(_cdm.owner(), _MESSENGER_OWNER);
  }
}

contract L2ToL2CrossDomainMessenger_Unit_CrossDomainMessageSender is Base {
  /// @notice Test that the sender is correctly set in the transient storage
  function test_crossDomainMessageSenderReturnsCorrect(
    address _sender
  ) external {
    _cdm.forTest_setEntered(1);
    assertTrue(_cdm.forTest_entered(), 'Not entered');
    _cdm.forTest_storeMessageMetadata(0, _sender);
    assertEq(_cdm.crossDomainMessageSender(), _sender, 'Incorrect sender');
  }

  /// @notice Test that crossDomainMessageSender reverts if not called in the middle of `relayMessage` or `sendMessage`
  function test_crossDomainMessageSenderWhenNotEnteredReverts() external {
    vm.expectRevert();
    _cdm.crossDomainMessageSender();
  }
}

contract L2ToL2CrossDomainMessenger_Unit_CrossDomainMessageSource is Base {
  /// @notice Test that the source chain is correctly set in the transient storage
  function test_crossDomainMessageSourceReturnsCorrect(
    uint256 _source
  ) external {
    _cdm.forTest_setEntered(1);
    _cdm.forTest_storeMessageMetadata(_source, address(0));
    assertEq(_cdm.crossDomainMessageSource(), _source, 'Incorrect source');
  }

  /// @notice Test that crossDomainMessageSource reverts if not called in the middle of `relayMessage` or `sendMessage`
  function test_crossDomainMessageSourceWhenNotEnteredReverts() external {
    vm.expectRevert();
    _cdm.crossDomainMessageSource();
  }
}

contract L2ToL2CrossDomainMessenger_Unit_CrossDomainMessageContext is Base {
  /// @notice Test that the sender and source chain are correctly set in the transient storage
  function test_crossDomainMessageContextReturnsCorrect(uint256 _source, address _sender) external {
    _cdm.forTest_setEntered(1);
    _cdm.forTest_storeMessageMetadata(_source, _sender);
    (address _storedSender, uint256 _storedSource) = _cdm.crossDomainMessageContext();
    assertEq(_storedSender, _sender, 'Incorrect sender');
    assertEq(_storedSource, _source, 'Incorrect source');
  }

  /// @notice Test that crossDomainMessageContext reverts if not called in the middle of `relayMessage` or `sendMessage`
  function test_crossDomainMessageContextWhenNotEnteredReverts() external {
    vm.expectRevert();
    _cdm.crossDomainMessageContext();
  }
}

contract L2ToL2CrossDomainMessenger_Unit_SendMessage is Base {
  // Event sent on sendMessage success
  event SentMessage(
    uint256 indexed destination, address indexed target, uint256 indexed messageNonce, address sender, bytes message
  );

  /// @notice Test sendMessage reverts if sending a message to the same chain
  function test_sendMessageWhenDestinationSameChain(address _target, bytes memory _message) external {
    // it reverts
    uint256 _thisChainId = block.chainid;

    vm.expectRevert(MessageDestinationSameChain.selector);
    _cdm.sendMessage(_thisChainId, _target, _message);
  }

  /// @notice Test sendMessage reverts if sending a message with CrossL2Inbox as target
  function test_sendMessageWhenTargetIsInbox(uint256 _destinationChain, bytes memory _message) external {
    // it reverts
    vm.assume(_destinationChain != block.chainid);
    address _target = address(_MOCK_INBOX);

    vm.expectRevert(MessageTargetCrossL2Inbox.selector);
    _cdm.sendMessage(_destinationChain, _target, _message);
  }

  /// @notice Test sendMessage reverts if sending a message with L2ToL2CrossDomainMessenger as target
  function test_sendMessageWhenTargetIsCrossDomainMessenger(uint256 _destinationChain, bytes memory _message) external {
    vm.assume(_destinationChain != block.chainid);
    address _target = address(_cdm);

    vm.expectRevert(MessageTargetL2ToL2CrossDomainMessenger.selector);
    _cdm.sendMessage(_destinationChain, _target, _message);
  }

  /// @notice Test sendMessage emits SentMessage event on success
  function test_sendMessageWhenSucceeds(uint256 _destId, address _target, bytes memory _data) external {
    vm.assume(_destId != block.chainid);
    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    uint256 _nonceBefore = _cdm.messageNonce();

    vm.expectEmit(address(_cdm));
    emit SentMessage(_destId, _target, _nonceBefore, address(this), _data);

    bytes32 _expectedHash = Hashing.hashL2toL2CrossDomainMessage({
      _destination: _destId,
      _source: block.chainid,
      _nonce: _nonceBefore,
      _sender: address(this),
      _target: _target,
      _message: _data
    });

    bytes32 _hash = _cdm.sendMessage(_destId, _target, _data);

    assertEq(_expectedHash, _hash);
    assertEq(_cdm.messageNonce(), _nonceBefore + 1);
  }
}

contract L2ToL2CrossDomainMessenger_Unit_RelayMessage is Base {
  // Event sent on relayMessage success
  event RelayedMessage(uint256 indexed source, uint256 indexed messageNonce, bytes32 indexed messageHash);

  /// @notice Test relayMessage can not be re-entered
  function test_relayMessageWhenEntered(
    Identifier memory _id
  ) external {
    // it reverts
    _cdm.forTest_setEntered(1);

    vm.expectRevert(TransientReentrancyAware.ReentrantCall.selector);
    _cdm.relayMessage(_id, bytes(''));
  }

  /// @notice Test relayMessage reverts if the message was not originated in the CDM
  function test_relayMessageWhenOriginNotCrossDomainMessenger(
    Identifier memory _id
  ) external {
    // it reverts
    vm.assume(_id.origin != address(_cdm));

    vm.expectRevert(IdOriginNotL2ToL2CrossDomainMessenger.selector);
    _cdm.relayMessage(_id, bytes(''));
  }

  /// @notice Test relayMessage reverts if wrong event signature prefixes payload
  function test_relayMessageWhenWrongEventPrefix(
    Identifier memory _id,
    address _target,
    address _sender,
    uint256 _nonce,
    bytes memory _message
  ) external {
    // it reverts
    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    _id.origin = address(_cdm);

    bytes memory _payload = abi.encodePacked(
      keccak256(abi.encodeWithSignature('NotSentMessage()')),
      abi.encode(_id.chainId, _target, _nonce),
      abi.encode(_sender, _message)
    );

    bytes32 _messageHash = Hashing.hashL2toL2CrossDomainMessage({
      _destination: block.chainid,
      _source: _id.chainId,
      _nonce: _nonce,
      _sender: _sender,
      _target: _target,
      _message: _message
    });

    _cdm.forTest_setSuccessfulMessage(_messageHash, true);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.expectRevert(EventPayloadNotSentMessage.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if this chain is not the destination chain on the message
  function test_relayMessageWhenDestinationNotThisChain(
    Identifier memory _id,
    address _target,
    bytes memory _message,
    uint256 _nonce
  ) external {
    vm.assume(_id.chainId != block.chainid);
    // it reverts
    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(_id.chainId, _target, _nonce, _id.origin, _message);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.expectRevert(MessageDestinationNotRelayChain.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if the CrossL2Inbox is the target of the message
  function test_relayMessageWhenTargetIsInbox(Identifier memory _id, bytes memory _message, uint256 _nonce) external {
    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(block.chainid, address(_MOCK_INBOX), _nonce, _id.origin, _message);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.expectRevert(MessageTargetCrossL2Inbox.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if the CDM is the target of the message
  function test_relayMessageWhenTargetL2ToL2CrossDomainMessenger(
    Identifier memory _id,
    uint256 _nonce,
    bytes memory _message
  ) external {
    // it reverts
    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(block.chainid, address(_cdm), _nonce, _id.origin, _message);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.expectRevert(MessageTargetL2ToL2CrossDomainMessenger.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if the CrossL2Inbox reverts with InvalidHash
  function test_relayMessageWhenInboxReturnsInvalidHash(
    Identifier memory _id,
    address _target,
    bytes memory _payload
  ) external {
    // it reverts
    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    _id.origin = address(_cdm);

    vm.etch(_MOCK_INBOX, bytes('Code'));

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    vm.mockCallRevert(_MOCK_INBOX, _validateCalldata, abi.encodeWithSelector(InvalidHash.selector));

    vm.expectRevert(InvalidHash.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if the message has been already relayed
  function test_relayMessageWhenMessageAlreadyRelayed(
    Identifier memory _id,
    address _target,
    address _sender,
    uint256 _nonce,
    bytes memory _message
  ) external {
    // it reverts
    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(block.chainid, _target, _nonce, _sender, _message);

    bytes32 _messageHash = Hashing.hashL2toL2CrossDomainMessage({
      _destination: block.chainid,
      _source: _id.chainId,
      _nonce: _nonce,
      _sender: _sender,
      _target: _target,
      _message: _message
    });

    _cdm.forTest_setSuccessfulMessage(_messageHash, true);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.expectRevert(MessageAlreadyRelayed.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage reverts if the call to the target fails
  function test_relayMessageWhenTargetCallFails(
    Identifier memory _id,
    address _target,
    address _sender,
    uint256 _nonce,
    bytes memory _message
  ) external {
    // it reverts
    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(block.chainid, _target, _nonce, _sender, _message);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    vm.mockCallRevert(_target, _message, 'SOME_ERROR_MESSAGE');

    vm.expectRevert(TargetCallFailed.selector);
    _cdm.relayMessage(_id, _payload);
  }

  /// @notice Test relayMessage updates the successfulMessages mapping and emits RelayedMessage event on success
  function test_relayMessageWhenSucceeds(
    Identifier memory _id,
    address _target,
    address _sender,
    uint256 _nonce,
    bytes memory _message
  ) external {
    vm.assume(_target != _CHEATCODES_ADDRESS && _target != _CONSOLE_ADDRESS);

    vm.assume(_target != address(_cdm));
    vm.assume(_target != _MOCK_INBOX);

    _id.origin = address(_cdm);

    bytes memory _payload = Helpers.encodePayload(block.chainid, _target, _nonce, _sender, _message);

    bytes memory _validateCalldata = abi.encodeCall(CrossL2Inbox.validateMessage, (_id, keccak256(_payload)));
    _mockAndExpect(_MOCK_INBOX, _validateCalldata, abi.encode(true));

    _mockAndExpect(_target, _message, abi.encode(true));

    bytes32 _messageHash = Hashing.hashL2toL2CrossDomainMessage({
      _destination: block.chainid,
      _source: _id.chainId,
      _nonce: _nonce,
      _sender: _sender,
      _target: _target,
      _message: _message
    });

    assertFalse(_cdm.successfulMessages(_messageHash), 'Message already relayed');

    vm.expectEmit(address(_cdm));
    emit RelayedMessage(_id.chainId, _nonce, _messageHash);

    _cdm.relayMessage(_id, _payload);

    // successfulMessages must have been updated
    assertTrue(_cdm.successfulMessages(_messageHash), 'Message not relayed');
  }
}

contract L2ToL2CrossDomainMessenger_Unit_AuthorizeUpgrade is Base {
  /// @notice Test authorizeUpgrade reverts if the sender is not the owner
  function test_authorizeUpgradeWhenNotOwner(
    address _sender
  ) external {
    vm.prank(_UNAUTHORIZED_CALLER);
    vm.expectRevert(
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _UNAUTHORIZED_CALLER)
    );
    _cdm.forTest_authorizeUpgrade(_sender);
  }

  /// @notice Test authorizeUpgrade if the sender is the owner
  function test_authorizeUpgradeWhenOwner() external {
    vm.prank(_MESSENGER_OWNER);
    _cdm.forTest_authorizeUpgrade(_MESSENGER_OWNER);
  }
}
