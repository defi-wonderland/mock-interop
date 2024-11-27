// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from '@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {ISemver} from 'optimism/src/universal/interfaces/ISemver.sol';

/// @notice The struct for a pointer to a message payload in a remote (or local) chain.
/// @param origin The address of the chain where the message originated.
/// @param blockNumber The block number where the message was emitted.
/// @param logIndex The log index of the message in the block.
/// @param timestamp The timestamp of the block where the message was emitted.
/// @param chainId The chain id where the message originated.
struct Identifier {
  address origin;
  uint256 blockNumber;
  uint256 logIndex;
  uint256 timestamp;
  uint256 chainId;
}

/// @notice Thrown when trying to execute a function that requires the caller to be a valid relayer.
error InvalidRelayer();

/// @notice Thrown when trying to execute a cross chain message with an invalid hash.
error InvalidHash();

/// @custom:proxied true
/// @title CrossL2Inbox
/// @notice The CrossL2Inbox is responsible for executing a cross chain message on the destination
///         chain. It is permissionless to validate a cross chain message on behalf of any user.
contract CrossL2Inbox is ISemver, UUPSUpgradeable, OwnableUpgradeable {
  /// @notice Emitted when a cross chain message is being executed.
  /// @param msgHash Hash of message payload being executed.
  /// @param id Encoded Identifier of the message.
  event ExecutingMessage(bytes32 indexed msgHash, Identifier id);

  /// @notice Emitted when a relayer's status is updated.
  /// @param account The address of the relayer whose status is being updated.
  /// @param isRelayer A boolean indicating whether the relayer is enabled (true) or disabled (false).
  event UpdatedRelayer(address indexed account, bool isRelayer);

  /// @notice Emitted when a new hash is registered as valid for cross chain messages.
  /// @param hash The hash of the cross chain message that has been registered.
  event RegisteredHash(bytes32 indexed hash);

  /// @notice Semantic version.
  /// @custom:semver 1.0.0-mock
  string public constant version = '1.0.0-mock';

  /// @notice Authorized relayers that can execute cross chain messages.
  mapping(address _sender => bool) public validRelayers;

  /// @notice Authorized hashes of cross chain messages that can be executed.
  /// @dev Hashes are generated using:
  ///      keccak256(abi.encode(identifier, keccak256(payload)))
  ///      where payload is the encoded chainId, target contract, nonce, sender,
  ///      and the calldata sent to the target contract.
  mapping(bytes32 _hash => bool) public validHashes;

  /// @notice Initializes the contract disabling the initializers.
  constructor() OwnableUpgradeable() {
    _disableInitializers();
  }

  /// @notice Initialize the contract
  /// @param _owner The owner of the contract
  function initialize(
    address _owner
  ) external initializer {
    __Ownable_init(_owner);
  }

  /// @notice Validates a cross chain message on the destination chain
  ///         and emits an ExecutingMessage event. This function is useful
  ///         for applications that understand the schema of the _message payload and want to
  ///         process it in a custom way.
  /// @param _id      Identifier of the message.
  /// @param _msgHash Hash of the message payload to call target with.
  function validateMessage(Identifier calldata _id, bytes32 _msgHash) external {
    // Check the Id and Message hash
    _checkHash(_id, _msgHash);

    emit ExecutingMessage(_msgHash, _id);
  }

  /// @notice Enables a relayer to operate with the contract.
  /// @param _relayer The address of the relayer.
  function enableRelayer(
    address _relayer
  ) external onlyOwner {
    validRelayers[_relayer] = true;

    emit UpdatedRelayer(_relayer, true);
  }

  /// @notice Disables a relayer from operating with the contract.
  /// @param _relayer The address of the relayer.
  function disableRelayer(
    address _relayer
  ) external onlyOwner {
    validRelayers[_relayer] = false;

    emit UpdatedRelayer(_relayer, false);
  }

  /// @notice Registers a valid hash for a cross chain message.
  /// @dev Hashes are generated using:
  ///      keccak256(abi.encode(identifier, keccak256(payload)))
  ///      where payload is the encoded chainId, target contract, nonce, sender,
  ///      and the calldata sent to the target contract.
  /// @param _hash Hash of the cross chain message.
  function registerValidHash(
    bytes32 _hash
  ) external {
    if (!validRelayers[msg.sender]) revert InvalidRelayer();
    validHashes[_hash] = true;

    emit RegisteredHash(_hash);
  }

  /// @notice Authorizes an upgrade to a new implementation.
  /// @param _newImplementation Address of the new implementation (not used).
  function _authorizeUpgrade(
    address _newImplementation
  ) internal override onlyOwner {}

  /// @notice Validates that for a given cross chain message identifier and message hash
  ///         the message can be executed on the destination chain.
  /// @param _id Identifier of the message.
  /// @param _msgHash Hash of the message payload to call target with.
  function _checkHash(Identifier calldata _id, bytes32 _msgHash) internal view {
    bytes32 _hash = keccak256(abi.encode(_id, _msgHash));
    if (!validHashes[_hash]) revert InvalidHash();
  }
}
