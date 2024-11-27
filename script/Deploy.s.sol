// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';
import {CrossL2Inbox} from 'contracts/CrossL2Inbox.sol';
import {L2ToL2CrossDomainMessenger} from 'contracts/L2ToL2CrossDomainMessenger.sol';
import {Script} from 'forge-std/Script.sol';

interface ICreate2Deployer {
  /**
   * @dev Deploys a contract using `CREATE2`. The address where the
   * contract will be deployed can be known in advance via {computeAddress}.
   *
   * The bytecode for a contract can be obtained from Solidity with
   * `type(contractName).creationCode`.
   *
   * Requirements:
   * - `bytecode` must not be empty.
   * - `salt` must have not been used for `bytecode` already.
   * - the factory must have a balance of at least `value`.
   * - if `value` is non-zero, `bytecode` must have a `payable` constructor.
   */
  function deploy(uint256 value, bytes32 salt, bytes memory code) external;

  /**
   * @dev Returns the address where a contract will be stored if deployed via {deploy}.
   * Any change in the `bytecodeHash` or `salt` will result in a new destination address.
   */
  function computeAddress(bytes32 salt, bytes32 codeHash) external view returns (address);
}

/// @title Deploy
/// @notice This script deploys the CrossL2Inbox and L2ToL2CrossDomainMessenger contracts
///         with the same address on every chain using Create2Deployer. Since the owner
///         is part of the creation code, it should be the same on every chain.
contract Deploy is Script {
  ICreate2Deployer public constant CREATE_2_DEPLOYER = ICreate2Deployer(0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2);

  function run() external returns (address _inboxProxy, address _messengerProxy) {
    bytes32 _salt = keccak256(abi.encodePacked(vm.envString('CREATE2_SALT')));
    address _owner = vm.envAddress('OWNER_ADDR');

    vm.startBroadcast(vm.envUint('DEPLOYER_PK'));

    // Creation code of CrossL2Inbox Implementation
    bytes memory _inboxImplementationCreationCode = type(CrossL2Inbox).creationCode;

    // Deploy CrossL2Inbox Implementation using Create2Deployer
    address _inboxImplementation = _deploy(_salt, _inboxImplementationCreationCode);

    // Creation code of CrossL2Inbox Proxy
    bytes memory _inboxCreationCode = bytes.concat(
      type(ERC1967Proxy).creationCode,
      abi.encode(_inboxImplementation, abi.encodeWithSelector(CrossL2Inbox.initialize.selector, _owner))
    );

    // Deploy Proxy and Initialize
    _inboxProxy = _deploy(_salt, _inboxCreationCode);

    // Creation code of L2ToL2CrossDomainMessenger Implementation
    bytes memory _messengerImplementationCreationCode =
      bytes.concat(type(L2ToL2CrossDomainMessenger).creationCode, abi.encode(_inboxProxy));

    // Deploy L2ToL2CrossDomainMessenger Implementation using Create2Deployer
    address _messengerImplementation = _deploy(_salt, _messengerImplementationCreationCode);

    // Creation code of L2ToL2CrossDomainMessenger Proxy
    bytes memory _messengerCreationCode = bytes.concat(
      type(ERC1967Proxy).creationCode,
      abi.encode(_messengerImplementation, abi.encodeWithSelector(CrossL2Inbox.initialize.selector, _owner))
    );

    // Deploy Proxy and Initialize
    _messengerProxy = _deploy(_salt, _messengerCreationCode);

    vm.stopBroadcast();
  }

  function _deploy(bytes32 _salt, bytes memory _creationCode) internal returns (address _address) {
    // Pre compute address
    _address = CREATE_2_DEPLOYER.computeAddress(_salt, keccak256(_creationCode));

    // Deploy
    CREATE_2_DEPLOYER.deploy(0, _salt, _creationCode);
  }
}
