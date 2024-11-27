// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from '@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol';
import {CrossL2Inbox} from 'contracts/CrossL2Inbox.sol';
import {L2ToL2CrossDomainMessenger} from 'contracts/L2ToL2CrossDomainMessenger.sol';
import {Test} from 'forge-std/Test.sol';
import {Deploy} from 'script/Deploy.s.sol';

contract DeployTest is Test {
  CrossL2Inbox internal _unichainInbox;
  L2ToL2CrossDomainMessenger internal _unichainL2ToL2Cdm;
  CrossL2Inbox internal _optimismInbox;
  L2ToL2CrossDomainMessenger internal _optimismL2ToL2Cdm;
  address internal _deployer = vm.addr(vm.envUint('DEPLOYER_PK'));
  // We need to use the same owner address used in the deploy script to test proxy upgrades.
  address internal _owner = vm.envAddress('OWNER_ADDR');
  uint256 internal _optimism;
  uint256 internal _unichain;

  /// @dev Since the deploy shuould be nonce agnostic, we need to set the nonce to a random value.
  function setUp() external {
    _optimism = vm.createFork(vm.rpcUrl('optimism'), 19_032_508);
    _unichain = vm.createFork(vm.rpcUrl('unichain'), 3_015_172);

    vm.selectFork(_optimism);
    // Randomize deployer nonce
    vm.setNonce(_deployer, uint64(block.prevrandao));
    Deploy _deploy = new Deploy();
    (address _inboxAddress, address _cdmAddress) = _deploy.run();

    _optimismInbox = CrossL2Inbox(_inboxAddress);
    _optimismL2ToL2Cdm = L2ToL2CrossDomainMessenger(_cdmAddress);

    vm.selectFork(_unichain);
    // Randomize deployer nonce
    vm.setNonce(_deployer, uint64(block.prevrandao));
    _deploy = new Deploy();
    (_inboxAddress, _cdmAddress) = _deploy.run();

    _unichainInbox = CrossL2Inbox(_inboxAddress);
    _unichainL2ToL2Cdm = L2ToL2CrossDomainMessenger(_cdmAddress);
  }

  /// @notice Test that contract is correctly initialized.
  function test_inboxInitialize() external view {
    assertEq(address(_unichainInbox), address(_optimismInbox), 'Different inbox addresses');
    assertEq(_unichainInbox.owner(), _owner, 'Incorrect owner on unichain');
    assertEq(_optimismInbox.owner(), _owner, 'Incorrect owner on optimism');
  }

  /// @notice Test that contract is correctly initialized.
  function test_cdmInitialize() external view {
    assertEq(address(_unichainL2ToL2Cdm), address(_optimismL2ToL2Cdm), 'Different inbox addresses');
    assertEq(_unichainInbox.owner(), _owner, 'Incorrect owner on unichain');
    assertEq(_optimismInbox.owner(), _owner, 'Incorrect owner on optimism');
    assertEq(_unichainL2ToL2Cdm.CROSS_L2_INBOX(), address(_unichainInbox), 'Incorrect inbox address');
    assertEq(_optimismL2ToL2Cdm.CROSS_L2_INBOX(), address(_optimismInbox), 'Incorrect inbox address');
  }

  /// @notice Test that the owner can upgrade the proxy.
  function test_ownerCanUpgradeProxy() external {
    vm.startPrank(_owner);

    vm.selectFork(_optimism);
    _optimismInbox.upgradeToAndCall(address(new CrossL2Inbox()), bytes(''));
    _optimismL2ToL2Cdm.upgradeToAndCall(address(new L2ToL2CrossDomainMessenger(address(1))), bytes(''));

    vm.selectFork(_unichain);
    _unichainInbox.upgradeToAndCall(address(new CrossL2Inbox()), bytes(''));
    _unichainL2ToL2Cdm.upgradeToAndCall(address(new L2ToL2CrossDomainMessenger(address(1))), bytes(''));
  }

  /// @notice Test that the `upgradeToAndCall` function reverts when the caller is not the owner.
  /// @dev Was getting an error with vm.expectRevert so I used the following code to test the reverts.
  function test_notOwnerCanNotUpgradeProxy() external {
    address _unauthorizedCaller = makeAddr('Unauthorized Caller');
    vm.startPrank(_unauthorizedCaller);

    vm.selectFork(_optimism);
    // it reverts
    (bool _success, bytes memory _returnData) = address(_optimismInbox).call(
      abi.encodeWithSignature('upgradeToAndCall(address,bytes)', address(new CrossL2Inbox()), bytes(''))
    );
    assertEq(_success, false, 'Upgrade to and call on inbox not failed');
    assertEq(
      _returnData,
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _unauthorizedCaller),
      'Incorrect revert message'
    );

    // it reverts
    (_success, _returnData) = address(_optimismL2ToL2Cdm).call(
      abi.encodeWithSignature(
        'upgradeToAndCall(address,bytes)', address(new L2ToL2CrossDomainMessenger(address(1))), bytes('')
      )
    );
    assertEq(_success, false, 'Upgrade to and call on messenger not failed');
    assertEq(
      _returnData,
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _unauthorizedCaller),
      'Incorrect revert message'
    );

    vm.selectFork(_unichain);
    // it reverts
    (_success, _returnData) = address(_optimismInbox).call(
      abi.encodeWithSignature('upgradeToAndCall(address,bytes)', address(new CrossL2Inbox()), bytes(''))
    );
    assertEq(_success, false, 'Upgrade to and call on inbox not failed');
    assertEq(
      _returnData,
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _unauthorizedCaller),
      'Incorrect revert message'
    );

    (_success, _returnData) = address(_optimismL2ToL2Cdm).call(
      abi.encodeWithSignature(
        'upgradeToAndCall(address,bytes)', address(new L2ToL2CrossDomainMessenger(address(1))), bytes('')
      )
    );
    assertEq(_success, false, 'Upgrade to and call on messenger not failed');
    assertEq(
      _returnData,
      abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _unauthorizedCaller),
      'Incorrect revert message'
    );
  }
}
