// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library Helpers {
  bytes32 internal constant _SENT_MESSAGE_EVENT_SELECTOR =
    0x382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320;

  function encodePayload(
    uint256 _destination,
    address _target,
    uint256 _nonce,
    address _sender,
    bytes memory _message
  ) external pure returns (bytes memory encoded_) {
    encoded_ = abi.encodePacked(
      _SENT_MESSAGE_EVENT_SELECTOR, abi.encode(_destination, _target, _nonce), abi.encode(_sender, _message)
    );
  }
}
