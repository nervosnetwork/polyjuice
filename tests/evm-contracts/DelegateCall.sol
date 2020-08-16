pragma solidity >=0.4.0 <0.7.0;

contract DelegateCall {
  uint storedData;

  constructor() public payable {
    storedData = 123;
  }

  function set(address ss, uint x) public payable {
    (bool success, bytes memory _result) = ss.delegatecall(abi.encodeWithSignature("set(uint256)", x));
    require(success);
  }

  function overwrite(address ss, uint x) public payable {
    (bool success, bytes memory _result) = ss.delegatecall(abi.encodeWithSignature("set(uint256)", x));
    storedData = x + 1;
    require(success);
  }

  function get() public view returns (uint) {
    return storedData;
  }
}
