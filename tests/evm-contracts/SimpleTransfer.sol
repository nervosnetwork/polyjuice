pragma solidity >=0.4.0 <0.7.0;

contract SimpleTransfer {

  constructor() public payable {}

  function transferTo(address payable target) public payable {
    target.transfer(1 wei);
  }
}
