pragma solidity >=0.4.0 <0.7.0;

contract DaughterContract {
  constructor () public {}
}

contract MomContract {
  event DoLog(address indexed _from, uint _value, uint _n);
  DaughterContract public daughter;

  constructor () public payable {
    emit DoLog(msg.sender, msg.value, 3);
    daughter = new DaughterContract();
  }
}
