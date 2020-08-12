pragma solidity >=0.4.0 <0.7.0;

contract BlockInfo {
  bytes32 blockHash;
  uint difficulty;
  uint gasLimit;
  uint number;
  uint timestamp;

  constructor() public payable {
    blockHash = blockhash(0);
    difficulty = block.difficulty;
    gasLimit = block.gaslimit;
    number = block.number;
    timestamp = block.timestamp;
    require(blockHash == 0x823b2ff5785b12da8b1363cac9a5cbe566d8b715a4311441b119c39a0367488c);
    require(gasLimit == 9223372036854775807);
  }

  function getGenesisHash() public view returns (bytes32) {
    return blockHash;
  }

  function getDifficulty() public view returns (uint) {
    return difficulty;
  }
  function getGasLimit() public view returns (uint) {
    return gasLimit;
  }
  function getNumber() public view returns (uint) {
    return number;
  }
  function getTimestamp() public view returns (uint) {
    return timestamp;
  }
}
