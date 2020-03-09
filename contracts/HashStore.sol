pragma solidity ^0.6.1;

contract HashStore {
  /*
  *  Events
  */
  event OwnershipTransferred(address indexed _previousOwner, address indexed _newOwner);
  event NewHashStored(address indexed _hashSender, uint _hashId, string _hashContent, uint timestamp);
  event Withdrawn(address indexed _hashSender, uint amount);

  /*
  * Storage
  */

  struct Hash {
    // sender address
    address sender;
    // hash text
    string content;
    // creation timestamp
    uint timestamp;
    // previous hash text
    string old;
    // tag
    uint32 tag;
  }

  // Hashes mapping
  mapping(uint => Hash) public hashes;
  // Contract owner
  address public owner;
  // Last stored Hash Id
  uint public lastHashId;
  // Service price in Wei
  uint public price;

  /*
  * Modifiers
  */

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /*
  * Public functions
  */

  /**
  * @dev Contract constructor
  * @param _price Service price
  * renamed HashStore{} to StoreHash{}
  */
  function StoreHash(uint _price) public {
    // check price valid
    require(_price > 0);

    // assign owner
    owner = msg.sender;
    // assign price
    price = _price;
    // init ids
    lastHashId = 0;
  }

  /**
  * @dev Transfer contract ownership
  * @param _newOwner New owner address
  */
  function transferOwnership(address _newOwner) onlyOwner public {
    // check address not null
    require(_newOwner != address(0));

    // assign new owner
    owner = _newOwner;

    // Log event
    emit OwnershipTransferred(owner, _newOwner);
  }

  /**
  * @dev Withdraw contract accumulated Eth balance
  */
  /*function withdrawBalance() onlyOwner public */

  /**
  * @dev save new hash
  * @param _hashContent Hash Content
  */
  function save(string memory _hashContent, uint32 _tag, string memory _lastHashContent) payable public {
    // only save if service price paid
    require(msg.value >= price);

    // create Hash
    uint hashId = ++lastHashId;
    hashes[hashId].sender = msg.sender;
    hashes[hashId].content = _hashContent;
    hashes[hashId].old = _lastHashContent;
    hashes[hashId].tag = _tag;
    hashes[hashId].timestamp = block.timestamp;

    // Log event
    emit NewHashStored(hashes[hashId].sender, hashId, hashes[hashId].content, hashes[hashId].timestamp);
  }

  /**
  * @dev find hash by id
  * @param _hashId Hash Id
  */
  function find(uint _hashId) view public returns (address hashSender, string memory hashContent, uint hashTimestamp) {
    return (hashes[_hashId].sender, hashes[_hashId].content, hashes[_hashId].timestamp);
  }
}
