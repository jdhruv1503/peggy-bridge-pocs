// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./PeggyMinimal.sol";

/**
 * @title CosmosERC20Mock
 * @notice Minimal ERC20 that Peggy can mint/burn (mirrors real CosmosERC20).
 */
contract CosmosERC20Mock {
    string public name;
    string public symbol;
    uint8  public decimals;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name     = _name;
        symbol   = _symbol;
        decimals = _decimals;
        owner    = msg.sender;  // Peggy contract becomes owner
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address account, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function burn(address account, uint256 amount) external onlyOwner {
        require(balanceOf[account] >= amount, "insufficient balance");
        totalSupply -= amount;
        balanceOf[account] -= amount;
        emit Transfer(account, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient balance");
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

/**
 * @title RevertingERC20
 * @notice ERC20 that reverts on transfer - used to test reward token DoS.
 */
contract RevertingERC20 {
    function transfer(address, uint256) external pure returns (bool) {
        revert("I always revert");
    }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        revert("I always revert");
    }
    function balanceOf(address) external pure returns (uint256) { return type(uint256).max; }
}

/**
 * @title PeggyWithDeployERC20
 * @notice Extends PeggyMinimal with deployERC20 and reward-token-in-updateValset
 *         to test access control and reentrancy/DoS vectors.
 */
contract PeggyWithDeployERC20 is PeggyMinimal {

    mapping(address => bool) public isInjectiveNativeToken;

    // Reward token state (for testing updateValset with rewards)
    bool public rewardTransferEnabled = true;

    event ERC20DeployedEvent(
        string  _cosmosDenom,
        address indexed _tokenContract,
        string  _name,
        string  _symbol,
        uint8   _decimals,
        uint256 _eventNonce
    );

    /**
     * @notice EXACT COPY of deployERC20 from Peggy.sol
     * ⚠️ NO ACCESS CONTROL — anyone can call this ⚠️
     */
    function deployERC20(
        string calldata _cosmosDenom,
        string calldata _name,
        string calldata _symbol,
        uint8 _decimals
    ) external {
        CosmosERC20Mock erc20 = new CosmosERC20Mock(_name, _symbol, _decimals);
        isInjectiveNativeToken[address(erc20)] = true;

        state_lastEventNonce = state_lastEventNonce + 1;
        emit ERC20DeployedEvent(
            _cosmosDenom,
            address(erc20),
            _name,
            _symbol,
            _decimals,
            state_lastEventNonce
        );
    }

    /**
     * @notice updateValset with reward token transfer (from Peggy.sol).
     */
    function updateValsetWithReward(
        ValsetArgs calldata _newValset,
        ValsetArgs calldata _currentValset,
        uint8[]   calldata _v,
        bytes32[] calldata _r,
        bytes32[] calldata _s
    ) external {
        require(
            _newValset.valsetNonce > _currentValset.valsetNonce,
            "New valset nonce must be greater than the current nonce"
        );
        require(
            _currentValset.validators.length == _currentValset.powers.length &&
            _currentValset.validators.length == _v.length &&
            _currentValset.validators.length == _r.length &&
            _currentValset.validators.length == _s.length,
            "Malformed current validator set"
        );
        require(
            makeCheckpoint(_currentValset, state_peggyId) == state_lastValsetCheckpoint,
            "Checkpoint mismatch"
        );

        bytes32 newCheckpoint = makeCheckpoint(_newValset, state_peggyId);
        checkValidatorSignatures(
            _currentValset.validators,
            _currentValset.powers,
            _v, _r, _s,
            newCheckpoint,
            state_powerThreshold
        );

        // ACTIONS — state updated BEFORE reward transfer
        state_lastValsetCheckpoint = newCheckpoint;
        state_lastValsetNonce      = _newValset.valsetNonce;

        // REWARD TRANSFER — can revert entire tx including state update
        if (_newValset.rewardToken != address(0) && _newValset.rewardAmount != 0) {
            // Use low-level call to mirror safeTransfer behavior
            (bool ok,) = _newValset.rewardToken.call(
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    msg.sender,
                    _newValset.rewardAmount
                )
            );
            require(ok, "reward transfer failed");
        }

        state_lastEventNonce = state_lastEventNonce + 1;
        emit ValsetUpdatedEvent(
            _newValset.valsetNonce,
            state_lastEventNonce,
            _newValset.rewardAmount,
            _newValset.rewardToken,
            _newValset.validators,
            _newValset.powers
        );
    }
}

/**
 * @title OwnableExpiryMock
 * @notice Minimal reproduction of OwnableUpgradeableWithExpiry for griefing test.
 */
contract OwnableExpiryMock {
    address private _owner;
    uint256 private _deployTimestamp;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        _deployTimestamp = block.timestamp;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function owner() public view returns (address) { return _owner; }

    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function getOwnershipExpiryTimestamp() public view returns (uint256) {
        return _deployTimestamp + 82 weeks;
    }

    function isOwnershipExpired() public view returns (bool) {
        return block.timestamp > getOwnershipExpiryTimestamp();
    }

    /**
     * @notice EXACT COPY from OwnableUpgradeableWithExpiry.sol
     * ⚠️ CALLABLE BY ANYONE AFTER 82 WEEKS ⚠️
     */
    function renounceOwnershipAfterExpiry() external {
        require(isOwnershipExpired(), "Ownership not yet expired");
        _renounceOwnership();
    }

    function renounceOwnership() external onlyOwner {
        _renounceOwnership();
    }

    function _renounceOwnership() private {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    // Simulates emergencyPause / emergencyUnpause from Peggy
    bool public paused = false;

    function emergencyPause() external onlyOwner {
        paused = true;
    }

    function emergencyUnpause() external onlyOwner {
        paused = false;
    }
}
