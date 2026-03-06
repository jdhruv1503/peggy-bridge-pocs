// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/**
 * @title PeggyMinimal
 * @notice Minimal extraction of Peggy.sol signature verification logic for testing.
 *         This contract faithfully reproduces the exact code paths from the production
 *         Peggy.sol so that vulnerabilities can be tested in isolation.
 */

struct ValsetArgs {
    address[] validators;
    uint256[] powers;
    uint256 valsetNonce;
    uint256 rewardAmount;
    address rewardToken;
}

contract PeggyMinimal {
    bytes32 public state_lastValsetCheckpoint;
    mapping(address => uint256) public state_lastBatchNonces;
    uint256 public state_lastValsetNonce = 0;
    uint256 public state_lastEventNonce = 0;
    bytes32 public state_peggyId;
    uint256 public state_powerThreshold;

    event ValsetUpdatedEvent(
        uint256 indexed _newValsetNonce,
        uint256 _eventNonce,
        uint256 _rewardAmount,
        address _rewardToken,
        address[] _validators,
        uint256[] _powers
    );

    event TransactionBatchExecutedEvent(
        uint256 indexed _batchNonce,
        address indexed _token,
        uint256 _eventNonce
    );

    function initialize(
        bytes32 _peggyId,
        uint256 _powerThreshold,
        address[] calldata _validators,
        uint256[] calldata _powers
    ) external {
        require(_validators.length == _powers.length, "Malformed current validator set");

        uint256 cumulativePower = 0;
        for (uint256 i = 0; i < _powers.length; i++) {
            cumulativePower = cumulativePower + _powers[i];
            if (cumulativePower > _powerThreshold) {
                break;
            }
        }
        require(
            cumulativePower > _powerThreshold,
            "Submitted validator set signatures do not have enough power."
        );

        ValsetArgs memory _valset;
        _valset = ValsetArgs(_validators, _powers, 0, 0, address(0));

        bytes32 newCheckpoint = makeCheckpoint(_valset, _peggyId);

        state_peggyId = _peggyId;
        state_powerThreshold = _powerThreshold;
        state_lastValsetCheckpoint = newCheckpoint;
        state_lastEventNonce = state_lastEventNonce + 1;

        emit ValsetUpdatedEvent(
            state_lastValsetNonce,
            state_lastEventNonce,
            0,
            address(0),
            _validators,
            _powers
        );
    }

    // === EXACT COPY of verifySig from Peggy.sol ===
    function verifySig(
        address _signer,
        bytes32 _theHash,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public pure returns (bool) {
        bytes32 messageDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _theHash)
        );
        return _signer == ecrecover(messageDigest, _v, _r, _s);
    }

    // === EXACT COPY of makeCheckpoint from Peggy.sol ===
    function makeCheckpoint(ValsetArgs memory _valsetArgs, bytes32 _peggyId)
        public
        pure
        returns (bytes32)
    {
        bytes32 methodName = 0x636865636b706f696e7400000000000000000000000000000000000000000000;
        bytes32 checkpoint = keccak256(
            abi.encode(
                _peggyId,
                methodName,
                _valsetArgs.valsetNonce,
                _valsetArgs.validators,
                _valsetArgs.powers,
                _valsetArgs.rewardAmount,
                _valsetArgs.rewardToken
            )
        );
        return checkpoint;
    }

    // === EXACT COPY of checkValidatorSignatures from Peggy.sol ===
    function checkValidatorSignatures(
        address[] memory _currentValidators,
        uint256[] memory _currentPowers,
        uint8[] memory _v,
        bytes32[] memory _r,
        bytes32[] memory _s,
        bytes32 _theHash,
        uint256 _powerThreshold
    ) public pure {
        uint256 cumulativePower = 0;

        for (uint256 i = 0; i < _currentValidators.length; i++) {
            // If v is set to 0, this signifies that it was not possible to get a signature
            // from this validator and we skip evaluation
            if (_v[i] != 0) {
                // Check that the current validator has signed off on the hash
                require(
                    verifySig(
                        _currentValidators[i],
                        _theHash,
                        _v[i],
                        _r[i],
                        _s[i]
                    ),
                    "Validator signature does not match."
                );
                cumulativePower = cumulativePower + _currentPowers[i];
                if (cumulativePower > _powerThreshold) {
                    break;
                }
            }
        }

        require(
            cumulativePower > _powerThreshold,
            "Submitted validator set signatures do not have enough power."
        );
    }

    // === EXACT COPY of updateValset from Peggy.sol ===
    function updateValset(
        ValsetArgs calldata _newValset,
        ValsetArgs calldata _currentValset,
        uint8[] calldata _v,
        bytes32[] calldata _r,
        bytes32[] calldata _s
    ) external {
        require(
            _newValset.valsetNonce > _currentValset.valsetNonce,
            "New valset nonce must be greater than the current nonce"
        );
        require(
            _newValset.validators.length == _newValset.powers.length,
            "Malformed new validator set"
        );
        require(
            _currentValset.validators.length == _currentValset.powers.length &&
                _currentValset.validators.length == _v.length &&
                _currentValset.validators.length == _r.length &&
                _currentValset.validators.length == _s.length,
            "Malformed current validator set"
        );
        require(
            makeCheckpoint(_currentValset, state_peggyId) ==
                state_lastValsetCheckpoint,
            "Supplied current validators and powers do not match checkpoint."
        );

        bytes32 newCheckpoint = makeCheckpoint(_newValset, state_peggyId);
        checkValidatorSignatures(
            _currentValset.validators,
            _currentValset.powers,
            _v,
            _r,
            _s,
            newCheckpoint,
            state_powerThreshold
        );

        state_lastValsetCheckpoint = newCheckpoint;
        state_lastValsetNonce = _newValset.valsetNonce;

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

    // === EXACT COPY of submitBatch from Peggy.sol (simplified, no ERC20 transfers) ===
    function submitBatchValidation(
        ValsetArgs memory _currentValset,
        uint8[] memory _v,
        bytes32[] memory _r,
        bytes32[] memory _s,
        uint256[] memory _amounts,
        address[] memory _destinations,
        uint256[] memory _fees,
        uint256 _batchNonce,
        address _tokenContract,
        uint256 _batchTimeout
    ) external {
        require(
            state_lastBatchNonces[_tokenContract] < _batchNonce,
            "New batch nonce must be greater than the current nonce"
        );
        require(
            block.number < _batchTimeout,
            "Batch timeout must be greater than the current block height"
        );
        require(
            _currentValset.validators.length == _currentValset.powers.length &&
                _currentValset.validators.length == _v.length &&
                _currentValset.validators.length == _r.length &&
                _currentValset.validators.length == _s.length,
            "Malformed current validator set"
        );
        require(
            makeCheckpoint(_currentValset, state_peggyId) ==
                state_lastValsetCheckpoint,
            "Supplied current validators and powers do not match checkpoint."
        );
        require(
            _amounts.length == _destinations.length && _amounts.length == _fees.length,
            "Malformed batch of transactions"
        );

        checkValidatorSignatures(
            _currentValset.validators,
            _currentValset.powers,
            _v,
            _r,
            _s,
            keccak256(
                abi.encode(
                    state_peggyId,
                    0x7472616e73616374696f6e426174636800000000000000000000000000000000,
                    _amounts,
                    _destinations,
                    _fees,
                    _batchNonce,
                    _tokenContract,
                    _batchTimeout
                )
            ),
            state_powerThreshold
        );

        state_lastBatchNonces[_tokenContract] = _batchNonce;
        state_lastEventNonce = state_lastEventNonce + 1;
        emit TransactionBatchExecutedEvent(_batchNonce, _tokenContract, state_lastEventNonce);
    }
}
