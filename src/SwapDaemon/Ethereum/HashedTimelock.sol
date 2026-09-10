// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title Hash Time-Lock Contract for XFG atomic swaps
/// @notice Locks ETH with a keccak256 hash lock and block-height timeout
contract HashedTimelock {

    // Minimal non-reentrancy guard. `claim`/`refund` now use `.call` for the
    // payout (see AUDIT 6.2) so the 2300-gas stipend of `.transfer` no longer
    // bricks smart-contract-wallet recipients; the guard preserves the
    // no-reentrancy property that `.transfer` used to give for free.
    uint256 private _entered;
    modifier nonReentrant() {
        require(_entered == 0, "Reentrant call");
        _entered = 1;
        _;
        _entered = 0;
    }

    struct LockContract {
        address payable sender;
        address payable recipient;
        uint256 amount;
        bytes32 hashLock;
        uint256 timeoutBlock;
        bool claimed;
        bool refunded;
        bytes32 preimage;   // set on claim
    }

    mapping(bytes32 => LockContract) public contracts;

    event Locked(bytes32 indexed contractId, address indexed sender, address indexed recipient,
                 uint256 amount, bytes32 hashLock, uint256 timeoutBlock);
    event Claimed(bytes32 indexed contractId, bytes32 preimage);
    event Refunded(bytes32 indexed contractId);

    /// @notice Lock ETH for a recipient with a hash lock and timeout
    /// @param recipient Who can claim with the preimage
    /// @param hashLock keccak256(preimage) that must be revealed to claim
    /// @param timeoutBlock Block number after which sender can refund
    function lock(address payable recipient, bytes32 hashLock, uint256 timeoutBlock)
        external payable returns (bytes32 contractId)
    {
        require(msg.value > 0, "Must send ETH");
        require(timeoutBlock > block.number, "Timeout must be in future");
        require(recipient != address(0), "Invalid recipient");

        contractId = keccak256(abi.encodePacked(
            msg.sender, recipient, msg.value, hashLock, timeoutBlock
        ));

        require(contracts[contractId].amount == 0, "Contract already exists");

        contracts[contractId] = LockContract({
            sender: payable(msg.sender),
            recipient: recipient,
            amount: msg.value,
            hashLock: hashLock,
            timeoutBlock: timeoutBlock,
            claimed: false,
            refunded: false,
            preimage: bytes32(0)
        });

        emit Locked(contractId, msg.sender, recipient, msg.value, hashLock, timeoutBlock);
    }

    /// @notice Claim locked ETH by revealing the preimage
    function claim(bytes32 contractId, bytes32 preimage) external nonReentrant {
        LockContract storage c = contracts[contractId];
        require(c.amount > 0, "Contract not found");
        require(!c.claimed, "Already claimed");
        require(!c.refunded, "Already refunded");
        require(keccak256(abi.encodePacked(preimage)) == c.hashLock, "Invalid preimage");

        // Checks-effects-interactions: state finalized before the external call.
        c.claimed = true;
        c.preimage = preimage;
        uint256 amount = c.amount;

        emit Claimed(contractId, preimage);

        // AUDIT 6.2: pay out with `.call` (all forwarded gas) instead of
        // `.transfer` (2300 gas). A contract-wallet recipient whose receive()
        // costs > 2300 gas would otherwise make BOTH claim and refund revert
        // forever, permanently locking the funds. nonReentrant + CEI above
        // keep this safe.
        (bool ok, ) = c.recipient.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Refund locked ETH after timeout
    function refund(bytes32 contractId) external nonReentrant {
        LockContract storage c = contracts[contractId];
        require(c.amount > 0, "Contract not found");
        require(!c.claimed, "Already claimed");
        require(!c.refunded, "Already refunded");
        require(block.number >= c.timeoutBlock, "Timeout not reached");

        c.refunded = true;
        uint256 amount = c.amount;

        emit Refunded(contractId);

        (bool ok, ) = c.sender.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Check contract details
    function getContract(bytes32 contractId) external view returns (
        address sender, address recipient, uint256 amount,
        bytes32 hashLock, uint256 timeoutBlock,
        bool claimed, bool refunded, bytes32 preimage
    ) {
        LockContract storage c = contracts[contractId];
        return (c.sender, c.recipient, c.amount, c.hashLock, c.timeoutBlock,
                c.claimed, c.refunded, c.preimage);
    }
}
