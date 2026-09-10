// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title Point Time-Lock Contract for XFG PTLC atomic swaps
/// @notice Locks ETH with a secp256k1 point lock (PTLC) and block-height timeout
contract PointTimelock {

    // secp256k1 curve parameters for t * G verification via ecrecover
    uint256 private constant G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 private constant N   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    struct LockContract {
        address payable sender;
        address payable recipient;
        uint256 amount;
        address pointAddress; // address derived from secp256k1 point T = t * G
        uint256 timeoutBlock;
        bool claimed;
        bool refunded;
        bytes32 secret;       // secret scalar t set on claim
    }

    mapping(bytes32 => LockContract) public contracts;

    event Locked(bytes32 indexed contractId, address indexed sender, address indexed recipient,
                 uint256 amount, address pointAddress, uint256 timeoutBlock);
    event Claimed(bytes32 indexed contractId, bytes32 secret);
    event Refunded(bytes32 indexed contractId);

    /// @notice Lock ETH for a recipient with a point lock and timeout
    /// @param recipient Who can claim with scalar secret t
    /// @param pointAddress ETH address of point T = t * G
    /// @param timeoutBlock Block number after which sender can refund
    function lock(address payable recipient, address pointAddress, uint256 timeoutBlock)
        external payable returns (bytes32 contractId)
    {
        require(msg.value > 0, "Must send ETH");
        require(timeoutBlock > block.number, "Timeout must be in future");
        require(recipient != address(0), "Invalid recipient");
        require(pointAddress != address(0), "Invalid point address");

        contractId = keccak256(abi.encodePacked(
            msg.sender, recipient, msg.value, pointAddress, timeoutBlock
        ));

        require(contracts[contractId].amount == 0, "Contract already exists");

        contracts[contractId] = LockContract({
            sender: payable(msg.sender),
            recipient: recipient,
            amount: msg.value,
            pointAddress: pointAddress,
            timeoutBlock: timeoutBlock,
            claimed: false,
            refunded: false,
            secret: bytes32(0)
        });

        emit Locked(contractId, msg.sender, recipient, msg.value, pointAddress, timeoutBlock);
    }

    /// @notice Claim locked ETH by revealing scalar secret t such that t * G = T.
    /// @dev SECRET ENCODING — CANONICAL RULE:
    ///      `secret` MUST be the CryptoNote SecretKey scalar t interpreted as a
    ///      BIG-endian 256-bit integer, i.e. the BYTE-REVERSED raw 32-byte little-
    ///      endian storage used by the CryptoNote codebase. Rationale: cross-curve
    ///      scalar reuse guarantees t < N_secp256k1 (since t < l_ed25519 < n_secp),
    ///      so the same mathematical scalar t is valid on both curves; every
    ///      consumer in the secp256k1 domain (libsecp256k1 C API and Solidity
    ///      uint256) reads scalars BIG-endian. Callers must therefore reverse the
    ///      CryptoNote LE bytes once at the ABI boundary (see
    ///      ContractAbi::derivePointAddressFromSecret) and pass that BE form here.
    ///      The revealed value is emitted in the Claimed event for indexer
    ///      extraction — indexers must treat it as the canonical BE form.
    /// @param contractId Identifier of the lock contract
    /// @param secret Scalar key t (32 bytes), canonical big-endian form
    function claim(bytes32 contractId, bytes32 secret) external {
        LockContract storage c = contracts[contractId];
        require(c.amount > 0, "Contract not found");
        require(!c.claimed, "Already claimed");
        require(!c.refunded, "Already refunded");

        uint256 t = uint256(secret);
        require(t > 0 && t < N, "Invalid scalar");

        uint256 s = mulmod(t, G_X, N);
        // Defense-in-depth: mulmod can only yield 0 if t == 0 or t == N, both
        // already excluded above; this require guards against any regression.
        require(s != 0, "Zero scalar product");

        // Verified math (proven 50/50 in simulation): s = t*G_X mod N recovers
        // the pubkey x-coordinate of T = t*G; ecrecover(0,27,G_X,s) yields the
        // Ethereum address derived from that point.
        address derivedAddress = ecrecover(bytes32(0), 27, bytes32(G_X), bytes32(s));
        require(derivedAddress == c.pointAddress, "Invalid point secret");

        // Checks-effects-interactions: state finalized before external transfer.
        c.claimed = true;
        c.secret = secret;
        c.recipient.transfer(c.amount);

        emit Claimed(contractId, secret);
    }

    /// @notice Refund locked ETH after timeout
    function refund(bytes32 contractId) external {
        LockContract storage c = contracts[contractId];
        require(c.amount > 0, "Contract not found");
        require(!c.claimed, "Already claimed");
        require(!c.refunded, "Already refunded");
        require(block.number >= c.timeoutBlock, "Timeout not reached");

        c.refunded = true;
        c.sender.transfer(c.amount);

        emit Refunded(contractId);
    }

    /// @notice Check contract details
    function getContract(bytes32 contractId) external view returns (
        address sender, address recipient, uint256 amount,
        address pointAddress, uint256 timeoutBlock,
        bool claimed, bool refunded, bytes32 secret
    ) {
        LockContract storage c = contracts[contractId];
        return (c.sender, c.recipient, c.amount, c.pointAddress, c.timeoutBlock,
                c.claimed, c.refunded, c.secret);
    }
}
