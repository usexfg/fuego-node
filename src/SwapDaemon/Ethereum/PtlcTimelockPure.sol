// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title Pure Point Time-Lock Contract for XFG atomic swaps (PTLC_PURE_PLAN P4.1)
/// @notice PURE point-lock escrow: funds are locked against the adaptor POINT
///         T = t*G (x-only) with NO hashlock H(t). The counterparty claims by
///         presenting the completed adaptor signature; the adaptor secret t is
///         extracted OFF-CHAIN from the emitted raw signature material.
/// @dev Verification runs in one of two deploy-time modes (`VerifyMode`):
///
///   1. StrictPrecompile — verifies the completed-Schnorr equation
///          s*G == R + e*P      with  e = keccak256(presigR || T || contractId)
///      using the EIP-6601 secp256k1 ECADD/ECMUL precompiles. Until those
///      precompiles are live on the target chain every claim reverts with
///      "ECMUL_UNAVAILABLE" (fail-closed: funds remain refundable after
///      timeout — a PTLC whose adaptor never completes must stay refundable).
///
///   2. EcrecoverFallback — approximate check usable on today's EVM chains
///      (see the NatSpec on `claimPtlc` for EXACTLY what is verified and its
///      limitations). This mode is why `EthChainClient::supportsPurePtlc()`
///      stays `false`: the approximation is NOT cryptographic proof.
///
/// In both modes the raw adaptor signature + presignature nonce are emitted in
/// `ClaimedPtlc` so the off-chain indexer recovers t = s' - s (mod n) and
/// independently verifies t*G == T. On-chain t extraction is deliberately NOT
/// attempted: Solidity cannot do safe mod-n scalar arithmetic without the
/// precompile, and a wrong on-chain t computation would brick claims.
///
/// Checks-effects-interactions throughout; no external calls before state is
/// finalized; custom errors for every failure path.
///
/// @custom:staged  NOT DEPLOYABLE AS-IS. This contract targets the draft
///   EIP-6601 secp256k1 precompiles, which are not live on any chain, and it
///   only compiles with `viaIR = true` + optimizer enabled (the precompile
///   plumbing is stack-heavy). `EthChainClient::supportsPurePtlc()` returns
///   false, so no swap uses it. The AUDIT 6.7 change below (on-chain adaptor
///   identity `(s - s')*G == T`) makes the strict-mode logic correct for when
///   this is eventually productionised and independently audited. The LIVE EVM
///   PTLC path is PointTimelock.sol, whose ecrecover check already proves
///   t*G == T.
contract PtlcTimelockPure {

    // ── Types ─────────────────────────────────────────────────────────────

    struct PureLock {
        address payable sender;
        address payable recipient;
        uint256 amount;
        bytes32 ptlcPoint;    // x-only adaptor point T = t*G (never zero)
        bytes32 ptlcPointY;   // AUDIT 6.7: affine y of T — needed for the
                              // on-chain adaptor-identity check t*G == T
                              // (x-only cannot distinguish T from -T).
        bytes32 pCombinedX;   // MuSig2 aggregate key P, affine x — equation + verifier binding
        bytes32 pCombinedY;   // MuSig2 aggregate key P, affine y
        bytes32 presigRx;     // presignature nonce R, affine x — bound at lock time
        bytes32 presigRy;     // presignature nonce R, affine y
        address verifier;     // address(uint160(uint256(keccak256(P_combined))))
        uint256 timeoutBlock;
        bool claimed;
        bool refunded;
    }

    /// @dev Selects the claim verification strategy at deploy time.
    enum VerifyMode { StrictPrecompile, EcrecoverFallback }

    // ── Constants ──────────────────────────────────────────────────────────

    /// @dev EIP-6601 (draft) secp256k1 precompile assignments. Probed at
    ///      runtime — a call to an unassigned precompile address succeeds with
    ///      EMPTY returndata on current chains, so availability is detected by
    ///      checking returndata length AND validating a known-answer result,
    ///      never by success flag alone.
    address private constant PRECOMPILE_SECP_ECMUL = address(0x07);
    address private constant PRECOMPILE_SECP_ECADD = address(0x0b);

    /// @dev secp256k1 generator G.
    bytes32 private constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    bytes32 private constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /// @dev secp256k1 group order n (AUDIT 6.7 — for t = s - s' mod n).
    uint256 private constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev 2*G — known-answer for precompile probing.
    bytes32 private constant TWO_GX =
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5;
    bytes32 private constant TWO_GY =
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A;

    // ── Storage / events / errors ──────────────────────────────────────────

    mapping(bytes32 => PureLock) public locks;

    VerifyMode public immutable verifyMode;

    event PtlcPureLocked(bytes32 indexed contractId, bytes32 indexed ptlcPoint,
                         address indexed sender, address recipient,
                         uint256 amount, uint256 timeoutBlock);
    /// @param adaptorSig Raw 64-byte completed adaptor signature (as presented).
    /// @param presig     Presignature nonce x-coordinate bound at lock time.
    /// @dev Off-chain indexer extracts t = s' - s (mod n) from these values and
    ///      verifies t*G == ptlcPoint before treating the claim as final.
    event ClaimedPtlc(bytes32 indexed contractId, bytes adaptorSig, bytes32 presig);
    event Refunded(bytes32 indexed contractId);

    error ZeroValue();
    error ZeroRecipient();
    error ZeroPoint();
    error ZeroCombinedKey();
    error ZeroPresigPoint();
    error TimeoutInPast();
    error TimeoutNotReached();   // pre-existing: referenced in refund() but never declared
    error DuplicateContract();
    error NotFound();
    error AlreadyClaimed();
    error AlreadyRefunded();
    error BadAdaptorSigLength();
    error PresigMismatch();
    error RecoverFailed();
    error VerifierMismatch();
    error AdaptorEquationFailed();
    error EthTransferFailed();

    constructor(VerifyMode mode) {
        verifyMode = mode;
    }

    // ── Lock ───────────────────────────────────────────────────────────────

    /// @notice Lock ETH against the pure adaptor point T (no hashlock).
    /// @param recipient  Who can claim by completing the adaptor signature.
    /// @param ptlcPoint  x-only adaptor point T = t*G. Must be nonzero.
    /// @param pCombinedX Affine x of the MuSig2 aggregate key P_combined.
    /// @param pCombinedY Affine y of the MuSig2 aggregate key P_combined.
    /// @param presigRx   Affine x of the presignature nonce R (exchanged before
    ///                   the lock in the swap protocol — bound here so a claim
    ///                   must present the committed nonce).
    /// @param presigRy   Affine y of the presignature nonce R.
    /// @param timeoutBlock Block after which the sender can refund.
    /// @return contractId keccak256(sender, recipient, value, ptlcPoint, timeoutBlock)
    /// @param ptlcPointY Affine y of T (AUDIT 6.7 — the strict-mode claim now
    ///                   verifies t*G == T as a full point, so both coords are
    ///                   bound at lock time).
    function lockWithPoint(address payable recipient,
                           bytes32 ptlcPoint,
                           bytes32 ptlcPointY,
                           bytes32 pCombinedX,
                           bytes32 pCombinedY,
                           bytes32 presigRx,
                           bytes32 presigRy,
                           uint256 timeoutBlock)
        external payable returns (bytes32 contractId)
    {
        if (msg.value == 0) revert ZeroValue();
        if (recipient == address(0)) revert ZeroRecipient();
        if (ptlcPoint == bytes32(0) && ptlcPointY == bytes32(0)) revert ZeroPoint();
        if (pCombinedX == bytes32(0) && pCombinedY == bytes32(0)) revert ZeroCombinedKey();
        if (presigRx == bytes32(0) && presigRy == bytes32(0)) revert ZeroPresigPoint();
        if (timeoutBlock <= block.number) revert TimeoutInPast();

        contractId = keccak256(abi.encodePacked(
            msg.sender, recipient, msg.value, ptlcPoint, ptlcPointY, timeoutBlock
        ));

        if (locks[contractId].amount != 0) revert DuplicateContract();

        // Stored verifier binding: address derived from the aggregate key.
        address verifier = address(uint160(uint256(
            keccak256(abi.encodePacked(pCombinedX, pCombinedY))
        )));

        locks[contractId] = PureLock({
            sender: payable(msg.sender),
            recipient: recipient,
            amount: msg.value,
            ptlcPoint: ptlcPoint,
            ptlcPointY: ptlcPointY,
            pCombinedX: pCombinedX,
            pCombinedY: pCombinedY,
            presigRx: presigRx,
            presigRy: presigRy,
            verifier: verifier,
            timeoutBlock: timeoutBlock,
            claimed: false,
            refunded: false
        });

        emit PtlcPureLocked(contractId, ptlcPoint, msg.sender,
                            recipient, msg.value, timeoutBlock);
    }

    // ── Claim ──────────────────────────────────────────────────────────────

    /// @notice Claim locked ETH with the completed adaptor signature.
    ///
    /// WHAT IS VERIFIED (per mode):
    ///
    /// * StrictPrecompile — the full completed-Schnorr equation
    ///       s*G == R + e*P,   e = keccak256(presigR || ptlcPoint || contractId)
    ///   via EIP-6601 precompiles. If the precompiles are absent the claim
    ///   reverts with "ECMUL_UNAVAILABLE" (fail-closed; refund path unaffected).
    ///   NOTE: the completion identity (s'-s)*G == T is enforced OFF-CHAIN —
    ///   the indexer extracts t from the emitted raw signature material.
    ///
    /// * EcrecoverFallback — APPROXIMATE check: ecrecover(e, v, r, s) must
    ///   return the stored verifier address
    ///       address(uint160(uint256(keccak256(P_combined)))).
    ///   Inputs: v = y-parity bit taken from the LOW BIT of adaptorSig[0]
    ///   (mapped to 27/28); r = adaptorSig[0..32) interpreted as the nonce
    ///   x-coordinate R_x AS-IS; s = adaptorSig[32..64).
    ///   LIMITATIONS (deliberate, documented):
    ///     - ecrecover performs ECDSA recovery, NOT Schnorr/adaptor
    ///       verification. Matching the verifier address shows the presented
    ///       tuple was derived under the aggregate key's domain — it does NOT
    ///       prove s*G == R + e*P nor (s'-s)*G == T.
    ///     - The parity bit shares its byte with r's most significant byte;
    ///       if that makes r >= n, ecrecover returns address(0) and the claim
    ///       fails closed.
    ///   Because of these limitations EVM clients keep pure PTLC gated OFF
    ///   (supportsPurePtlc() == false) until EIP-6601 is live; the definitive
    ///   secret hand-off always happens off-chain via ClaimedPtlc data.
    ///
    /// @param contractId Lock identifier from lockWithPoint.
    /// @param adaptorSig 64-byte completed adaptor signature (R_x ‖ s).
    /// @param presigR    Presignature nonce x-coordinate (must equal the
    ///                   nonce bound at lock time).
    /// @param sPrime     AUDIT 6.7 — the pre-signature scalar s' exchanged
    ///                   off-chain. StrictPrecompile mode now checks
    ///                   (s - s')*G == T on-chain, so a claim can only settle
    ///                   by revealing the real adaptor secret t = s - s'.
    ///                   Ignored by EcrecoverFallback (which is not a proof —
    ///                   see the contract-level NatSpec).
    function claimPtlc(bytes32 contractId, bytes calldata adaptorSig, bytes32 presigR, bytes32 sPrime)
        external
    {
        PureLock storage c = locks[contractId];
        if (c.amount == 0) revert NotFound();
        if (c.claimed) revert AlreadyClaimed();
        if (c.refunded) revert AlreadyRefunded();
        if (adaptorSig.length != 64) revert BadAdaptorSigLength();
        if (presigR != c.presigRx) revert PresigMismatch();

        // Effects BEFORE interaction (reentrancy safety; revert rolls back).
        c.claimed = true;

        bytes32 e = keccak256(abi.encodePacked(presigR, c.ptlcPoint, contractId));

        if (verifyMode == VerifyMode.StrictPrecompile) {
            _verifyStrict(c, e, adaptorSig, sPrime);
        } else {
            _verifyEcrecoverFallback(c, e, adaptorSig);
        }

        emit ClaimedPtlc(contractId, adaptorSig, presigR);

        (bool sent, ) = c.recipient.call{value: c.amount}("");
        if (!sent) revert EthTransferFailed();
    }

    // ── Refund ─────────────────────────────────────────────────────────────

    /// @notice Refund locked ETH after timeoutBlock (same policy as HashedTimelock).
    function refund(bytes32 contractId) external {
        PureLock storage c = locks[contractId];
        if (c.amount == 0) revert NotFound();
        if (c.claimed) revert AlreadyClaimed();
        if (c.refunded) revert AlreadyRefunded();
        if (block.number < c.timeoutBlock) revert TimeoutNotReached();

        c.refunded = true;

        (bool sent, ) = c.sender.call{value: c.amount}("");
        if (!sent) revert EthTransferFailed();

        emit Refunded(contractId);
    }

    // ── Views ──────────────────────────────────────────────────────────────

    function getLock(bytes32 contractId) external view returns (
        address sender, address recipient, uint256 amount,
        bytes32 ptlcPoint, address verifier, uint256 timeoutBlock,
        bool claimed, bool refunded
    ) {
        PureLock storage c = locks[contractId];
        return (c.sender, c.recipient, c.amount, c.ptlcPoint, c.verifier,
                c.timeoutBlock, c.claimed, c.refunded);
    }

    /// @notice True when the EIP-6601 precompiles answer with correct results
    ///         on this chain (known-answer probes: 2*G via both ops).
    function precompilesAvailable() external view returns (bool) {
        return _ecmulAvailable() && _ecaddAvailable();
    }

    // ── Internal: strict precompile path ───────────────────────────────────

    function _verifyStrict(PureLock storage c, bytes32 e, bytes calldata adaptorSig, bytes32 sPrime)
        internal view
    {
        if (!_ecmulAvailable() || !_ecaddAvailable()) revert("ECMUL_UNAVAILABLE");

        bytes32 sScalar = bytes32(adaptorSig[32:64]);

        // (1) Completed-Schnorr equation: s*G == e*P + R.
        //     Scoped so its locals free the stack before check (2).
        {
            (bytes32 lx, bytes32 ly) = _ecmul(sScalar, GX, GY);
            (bytes32 px, bytes32 py) = _ecmul(bytes32(e), c.pCombinedX, c.pCombinedY);
            (bytes32 rhsX, bytes32 rhsY) = _ecadd(px, py, c.presigRx, c.presigRy);
            if (!(lx == rhsX && ly == rhsY)) revert AdaptorEquationFailed();
        }

        // (2) AUDIT 6.7 — adaptor identity, enforced ON-CHAIN:
        //     t = s - s' (mod n) must be nonzero and satisfy t*G == T as a
        //     FULL point. This pins the claim to the real adaptor secret for
        //     the point T bound at lock time — an attacker cannot pick an
        //     arbitrary s' (the -t / n-t ambiguity is resolved by checking
        //     both affine coordinates, which x-only could not do). The
        //     ClaimedPtlc event then carries material from which the XFG-side
        //     counterparty recovers exactly that t.
        uint256 t = addmod(uint256(sScalar), N - (uint256(sPrime) % N), N);
        if (t == 0) revert AdaptorEquationFailed();
        (bytes32 tx_, bytes32 ty_) = _ecmul(bytes32(t), GX, GY);
        if (tx_ != c.ptlcPoint || ty_ != c.ptlcPointY) revert AdaptorEquationFailed();
    }

    // NB: `ret` is `bytes memory` — index-range slicing is calldata-only, so
    // decode the 64-byte precompile output with abi.decode (pre-existing
    // compile fix, needed for the AUDIT 6.7 change to build).
    function _ecmul(bytes32 scalar, bytes32 x, bytes32 y)
        internal view returns (bytes32 ox, bytes32 oy)
    {
        (bool ok, bytes memory ret) =
            PRECOMPILE_SECP_ECMUL.staticcall(abi.encodePacked(x, y, scalar));
        if (!ok || ret.length != 64) revert("ECMUL_UNAVAILABLE");
        return abi.decode(ret, (bytes32, bytes32));
    }

    function _ecadd(bytes32 x1, bytes32 y1, bytes32 x2, bytes32 y2)
        internal view returns (bytes32 ox, bytes32 oy)
    {
        (bool ok, bytes memory ret) =
            PRECOMPILE_SECP_ECADD.staticcall(abi.encodePacked(x1, y1, x2, y2));
        if (!ok || ret.length != 64) revert("ECMUL_UNAVAILABLE");
        return abi.decode(ret, (bytes32, bytes32));
    }

    function _ecmulAvailable() internal view returns (bool) {
        (bool ok, bytes memory ret) =
            PRECOMPILE_SECP_ECMUL.staticcall(abi.encodePacked(GX, GY, bytes32(uint256(2))));
        if (!ok || ret.length != 64) return false;
        (bytes32 rx, bytes32 ry) = abi.decode(ret, (bytes32, bytes32));
        return rx == TWO_GX && ry == TWO_GY;
    }

    function _ecaddAvailable() internal view returns (bool) {
        (bool ok, bytes memory ret) =
            PRECOMPILE_SECP_ECADD.staticcall(abi.encodePacked(GX, GY, GX, GY));
        if (!ok || ret.length != 64) return false;
        (bytes32 rx, bytes32 ry) = abi.decode(ret, (bytes32, bytes32));
        return rx == TWO_GX && ry == TWO_GY;
    }

    // ── Internal: ecrecover fallback path ──────────────────────────────────

    function _verifyEcrecoverFallback(PureLock storage c, bytes32 e, bytes calldata adaptorSig)
        internal view
    {
        uint8 parity = uint8(adaptorSig[0]) & 1;
        uint8 v = parity == 0 ? 27 : 28;
        bytes32 r = bytes32(adaptorSig[0:32]);
        bytes32 s = bytes32(adaptorSig[32:64]);

        address recovered = ecrecover(e, v, r, s);
        if (recovered == address(0)) revert RecoverFailed();
        if (recovered != c.verifier) revert VerifierMismatch();
    }
}
