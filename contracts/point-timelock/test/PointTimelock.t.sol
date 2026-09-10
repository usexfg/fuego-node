// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {PointTimelock} from "../src/PointTimelock.sol";

/// Cross-curve canonical rule under test:
///   CryptoNote stores adaptor scalars LITTLE-endian; secp256k1 + Solidity
///   uint256 read BIG-endian => the on-chain `secret` MUST be the
///   byte-reversed CryptoNote scalar (see ContractAbi.cpp derivePointAddressFromSecret).
///
/// Independent reference (python EC, cross-checked vs C++ keccak path):
///   scalar_be = 0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201
///   eth_addr  = 0x7eb918a662a49b909db105760c3d157b87599d81   (= address(t*G))
contract PointTimelockTest is Test {
    PointTimelock internal ptl;

    // Reference vector (python double-and-add + keccak, independent of contract)
    bytes32 constant SECRET_BE =
        0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201;
    address constant EXPECTED_POINT_ADDR = 0x17ed5Da0053633f20437d10E91D24f85242bD097;

    address internal alice = makeAddr("alice"); // locker / XFG-side watcher
    address internal bob = makeAddr("bob");     // recipient, holds t

    function setUp() public {
        ptl = new PointTimelock();
    }

    function _lock(uint256 amountEth, uint64 timeoutDelta) internal returns (bytes32 id) {
        vm.deal(alice, amountEth);
        vm.prank(alice);
        id = ptl.lock{value: amountEth}(payable(bob), EXPECTED_POINT_ADDR, block.number + timeoutDelta);
    }

    /// The lock's committed point address must equal address(t*G) derived off-chain.
    function test_reference_vector_pointAddressMatchesTtimesG() public {
        assertEq(uint160(EXPECTED_POINT_ADDR) != 0, true);
        // Sanity: recompute via ecrecover-trick inside test env too (same primitive as contract)
        uint256 s = mulmod(uint256(SECRET_BE), _GX(), _N());
        address derived = ecrecover(bytes32(0), 27, bytes32(_GX()), bytes32(s));
        assertEq(derived, EXPECTED_POINT_ADDR);
    }

    function test_lock_stores_fields_and_emits() public {
        bytes32 id = _lock(1 ether, 100);
        (
            address sender, address recipient, uint256 amount, address pointAddr,
            uint256 timeout, bool claimed, bool refunded,
        ) = ptl.contracts(id);
        assertEq(sender, alice);
        assertEq(recipient, bob);
        assertEq(amount, 1 ether);
        assertEq(pointAddr, EXPECTED_POINT_ADDR);
        assertEq(timeout, block.number + 100);
        assertFalse(claimed);
        assertFalse(refunded);
    }

    function test_claim_with_canonical_secret_pays_and_reveals() public {
        bytes32 id = _lock(1 ether, 100);
        uint256 bobBefore = bob.balance;
        vm.prank(bob); // anyone may claim; recipient receives
        ptl.claim(id, SECRET_BE);
        assertEq(bob.balance, bobBefore + 1 ether);
        (,,,,, bool claimed,,) = ptl.contracts(id);
        assertTrue(claimed);
        (,,,,,,, bytes32 secret) = ptl.contracts(id);
        assertEq(secret, SECRET_BE);
    }

    function test_claim_wrong_secret_reverts() public {
        bytes32 id = _lock(1 ether, 100);
        bytes32 bad = bytes32(uint256(1)); // valid range but t*G != T
        vm.expectRevert("Invalid point secret");
        ptl.claim(id, bad);
    }

    function test_claim_zero_secret_reverts() public {
        bytes32 id = _lock(1 ether, 100);
        vm.expectRevert("Invalid scalar");
        ptl.claim(id, bytes32(0));
    }

    function test_claim_secret_ge_N_reverts() public {
        bytes32 id = _lock(1 ether, 100);
        vm.expectRevert("Invalid scalar");
        ptl.claim(id, bytes32(_N())); // t == N excluded by require
    }

    function test_refund_only_after_timeout() public {
        bytes32 id = _lock(1 ether, 10);
        vm.expectRevert("Timeout not reached");
        ptl.refund(id);
        vm.roll(block.number + 11);
        uint256 aliceBefore = alice.balance;
        ptl.refund(id);
        assertEq(alice.balance, aliceBefore + 1 ether);
    }

    function test_double_claim_reverts() public {
        bytes32 id = _lock(1 ether, 100);
        ptl.claim(id, SECRET_BE);
        vm.expectRevert("Already claimed");
        ptl.claim(id, SECRET_BE);
    }

    function test_refund_after_claim_reverts() public {
        bytes32 id = _lock(1 ether, 10);
        ptl.claim(id, SECRET_BE);
        vm.roll(block.number + 20);
        vm.expectRevert("Already claimed");
        ptl.refund(id);
    }

    function test_claim_after_refund_reverts() public {
        bytes32 id = _lock(1 ether, 5);
        vm.roll(block.number + 6);
        ptl.refund(id);
        vm.expectRevert("Already refunded");
        ptl.claim(id, SECRET_BE);
    }

    function test_lock_zero_point_or_value_reverts() public {
        vm.deal(alice, 1 ether);
        vm.startPrank(alice);
        vm.expectRevert("Must send ETH");
        ptl.lock{value: 0}(payable(bob), EXPECTED_POINT_ADDR, block.number + 5);
        vm.expectRevert("Invalid point address");
        ptl.lock{value: 1 ether}(payable(bob), address(0), block.number + 5);
        vm.stopPrank();
    }

    function test_same_params_twice_reverts_duplicate() public {
        bytes32 id1 = _lock(1 ether, 50);
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert("Contract already exists");
        ptl.lock{value: 1 ether}(payable(bob), EXPECTED_POINT_ADDR, block.number + 50);
        assertNotEq(id1, bytes32(0));
    }


    // ── AUDIT 6.2 regression: .transfer -> .call ──

    /// A contract wallet whose receive() costs more than the 2300-gas stipend
    /// must still be able to receive a claim. Under the old `.transfer` payout
    /// this reverted, which bricked claim AND refund permanently: the ETH could
    /// never leave the contract by any path.
    function test_claim_pays_contract_wallet_recipient() public {
        GreedyWallet wallet = new GreedyWallet();
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        bytes32 id = ptl.lock{value: 1 ether}(
            payable(address(wallet)), EXPECTED_POINT_ADDR, block.number + 100);

        ptl.claim(id, SECRET_BE);

        assertEq(address(wallet).balance, 1 ether);
        assertGt(wallet.touched(), 0);          // receive() really did burn >2300 gas
        (,,,,, bool claimed,,) = ptl.contracts(id);
        assertTrue(claimed);
    }

    /// Same for the refund path — a contract-wallet *sender* must get its ETH back.
    function test_refund_pays_contract_wallet_sender() public {
        GreedyWallet wallet = new GreedyWallet();
        vm.deal(address(wallet), 1 ether);
        bytes32 id = wallet.doLock(ptl, EXPECTED_POINT_ADDR, block.number + 10);

        vm.roll(block.number + 11);
        ptl.refund(id);

        assertEq(address(wallet).balance, 1 ether);
        (,,,,,, bool refunded,) = ptl.contracts(id);
        assertTrue(refunded);
    }

    /// Paying with `.call` forwards all gas, so the guard — not the stipend —
    /// is what stops reentrancy now. A recipient that calls back into claim()
    /// must not be able to drain a second payout.
    function test_reentrant_recipient_cannot_double_claim() public {
        ReentrantWallet attacker = new ReentrantWallet(ptl);
        vm.deal(alice, 3 ether);
        vm.prank(alice);
        bytes32 id = ptl.lock{value: 1 ether}(
            payable(address(attacker)), EXPECTED_POINT_ADDR, block.number + 100);
        attacker.arm(id, SECRET_BE);

        ptl.claim(id, SECRET_BE);

        // Exactly one payout, and the reentrant inner call was rejected.
        assertEq(address(attacker).balance, 1 ether);
        assertEq(address(ptl).balance, 0);
        assertTrue(attacker.reentryAttempted());
        assertFalse(attacker.reentrySucceeded());
    }

    // ── constants ──
    function _GX() internal pure returns (uint256) {
        return 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    }
    function _N() internal pure returns (uint256) {
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    }
}

/// Recipient whose receive() writes storage (~20k gas) — far beyond the 2300-gas
/// stipend that `.transfer` forwards.
contract GreedyWallet {
    uint256 public touched;
    receive() external payable { touched += 1; }
    function doLock(PointTimelock ptl, address point, uint256 timeoutBlock)
        external returns (bytes32)
    {
        return ptl.lock{value: 1 ether}(payable(address(this)), point, timeoutBlock);
    }
}

/// Recipient that attempts to reenter claim() from receive().
contract ReentrantWallet {
    PointTimelock private immutable ptl;
    bytes32 private id;
    bytes32 private secret;
    bool public reentryAttempted;
    bool public reentrySucceeded;

    constructor(PointTimelock _ptl) { ptl = _ptl; }
    function arm(bytes32 _id, bytes32 _secret) external { id = _id; secret = _secret; }

    receive() external payable {
        if (id == bytes32(0) || reentryAttempted) return;
        reentryAttempted = true;
        try ptl.claim(id, secret) { reentrySucceeded = true; } catch { }
    }
}
