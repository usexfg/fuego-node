# Tanda Implementation Guide

## Overview

This guide covers implementation of the Tanda (ROSCA) feature on the Fuego blockchain - a decentralized rotating savings and credit association system using XFG Confidential Deposits (CDs) and multi-sig aliases.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         swapxfg CLI                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │tanda     │  │tanda     │  │tanda     │  │tanda             ││
│  │create    │  │join      │  │pay       │  │status/history    ││
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘│
└───────┼────────────┼────────────┼────────────────┼───────────┘
        │            │            │                │
        └────────────┴────────────┴────────────────┘
                              │
                    JSON-RPC (daemon)
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                         fuegod                                │
│  ┌────────────────┐  ┌─────────────────┐  ┌────────────────┐ │
│  │ Tanda Module   │  │ SwapOfferRelay  │  │ CommitmentIdx │ │
│  │ - State mgmt   │  │ - Musig2        │  │ - CD commits   │ │
│  │ - Bundling    │  │ - Adaptor sigs  │  │ - Merkle tree  │ │
│  │ - Payouts     │  │ - Gossip        │  │ - Interest     │ │
│  └───────┬────────┘  └─────────────────┘  └────────────────┘ │
│          │                                                    │
│  ┌───────┴────────────────────────────────────────────────┐  │
│  │                   Wallet / CD Integration               │  │
│  │  - CD offers (IsSell=false)                             │  │
│  │  - Interest calculation                                 │  │
│  │  - Withdrawal processing                               │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Parameters (Locked)

| Parameter | Value |
|-----------|-------|
| Payment window | 1 epoch (900 blocks) |
| Downpayment | 2 payments upfront |
| Late penalty | Configurable, default 10% |
| Missed penalty | Configurable, default 25% |
| Group size | 2-10 members |
| Max CD term | 72 epochs |
| Lock-in | 1 ~~epoch~~ FULL ROTATION &lt;--how long? (default) 1 epoch per member??|
| Buffer | Small window between epochs (not full epoch) |
| Principal lock | Until CD term expires |
| Interest access | Each epoch |

---

## Data Structures

### C++ Structures (Core)

#### Tanda.h

```cpp
#pragma once

#include "CryptoNoteBasic.h"
#include "CryptoNoteSerialization.h"

namespace CryptoNote {

struct TandaMember {
    Crypto::PublicKey pubKey;
    uint64_t contributedAmount;
    uint64_t pendingPayments;
    uint64_t interestEarned;
    bool hasReceivedPayout;
    uint32_t lastPaymentHeight;
    uint8_t penaltyCount;

    void serialize(ISerializer& s) {
        s(pubKey, "pubKey");
        s(contributedAmount, "contributedAmount");
        s(pendingPayments, "pendingPayments");
        s(interestEarned, "interestEarned");
        s(hasReceivedPayout, "hasReceivedPayout");
        s(lastPaymentHeight, "lastPaymentHeight");
        s(penaltyCount, "penaltyCount");
    }
};

struct Tanda {
    uint64_t groupId;
    std::string name;
    std::vector<Crypto::PublicKey> members;
    std::vector<TandaMember> memberData;
    uint8_t quorum = 2;

    uint64_t contribution;
    uint32_t termMonths;
    uint8_t latePenaltyPct = 10;
    uint8_t missedPenaltyPct = 25;
    uint8_t lockinEpochs = 1;

    uint32_t rotationIdx = 0;
    uint64_t lockedPot = 0;
    uint32_t currentEpoch = 0;

    uint32_t lastPayoutHeight = 0;
    uint8_t status = 0; // 0=WAITING, 1=ACTIVE, 2=COMPLETED, 3=CLOSED

    Crypto::Hash commitmentRoot;
    Crypto::PublicKey jointCdPubKey;

    void serialize(ISerializer& s) {
        s(groupId, "groupId");
        s(name, "name");
        s(members, "members");
        s(memberData, "memberData");
        s(quorum, "quorum");
        s(contribution, "contribution");
        s(termMonths, "termMonths");
        s(latePenaltyPct, "latePenaltyPct");
        s(missedPenaltyPct, "missedPenaltyPct");
        s(lockinEpochs, "lockinEpochs");
        s(rotationIdx, "rotationIdx");
        s(lockedPot, "lockedPot");
        s(currentEpoch, "currentEpoch");
        s(lastPayoutHeight, "lastPayoutHeight");
        s(status, "status");
        s(commitmentRoot, "commitmentRoot");
        s(jointCdPubKey, "jointCdPubKey");
    }
};

}
```

### Go Structures (CLI)

```go
type TandaState struct {
    GroupID           string   `json:"groupId"`
    Name              string   `json:"name"`
    Members           []string `json:"members"`
    Contribution      uint64   `json:"contribution"`
    TermMonths        uint32   `json:"termMonths"`
    LatePenaltyPct    uint8    `json:"latePenaltyPct"`
    MissedPenaltyPct  uint8    `json:"missedPenaltyPct"`
    LockinEpochs       uint8    `json:"lockinEpochs"`
    RotationIdx       uint32   `json:"rotationIdx"`
    LockedPot         uint64   `json:"lockedPot"`
    CurrentEpoch      uint32   `json:"currentEpoch"`
    Status            string   `json:"status"` // WAITING, ACTIVE, COMPLETED, CLOSED
    JointCdPubKey     string   `json:"jointCdPubKey"`
}

type TandaMember struct {
    PubKey            string `json:"pubKey"`
    ContributedAmount uint64 `json:"contributedAmount"`
    PendingPayments   uint64 `json:"pendingPayments"`
    InterestEarned    uint64 `json:"interestEarned"`
    HasReceivedPayout bool   `json:"hasReceivedPayout"`
    PenaltyCount      uint8   `json:"penaltyCount"`
}

type TandaHistory struct {
    Payouts       []TandaPayout  `json:"payouts"`
    Contributions []TandaPayment `json:"contributions"`
    InterestPaid  uint64         `json:"interestPaid"`
}

type TandaPayout struct {
    Epoch     uint32 `json:"epoch"`
    Recipient string `json:"recipient"`
    Amount    uint64 `json:"amount"`
    Height    uint32 `json:"height"`
}

type TandaPayment struct {
    Epoch    uint32 `json:"epoch"`
    Member   string `json:"member"`
    Amount   uint64 `json:"amount"`
    Height   uint32 `json:"height"`
}
```

---

## Module Design

### TandaManager Class

Location: `src/CryptoNoteCore/Tanda.cpp` and `Tanda.h`

**Responsibilities:**
- Tanda lifecycle management (create, join, close)
- Member management
- Bundling individual CDs into Joint CD
- Epoch/rotation tracking
- Payout processing
- Penalty calculation

**Public Methods:**
```cpp
class TandaManager {
public:
    // Creation
    std::error_code createTanda(const std::string& name, 
                                uint64_t contribution,
                                uint32_t termMonths,
                                uint8_t latePenalty = 10,
                                uint8_t missedPenalty = 25,
                                Tanda& tanda);
    
    // Member management
    std::error_code addMember(uint64_t groupId, 
                              const Crypto::PublicKey& pubKey,
                              const std::vector<std::string>& cdOfferIds);
    std::error_code removeMember(uint64_t groupId, 
                                 const Crypto::PublicKey& pubKey);
    
    // Payments
    std::error_code addPayment(uint64_t groupId,
                               const Crypto::PublicKey& member,
                               uint64_t amount);
    
    // Epoch processing
    std::error_code processEpoch(uint64_t groupId);
    std::error_code createJointCd(uint64_t groupId);
    std::error_code rebundleJointCd(uint64_t groupId);
    
    // Payouts
    std::error_code initiatePayout(uint64_t groupId,
                                    std::string& escrowTx,
                                    Crypto::PublicKey& adaptorPoint);
    std::error_code confirmPayout(uint64_t groupId,
                                   const std::string& secret);
    
    // Withdrawals
    std::error_code withdrawInterest(uint64_t groupId,
                                      const Crypto::PublicKey& member,
                                      uint64_t& amount);
    std::error_code withdrawPrincipal(uint64_t groupId,
                                      const Crypto::PublicKey& member,
                                      uint64_t& amount);
    std::error_code relock(uint64_t groupId, const Crypto::PublicKey& member);
    std::error_code leave(uint64_t groupId, const Crypto::PublicKey& member);
    
    // Queries
    std::error_code getTandaState(uint64_t groupId, Tanda& tanda);
    std::error_code getTandaHistory(uint64_t groupId, TandaHistory& history);

private:
    core& m_core;
    CommitmentIndex& m_commitmentIndex;
    std::unordered_map<uint64_t, Tanda> m_tandas;
    
    std::error_code calculatePenalty(uint64_t groupId,
                                      const TandaMember& member,
                                      uint8_t penaltyType,
                                      uint64_t& penalty);
    std::error_code distributePenalties(uint64_t groupId,
                                         uint64_t totalPenalty);
    std::error_code updateCommitmentRoot(uint64_t groupId);
    bool isLockinComplete(const Tanda& tanda);
    bool isCDTermExpired(const Tanda& tanda, uint32_t currentHeight);
    uint64_t calculateProRataPayout(const Tanda& tanda, const TandaMember& member);
};
```

---

## Implementation Steps

### Phase 1: Core Module (Weeks 1-2)

1.1 Create `src/CryptoNoteCore/Tanda.h` - define structures
1.2 Create `src/CryptoNoteCore/Tanda.cpp` - implement TandaManager class
1.3 Implement tanda creation with alias registration
1.4 Implement member join with CD verification
1.5 Add to core initialization in `src/CryptoNoteCore/Core.cpp`

**Files Modified:**
- `src/CryptoNoteCore/CMakeLists.txt` - add Tanda.cpp
- `src/CryptoNoteCore/Core.h` - add TandaManager reference
- `src/CryptoNoteCore/Core.cpp` - initialize TandaManager

### Phase 2: CD Integration (Week 2)

2.1 Implement bundling logic - aggregate individual CDs into Joint CD
2.2 Implement re-bundling at epoch boundaries
2.3 Integrate with CommitmentIndex for CD tracking
2.4 Add interest calculation for Joint CD

### Phase 3: Payout Logic (Week 3)

3.1 Implement epoch boundary detection
3.2 Implement payout initiation (adaptor signature)
3.3 Implement payout confirmation (secret reveal)
3.4 Implement pro-rata calculation for unequal contributions
3.5 Implement penalty distribution

### Phase 4: Withdrawal Logic (Week 3)

4.1 Implement interest withdrawal (each epoch)
4.2 Implement principal withdrawal (after lock-in + CD term)
4.3 Implement early withdrawal penalty
4.4 Implement relock functionality
4.5 Implement buffer window logic

### Phase 5: RPC Endpoints (Week 4)

5.1 Add all RPC handlers in RpcServer.cpp
5.2 Add request/response structures in RpcServerCommon.h

| Handler | Function |
|---------|----------|
| `on_create_tanda` | Create new tanda |
| `on_tanda_join` | Add member with CD offers |
| `on_tanda_pay` | Add payment to tanda |
| `on_tanda_payout` | Initiate payout for current turn |
| `on_tanda_confirm` | Confirm payout with secret |
| `on_tanda_withdraw_interest` | Withdraw interest |
| `on_tanda_withdraw_principal` | Withdraw principal |
| `on_tanda_status` | Get tanda state |
| `on_tanda_history` | Get tanda history |
| `on_tanda_relock` | Relock for next cycle |
| `on_tanda_leave` | Exit tanda |

### Phase 6: CLI Integration (Weeks 4-5)

6.1 Update `swapxfg/app/rpc.go` - add Tanda RPC methods
6.2 Update `swapxfg/app/tui.go` - add Tanda commands
6.3 Update `swapxfg/app/app.go` - add Tanda hotkey handling
6.4 Add Tanda display in UI (status panel)

### Phase 7: Gossip & Sync (Week 5)

7.1 Add TandaState message type to SwapOfferRelay
7.2 Implement broadcast on state changes
7.3 Implement state sync on node connect

### Phase 8: Testing (Weeks 5-6)

8.1 Unit tests for TandaManager class
8.2 Unit tests for penalty calculations
8.3 Integration test - full 5-member tanda lifecycle
8.4 Integration test - early withdrawal scenarios
8.5 Integration test - penalty distribution

---

## Key Algorithms

### Bundling Logic

```cpp
std::error_code TandaManager::createJointCd(uint64_t groupId) {
    Tanda& tanda = getTanda(groupId);
    
    // Sum all member contributions
    uint64_t jointAmount = 0;
    for (const auto& member : tanda.memberData) {
        jointAmount += member.contributedAmount;
    }
    
    // Aggregate member keys for joint CD
    Crypto::PublicKey jointKey = aggregateMemberKeys(tanda.members);
    tanda.jointCdPubKey = jointKey;
    
    // Interest calculated on joint amount (higher tier = better rate)
    uint64_t interest = m_core.currency().calculateCdInterest(
        jointAmount, 
        tanda.termMonths, 
        m_core.getCurrentHeight()
    );
    
    // Store joint CD in CommitmentIndex
    CommitmentEntry entry;
    entry.commitment = computeCommitment(jointAmount);
    entry.amount = jointAmount;
    entry.term = tanda.termMonths;
    entry.type = CommitmentEntry::Type::JOINT;
    m_commitmentIndex.addCommitment(entry);
    
    // Update commitment root
    updateCommitmentRoot(groupId);
    
    return std::error_code();
}
```

### Pro-Rata Payout

```cpp
uint64_t TandaManager::calculateProRataPayout(const Tanda& tanda, const TandaMember& member) {
    uint64_t expected = tanda.contribution * tanda.currentEpoch;
    uint64_t actual = member.contributedAmount;
    
    // Ratio capped at 100%
    double ratio = std::min(double(actual) / double(expected), 1.0);
    
    uint64_t basePayout = tanda.lockedPot / tanda.members.size();
    uint64_t adjustedPayout = uint64_t(double(basePayout) * ratio);
    
    // Penalty for short payment
    if (ratio < 1.0) {
        uint64_t penalty = (basePayout - adjustedPayout) * tanda.missedPenaltyPct / 100;
        return adjustedPayout - penalty;
    }
    
    return adjustedPayout;
}
```

### Penalty Distribution

```cpp
std::error_code TandaManager::distributePenalties(uint64_t groupId, uint64_t totalPenalty) {
    Tanda& tanda = getTanda(groupId);
    if (tanda.members.empty()) return std::error_code();
    
    uint64_t perMember = totalPenalty / tanda.members.size();
    
    for (auto& member : tanda.memberData) {
        // Add penalty share to each good-faith member's interest
        member.interestEarned += perMember;
    }
    
    return std::error_code();
}
```

### Lock Check

```cpp
bool TandaManager::isCDTermExpired(const Tanda& tanda, uint32_t currentHeight) {
    uint32_t elapsedEpochs = currentHeight / EPOCH_LENGTH;
    return elapsedEpochs >= tanda.termMonths;
}

bool TandaManager::isLockinComplete(const Tanda& tanda) {
    return tanda.currentEpoch >= tanda.lockinEpochs;
}
```

---

## CLI Commands

| Command | Usage | Description |
|---------|-------|-------------|
| `tanda create` | `tanda create <name> <amt> <term> [latePct] [missedPct]` | Create tanda |
| `tanda join` | `tanda join <group>` | Join tanda |
| `tanda pay` | `tanda pay <amt>` | Add payment |
| `tanda status` | `tanda status [group]` | View tanda state |
| `tanda history` | `tanda history [group]` | View history |
| `tanda interest` | `tanda interest` | Withdraw interest |
| `tanda withdraw` | `tanda withdraw` | Withdraw all |
| `tanda relock` | `tanda relock` | Stay for next cycle |
| `tanda leave` | `tanda leave` | Exit tanda |
| `tanda list` | `tanda list` | List available tanda |

---

## RPC API Reference

### /createtanda

**Request:**
```json
{
  "name": "mytanda",
  "contribution": 100000000,
  "termMonths": 12,
  "latePenaltyPct": 10,
  "missedPenaltyPct": 25
}
```

**Response:**
```json
{
  "groupId": "abc123...",
  "alias": "@mytanda",
  "jointCdPubKey": "def456...",
  "status": "WAITING"
}
```

### /tandapay

**Request:**
```json
{
  "groupId": "abc123...",
  "amount": 100000000
}
```

**Response:**
```json
{
  "success": true,
  "pendingAmount": 100000000,
  "currentEpoch": 1
}
```

### /tandapayout

**Request:**
```json
{
  "groupId": "abc123..."
}
```

**Response:**
```json
{
  "escrowTx": "...",
  "adaptorPoint": "...",
  "recipient": "f...",
  "amount": 500000000
}
```

### /gettandastatus

**Request:**
```json
{
  "groupId": "abc123..."
}
```

**Response:**
```json
{
  "groupId": "abc123...",
  "name": "mytanda",
  "members": ["f...", "f..."],
  "contribution": 100000000,
  "termMonths": 12,
  "lockedPot": 200000000,
  "currentEpoch": 3,
  "rotationIdx": 1,
  "status": "ACTIVE",
  "jointCdPubKey": "def456..."
}
```

---

## Files to Create/Modify

### New Files
- `src/CryptoNoteCore/Tanda.h`
- `src/CryptoNoteCore/Tanda.cpp`
- `swapxfg/app/tanda_rpc.go`
- `tests/tanda_tests.cpp`
- `docs/tanda.md`

### Modified Files
- `src/CryptoNoteCore/CMakeLists.txt`
- `src/CryptoNoteCore/Core.h`
- `src/CryptoNoteCore/Core.cpp`
- `src/Rpc/RpcServer.cpp`
- `src/Rpc/RpcServer.h`
- `src/Rpc/RpcServerCommon.h`
- `src/CryptoNoteCore/SwapOfferRelay.cpp`
- `src/CryptoNoteCore/SwapOfferRelay.h`
- `swapxfg/app/rpc.go`
- `swapxfg/app/tui.go`
- `swapxfg/app/app.go`

---

## Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | Week 1-2 | Core module with create/join |
| Phase 2 | Week 2 | CD bundling integration |
| Phase 3 | Week 3 | Payout logic |
| Phase 4 | Week 3 | Withdrawal logic |
| Phase 5 | Week 4 | RPC endpoints |
| Phase 6 | Week 4-5 | CLI integration |
| Phase 7 | Week 5 | Gossip/sync |
| Phase 8 | Week 5-6 | Testing |

**Total: ~6 weeks**

---

## Testing Strategy

### Unit Tests

| Test | Description |
|------|-------------|
| `test_create_tanda` | Verify creation with all params |
| `test_add_member` | Verify member addition |
| `test_bundling` | Verify Joint CD creation |
| `test_payout` | Verify payout calculation |
| `test_penalty` | Verify penalty distribution |
| `test_pro_rata` | Verify proportional payout |
| `test_withdraw_interest` | Verify interest withdrawal |
| `test_withdraw_principal` | Verify principal after lock |

### Integration Test Scenario

```cpp
void test_full_lifecycle() {
    auto tanda = createTanda("test", 100, 6);
    
    for (auto& member : members) {
        member.join(tanda.id);
        member.pay(100);
        member.pay(100);
    }
    
    assert(tanda.status == ACTIVE);
    
    auto recipient = tanda.getRecipient();
    auto payout = recipient.claimPayout();
    assert(payout.amount == 500);
    
    for (int i = 0; i < 4; i++) {
        auto r = tanda.getRecipient();
        r.claimPayout();
    }
    
    assert(tanda.status == COMPLETED);
    
    for (auto& member : members) {
        auto withdrawal = member.withdrawAll();
        assert(withdrawal.principal > 0);
    }
}
```

---

## Security Considerations

1. **Principal Lock**: Verify principal cannot be withdrawn before CD term expiry
2. **Penalty Distribution**: Ensure penalties correctly distributed to good-faith members
3. **Adaptor Signatures**: Verify payout secret mechanism
4. **Early Withdrawal**: Confirm interest reduction applied correctly
5. **Replay Protection**: Add nonce to all tanda transactions
6. **Joint CD Access**: Ensure only tanda members can access joint CD funds

---

## Implementation Decision Points

The following can be decided during implementation:

1. **Exact buffer window size** - recommend ~100 blocks between epochs
2. **Default lock-in epochs** - currently 1, can be configurable
3. **Interest withdrawal timing** - epoch start vs end
4. **Gossip message frequency** - on change vs periodic

---

## Protocol Flow Summary

```
Create → WAITING (need 2 payments from all)
    ↓
ACTIVE (all locked)
    ↓
Lock-in passes (1 epoch)
    ↓
Joint CD created → interest calculated on bundled amount
    ↓
Each epoch:
  - Interest accrues on Joint CD
  - Interest available to pull
  - At epoch end: member can request withdrawal (if CD term expired)
  - If pull before turn → reduced/no interest from that round
    ↓
Full rotation → Buffer window → No penalty
    ↓
System auto-rollover → Next cycle begins
```
