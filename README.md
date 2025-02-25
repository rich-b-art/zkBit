# zkBit Protocol Documentation

**Version:** 1.0.0  
**Network:** Stacks Layer 2 (Bitcoin-secured)  
**Standard:** SIP-010 Compliant

## Protocol Overview

zkBit implements a non-custodial privacy layer for Bitcoin transactions using zero-knowledge cryptography and Merkle tree commitments. The system enables confidential transfers while maintaining regulatory compliance through selective transparency features.

### Key Components

1. **Merkle Commitment Tree** (Height 20, SHA-256)
2. **Nullifier Set** (Prevent double-spending)
3. **Compliance Oracle** (Regulatory interface)
4. **SIP-010 Token Bridge** (BTC-pegged assets)

## Technical Specifications

### System Constants

```clarity
(define-constant MERKLE-TREE-HEIGHT u20)     ;; 1,048,576 capacity
(define-constant MAX_DEPOSIT_AMOUNT u1000000) ;; 0.01 BTC base units
(define-constant CONTRACT_OWNER 0x...)        ;; Admin multisig address
```

### State Architecture

| Variable          | Type   | Description                  |
| ----------------- | ------ | ---------------------------- |
| `merkle_root`     | buff32 | Current root hash            |
| `leaf_index`      | uint   | Next available leaf position |
| `protocol_paused` | bool   | Emergency stop state         |
| `total_deposits`  | uint   | Cumulative deposited amount  |

### Storage Models

**Commitment Registry**

```clarity
{
  commitment: buff32 => {
    index: uint,
    block: uint,
    user: principal,
    amount: uint
  }
}
```

**Nullifier Set**

```clarity
{
  nullifier: buff32 => {
    used: bool,
    amount: uint,
    timestamp: uint
  }
}
```

## Core Operations

### Private Deposit Flow

1. User initiates deposit with cryptographic commitment
2. System verifies:
   - Valid SIP-010 token transfer
   - Commitment uniqueness
   - Deposit limit compliance
3. Merkle tree updated with new leaf
4. Deposit recorded in registry

**Transaction Diagram:**

```
User -> zkBit: Deposit(commitment, amount)
zkBit --> MerkleTree: Insert leaf
zkBit --> Registry: Record metadata
zkBit --> User: Leaf index receipt
```

### Confidential Withdrawal Process

1. User submits zk-SNARK proof with nullifier
2. System validates:
   - Valid Merkle proof
   - Nullifier uniqueness
   - Compliance thresholds
3. Funds transferred to recipient
4. Nullifier marked as spent

**Proof Requirements:**

- Merkle path verification (20 levels)
- Nullifier hash correctness
- Amount range proof

## Compliance Features

### Audit Interface

```clarity
(define-read-only (get-compliance-proof (commitment buff32))
  ;; Returns deposit metadata for regulatory inspection
```

### Transaction Freezing

```clarity
(define-public (compliance-freeze (nullifier buff32) (freeze bool))
  ;; Authorized regulator can freeze suspicious transactions
```

## Security Model

### Cryptographic Primitives

- **Commitments:** SHA-256
- **Nullifiers:** Pedersen hashes
- **Merkle Proofs:** SHA-256 binary tree

### Attack Mitigations

| Threat          | Protection Mechanism      |
| --------------- | ------------------------- |
| Double-spending | Nullifier set tracking    |
| Frontrunning    | Transaction entropy       |
| Sybil attacks   | Deposit amount limits     |
| Dusting         | Minimum deposit threshold |

## Administrative Functions

### Protocol Governance

```clarity
(define-public (toggle-protocol-pause))
  ;; Emergency circuit breaker control

(define-public (admin-recovery (token principal) (amount uint))
  ;; Multisig-controlled asset recovery
```
