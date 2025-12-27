# Protocol Specification — ZK-Verified Computation Gateway (ZKCG)

This document specifies the core protocol, state machine, proof interfaces, and transition rules of the ZK-Verified Computation Gateway (ZKCG).

It is designed to be:
- **Precise** — deterministic in behavior
- **Auditable** — comprehensible by other engineers
- **Robust** — covers edge cases and error conditions

---

## Table of Contents

1. Protocol Overview  
2. Actors  
3. Core Concepts  
4. State Definition  
5. Message Formats  
6. Valid State Transition Rules  
7. Policy Constraints  
8. Verifier Semantics  
9. Error Codes & Rejections  
10. Extensions (Phase 2)

---

## 1. Protocol Overview

ZKCG is a verifier protocol that enables clients (provers) to submit zero-knowledge proofs that a computation was executed correctly and adheres to specific policy constraints. The verifier node verifies the proof and updates the protocol state when all checks pass.

---

## 2. Actors

- **Prover (Client)**: Executes computation off-chain and produces a ZK proof √  
- **Verifier Node**: Validates proofs, enforces policies, updates state √  
- **Observer**: Optional read-only entity monitoring public state √

All actors may be real machines in distributed systems.

---

## 3. Core Concepts

### 3.1 Proof
A zero-knowledge proof that attests to the correctness of a computation with respect to given public inputs.

### 3.2 Public Inputs
Data that is included in each proof and required for verification, such as:
- protocol version
- threshold values
- previous state commitment

### 3.3 Private Inputs
Data used by the prover but not revealed to the verifier.

### 3.4 Commitment
A cryptographic commitment (e.g., Merkle root) representing the post-computation state.

---

## 4. State Definition

The verifier maintains a deterministic state:

```rust
struct ProtocolState {
    state_root: Hash,
    nonce: u64,
    epoch: u64,
}
```
state_root: Merkle commitment representing current state √

nonce: strictly increasing counter √

epoch: version or generation identifier √

##5. Message Formats
###5.1 Proof Submission
json
Copy code
{
  "proof": "<base64-encoded proof>",
  "public_inputs": {
    "threshold": "<uint64>",
    "old_state_root": "<hash>",
    "nonce": "<uint64>"
  },
  "new_state_commitment": "<hash>"
}
##6. Valid State Transition Rules
A transition is valid if ALL of the following hold:

public_inputs.old_state_root == current state_root

public_inputs.nonce == current nonce + 1

The ZK proof is valid (verifier confirms)

The computed result satisfies policy constraints

new_state_commitment correctly reflects the committed state after the result

If any rule fails, the submission is rejected.

##7. Policy Constraints
For Phase 1, we enforce a private risk or score check:

Constraint: computed_score <= threshold

This constraint must be embedded in the proof.

##8. Verifier Semantics
Upon receiving a proof submission:

Parse message

Validate message format

Check that old_state_root and nonce match current state

Verify the ZK proof with the given public_inputs

Enforce policy constraints

Compute and persist new state

Emit event/log

##9. Error Codes & Rejections
Errors are defined as:

Code	Meaning
ERR_INVALID_FORMAT	Bad message structure
ERR_STATE_MISMATCH	Old state doesn’t match current
ERR_NONCE_INVALID	Invalid nonce
ERR_PROOF_INVALID	Proof verification failed
ERR_POLICY_VIOLATION	Policy constraint not satisfied
ERR_COMMITMENT_MISMATCH	New commitment doesn’t match

Each error should be logged/returned to the client.

##10. Extensions (Phase 2)
Pluggable Proof Backends
In Phase 2, proofs may be:

circuit proofs (e.g., Halo2)

zkVM proofs (e.g., RISC Zero / SP1)

The verifier interface remains the same; only the backend implementation differs.

Versioning
To support upgrades, the epoch field may be used to route verification logic.

Provenance Statement
This specification is designed to be:

unambiguous

machine-verifiable

extensible

All state transforms and policy filters are deterministic.
