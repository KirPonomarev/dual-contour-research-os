# Public architecture boundary

The system has six logical planes:

1. Governance — policy, contracts, authority and promotion.
2. Domain — scientific semantics, data, validators and canonical outcomes.
3. Bridge control — admission, queue, leases, budgets and mechanical state.
4. Execution — bounded offline runners and durable checkpoints.
5. Validation — independent checks and immutable validation receipts.
6. Evolution — replication, learning decisions and governed mutation proposals.

The public repository implements domain-neutral Bridge contracts and control-plane primitives. Domain repositories remain canonical owners of scientific truth and sensitive artifacts.

Canonical flow:

```text
source reference
→ hypothesis/protocol reference
→ admission and budget reservation
→ Permit and AttemptLease
→ offline execution and checkpoint
→ staging and trusted ingestion
→ ExecutionReceipt
→ ValidationReceipt
→ domain registry writer applies outcome
→ domain receipts referenced by Bridge
→ LearningDecision
```

Bridge success is mechanical, never scientific. A validator proposes an outcome; a domain-owned registry writer applies it.
