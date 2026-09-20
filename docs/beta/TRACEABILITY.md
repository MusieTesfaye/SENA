# Requirements traceability

**Generated** by `docs/beta/traceability.py` — do not edit by hand.

Maps every requirement in the SRS to the code that cites it and the tests
that exercise it. A requirement showing `—` in both columns is not
implemented; that is information, not an error.

A citation means the source file names the requirement ID. It is evidence of
intent, not proof of correctness — read the cited code and its tests before
treating a row as satisfied.

**51 of 101 requirements are cited somewhere in the implementation.**

| Requirement | Status | Implementation | Tests |
|---|---|---|---|
| `REQ-AUTH-001` | not implemented | — | — |
| `REQ-AUTH-002` | implemented | [`address.rs`](../../crates/sena-primitives/src/address.rs), [`encoding.rs`](../../crates/sena-primitives/src/encoding.rs) | — |
| `REQ-AUTH-003` | implemented | [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-AUTH-004` | implemented | [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-AUTH-005` | not implemented | — | — |
| `REQ-AUTH-006` | not implemented | — | — |
| `REQ-AUTH-007` | not implemented | — | — |
| `REQ-SOCIAL-001` | implemented | [`instruction.rs`](../../crates/sena-stf/src/instruction.rs), [`social.rs`](../../crates/sena-stf/src/social.rs), [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-SOCIAL-002` | implemented | [`encoding.rs`](../../crates/sena-primitives/src/encoding.rs), [`identity.rs`](../../crates/sena-primitives/src/identity.rs) | — |
| `REQ-SOCIAL-003` | implemented | [`identity.rs`](../../crates/sena-primitives/src/identity.rs), [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-SOCIAL-004` | implemented | [`keys.rs`](../../crates/sena-stf/src/keys.rs), [`rpc.rs`](../../crates/sena-node/src/rpc.rs) | — |
| `REQ-SOCIAL-005` | implemented | [`keys.rs`](../../crates/sena-stf/src/keys.rs) | — |
| `REQ-GAS-001` | implemented | [`gas.rs`](../../crates/sena-stf/src/gas.rs), [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-GAS-002` | not implemented | — | [`execution.rs`](../../crates/sena-stf/tests/execution.rs) |
| `REQ-GAS-003` | implemented | [`gas.rs`](../../crates/sena-stf/src/gas.rs), [`governance.rs`](../../crates/sena-stf/src/governance.rs), [`instruction.rs`](../../crates/sena-stf/src/instruction.rs), [`keys.rs`](../../crates/sena-stf/src/keys.rs) | — |
| `REQ-GAS-004` | not implemented | — | — |
| `REQ-GAS-005` | implemented | [`instruction.rs`](../../crates/sena-stf/src/instruction.rs) | — |
| `REQ-GAS-006` | not implemented | — | — |
| `REQ-GAS-007` | implemented | [`execute.rs`](../../crates/sena-stf/src/execute.rs) | — |
| `REQ-GAS-008` | not implemented | — | — |
| `REQ-GAS-009` | not implemented | — | — |
| `REQ-GAS-010` | implemented | [`gas.rs`](../../crates/sena-stf/src/gas.rs) | — |
| `REQ-GOV-001` | implemented | [`governance.rs`](../../crates/sena-stf/src/governance.rs) | — |
| `REQ-GOV-002` | implemented | [`keys.rs`](../../crates/sena-stf/src/keys.rs) | — |
| `REQ-GOV-003` | implemented | [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | — |
| `REQ-GOV-004` | implemented | [`instruction.rs`](../../crates/sena-stf/src/instruction.rs) | — |
| `REQ-GOV-005` | implemented | [`instruction.rs`](../../crates/sena-stf/src/instruction.rs), [`keys.rs`](../../crates/sena-stf/src/keys.rs) | — |
| `REQ-GOV-006` | implemented | [`transaction.rs`](../../crates/sena-stf/src/transaction.rs) | [`execution.rs`](../../crates/sena-stf/tests/execution.rs) |
| `REQ-GOV-007` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move), [`execute.rs`](../../crates/sena-stf/src/execute.rs), [`governance.rs`](../../crates/sena-stf/src/governance.rs), [`lib.rs`](../../crates/sena-params/src/lib.rs) | [`execution.rs`](../../crates/sena-stf/tests/execution.rs) |
| `REQ-FRAUD-004` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move), [`lib.rs`](../../crates/sena-params/src/lib.rs) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-001` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move) | — |
| `REQ-FRAUD-002` | not implemented | — | — |
| `REQ-FRAUD-003` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-005` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move), [`bridge.move`](../../move/sena/sources/bridge.move) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-006` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-007` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`rpc.rs`](../../crates/sena-node/src/rpc.rs), [`sequencer.rs`](../../crates/sena-node/src/sequencer.rs), [`store.rs`](../../crates/sena-node/src/store.rs) | — |
| `REQ-FRAUD-008` | not implemented | — | — |
| `REQ-FRAUD-009` | implemented | [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-010` | not implemented | — | — |
| `REQ-FRAUD-011` | implemented | [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-012` | implemented | [`bisection.rs`](../../crates/sena-fraudproof/src/bisection.rs), [`disputes.move`](../../move/sena/sources/disputes.move) | — |
| `REQ-FRAUD-013` | not implemented | — | — |
| `REQ-FRAUD-014` | implemented | [`bisection.rs`](../../crates/sena-fraudproof/src/bisection.rs), [`disputes.move`](../../move/sena/sources/disputes.move), [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-015` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move), [`bisection.rs`](../../crates/sena-fraudproof/src/bisection.rs), [`disputes.move`](../../move/sena/sources/disputes.move), [`lib.rs`](../../crates/sena-params/src/lib.rs) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-016` | implemented | [`lib.rs`](../../crates/sena-state/src/lib.rs), [`osp.rs`](../../crates/sena-fraudproof/src/osp.rs) | — |
| `REQ-FRAUD-017` | implemented | [`execute.rs`](../../crates/sena-stf/src/execute.rs), [`osp.move`](../../move/sena/sources/osp.move) | — |
| `REQ-FRAUD-018` | implemented | [`osp.rs`](../../crates/sena-fraudproof/src/osp.rs) | — |
| `REQ-FRAUD-019` | implemented | [`assertion.rs`](../../crates/sena-fraudproof/src/assertion.rs), [`assertions.move`](../../move/sena/sources/assertions.move) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-020` | implemented | [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-021` | not implemented | — | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `REQ-FRAUD-022` | not implemented | — | — |
| `REQ-FRAUD-023` | not implemented | — | — |
| `REQ-FRAUD-024` | implemented | [`verifier.rs`](../../crates/sena-fraudproof/src/verifier.rs), [`verifier_node.rs`](../../crates/sena-node/src/verifier_node.rs) | — |
| `REQ-FRAUD-025` | implemented | [`verifier.rs`](../../crates/sena-fraudproof/src/verifier.rs) | — |
| `REQ-FRAUD-026` | implemented | [`verifier_node.rs`](../../crates/sena-node/src/verifier_node.rs) | — |
| `REQ-FRAUD-027` | implemented | [`rpc.rs`](../../crates/sena-node/src/rpc.rs) | [`node.rs`](../../crates/sena-node/tests/node.rs) |
| `REQ-FRAUD-028` | implemented | [`bridge.move`](../../move/sena/sources/bridge.move) | — |
| `REQ-FRAUD-029` | implemented | [`bridge.move`](../../move/sena/sources/bridge.move), [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-030` | implemented | [`lib.rs`](../../crates/sena-params/src/lib.rs) | — |
| `REQ-FRAUD-031` | implemented | [`account.rs`](../../crates/sena-stf/src/account.rs), [`address.rs`](../../crates/sena-primitives/src/address.rs), [`gas.rs`](../../crates/sena-stf/src/gas.rs), [`hash.rs`](../../crates/sena-primitives/src/hash.rs), [`lib.rs`](../../crates/sena-primitives/src/lib.rs), [`trie.rs`](../../crates/sena-state/src/trie.rs) | — |
| `REQ-FRAUD-032` | not implemented | — | — |
| `REQ-FRAUD-033` | not implemented | — | — |
| `REQ-FRAUD-034` | not implemented | — | — |
| `REQ-CORE-001` | not implemented | — | — |
| `REQ-CORE-002` | not implemented | — | — |
| `REQ-CORE-003` | not implemented | — | — |
| `REQ-CORE-004` | implemented | [`lib.rs`](../../crates/sena-state/src/lib.rs) | — |
| `REQ-CORE-005` | implemented | [`rpc.rs`](../../crates/sena-node/src/rpc.rs), [`sequencer.rs`](../../crates/sena-node/src/sequencer.rs) | [`node.rs`](../../crates/sena-node/tests/node.rs) |
| `REQ-CORE-006` | not implemented | — | — |
| `NFR-PERF-001` | not implemented | — | — |
| `NFR-PERF-002` | not implemented | — | — |
| `NFR-PERF-003` | not implemented | — | — |
| `NFR-PERF-004` | not implemented | — | — |
| `NFR-PERF-005` | not implemented | — | — |
| `NFR-PERF-006` | implemented | [`bisection.rs`](../../crates/sena-fraudproof/src/bisection.rs), [`lib.rs`](../../crates/sena-params/src/lib.rs) | [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) |
| `NFR-PERF-007` | not implemented | — | — |
| `NFR-SEC-001` | not implemented | — | — |
| `NFR-SEC-002` | not implemented | — | — |
| `NFR-SEC-003` | not implemented | — | — |
| `NFR-SEC-004` | not implemented | — | — |
| `NFR-SEC-005` | implemented | [`account.rs`](../../crates/sena-stf/src/account.rs), [`instruction.rs`](../../crates/sena-stf/src/instruction.rs) | [`execution.rs`](../../crates/sena-stf/tests/execution.rs) |
| `NFR-SEC-006` | not implemented | — | — |
| `NFR-SEC-007` | not implemented | — | — |
| `NFR-SEC-008` | not implemented | — | — |
| `NFR-SEC-009` | not implemented | — | — |
| `NFR-SEC-010` | not implemented | — | — |
| `NFR-SEC-011` | not implemented | — | — |
| `NFR-SEC-012` | implemented | [`README.md`](../../move/README.md) | — |
| `NFR-REL-001` | not implemented | — | — |
| `NFR-REL-002` | not implemented | — | — |
| `NFR-REL-003` | not implemented | — | — |
| `NFR-REL-004` | implemented | [`sequencer.rs`](../../crates/sena-node/src/sequencer.rs), [`trie.rs`](../../crates/sena-state/src/trie.rs), [`verifier.rs`](../../crates/sena-fraudproof/src/verifier.rs) | — |
| `NFR-REL-005` | not implemented | — | — |
| `NFR-MAINT-001` | not implemented | — | — |
| `NFR-MAINT-002` | not implemented | — | — |
| `NFR-MAINT-003` | not implemented | — | — |
| `NFR-MAINT-004` | implemented | [`execute.rs`](../../crates/sena-stf/src/execute.rs), [`lib.rs`](../../crates/sena-node/src/lib.rs), [`verifier_node.rs`](../../crates/sena-node/src/verifier_node.rs) | — |
| `NFR-MAINT-005` | not implemented | — | — |
| `NFR-PORT-001` | not implemented | — | — |
| `NFR-PORT-002` | not implemented | — | — |
| `NFR-PORT-003` | not implemented | — | — |
