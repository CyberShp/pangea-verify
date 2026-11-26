# pangea-verify

Clean-room multi-node live verification harness and self-evolving test knowledge engine for PANGEA.

## Core Capabilities

- **Multi-Node Topology & Credential Vault** (`src/topology.js`, `src/credentials.js`): Supports arbitrary node graphs (`host`, `controller`, `switch`, `bmc`, `jump`), `jump_via` SSH bastion tunneling, encrypted credentials (`DPAPI` on Windows, `AES-256-GCM` on Linux/macOS), deterministic `topo-adapter` scripts, and strict separation between `protected` management plane and `test_resources` target whitelist.
- **Phase-Gated Safety Harness** (`src/harness.js`, `src/safety-policy.js`): Enforces `preflight -> probe_readonly -> armed -> teardown_audit`. Mutating operations on whitelisted test resources are physically locked until `register-cleanup` is registered. Signs every SSH (`exec`, `bg`, `interactive` PTY) and controlled HTTPS REST action into an immutable `transcript.jsonl` ledger.
- **Four-Gate Knowledge Pack Engine** (`src/knowledge.js`): Organizes reusable atomic `CapabilityCard`s behind a compact `<2000 token` `catalog.json` index, enforcing de-binding literal checks, mandatory cleanup pairing, live transcript promotion proof, and read-only batch execution with mismatch feedback logging.

## Quick Verification

```bash
npm install
npm test
```
