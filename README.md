# pangea-verify

Clean-room multi-node live verification harness and self-evolving test knowledge engine for PANGEA.

## Architecture

- **Multi-Node Topology & Credential Vault** (`src/topology.js`, `src/credentials.js`): Arbitrary node graphs (`host`, `controller`, `switch`, `bmc`, `jump`), `jump_via` SSH bastion tunneling, encrypted secrets (`DPAPI` on Windows, `AES-256-GCM` on Linux/macOS), deterministic `topo-adapter` scripts, and strict separation between `protected` management plane and `test_resources` target whitelist.
- **Phase-Gated Safety Harness** (`src/harness.js`, `src/safety-policy.js`, `src/transport-ssh.js`, `src/transport-http.js`): Enforces `preflight -> probe_readonly -> armed -> teardown_audit`. Mutating operations on whitelisted test resources are physically locked until `register-cleanup` is registered. Signs every SSH (`exec`, `bg`, `interactive` PTY) and controlled HTTPS REST action into an immutable `transcript.jsonl` ledger.
- **Four-Gate Knowledge Pack Engine** (`src/knowledge.js`): Organizes reusable atomic `CapabilityCard`s behind a compact `catalog.json` index, enforcing de-binding literal checks, mandatory cleanup pairing, live transcript promotion proof, and read-only batch execution with mismatch feedback logging.
- **Read-Only Code & Legacy Python Distiller** (`src/code-index.js`, `tools/py_ast_index.py`): Zero-dependency Python `ast` indexer (never imports or executes target code) plus source CLI/inject-point scanner for white-box command lookup.
- **Dual-Mode Agent Drivers**:
  - **Mode A (Interactive Trainer)**: Standard stdio MCP server (`src/mcp-server.js`, `pangea-verify mcp`) + trainer SOP (`skills/trainer/SKILL.md`) for chat-based topology onboarding, command distillation, live trial, and verified card promotion.
  - **Mode B (Autonomous Batch Runner)**: ACP worker adapter (`src/runner-acp.js`) consuming read-only verified knowledge & code maps with single-worker repair continuation and Gate-4 feedback logging.

## Quick Verification

```bash
npm install
npm test
```

## CLI Usage

```bash
# Start stdio MCP server for interactive training (DSH / OpenCode / CodeAgent)
node bin/cli.mjs mcp --store ~/.pangea-verify/topologies.json --pack /path/to/knowledge-pack --data-root /path/to/runtime-data

# Read-only AST index of legacy Python automation
node bin/cli.mjs index-py --root /path/to/legacy-auto --topo-only true

# Scan target source CLI macros & inject points into Knowledge Pack code-maps
node bin/cli.mjs index-cli --root /path/to/target-src --pack /path/to/knowledge-pack --name storage-core
```
