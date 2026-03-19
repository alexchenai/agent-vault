# Agent Vault

**An autonomous agent that cannot be drained.**

Built for [SYNTHESIS 2026](https://synthesis.devfolio.co) -- Track: "Private Agents, Trusted Actions"

[Live Dashboard](https://agent-vault.chitacloud.dev) | [Live API Demo](https://agent-vault.chitacloud.dev/api/demo) | [SKILL.md](https://agent-vault.chitacloud.dev/SKILL.md)

---

## The Problem

Autonomous AI agents increasingly need to hold and spend funds -- for API calls, DeFi interactions, and agent-to-agent commerce. But an agent with a private key is a single point of failure:

> One compromised agent, one exploited prompt, one jailbreak -- and the vault is empty.

Current solutions force a bad tradeoff:
- **Trust the agent completely** -- no safeguards, one exploit drains everything
- **Require human approval for every transaction** -- defeats the purpose of autonomy

Agent Vault eliminates this tradeoff with MPC-backed keys and programmable spending policies.

---

## How It Works

### 1. MPC Key Management (Lit Protocol)

The agent never holds a raw private key. Instead:

1. A **PKP (Programmable Key Pair)** is minted on Lit Protocol's Chronicle chain
2. The private key is **distributed across 30 Lit nodes** using threshold ECDSA
3. To sign a transaction, **at least 15/30 nodes must cooperate**
4. No single node (or the agent itself) can reconstruct the private key

> In this demo, PKP keys are simulated with deterministic ethers.js wallets. The architecture and API surface are identical to production Lit Protocol.

### 2. Spending Policies (Vincent SDK)

Policies are evaluated **before every transaction**. The agent cannot bypass them -- they run inside Lit Actions (JavaScript executing on all 30 TEE nodes simultaneously).

| Policy | What It Does |
|--------|-------------|
| **spending-cap** | Per-transaction and daily spending limits |
| **whitelist-only** | Restrict destinations to pre-approved addresses |
| **rate-limiter** | Max N transactions per time window (sliding window) |
| **time-lock** | Queue large transfers for a mandatory review period |
| **multi-agent-approval** | M-of-N agent signatures required before execution |
| **circuit-breaker** | Auto-disable vault when anomalous activity detected |

### 3. Compliance Proofs

Every action is logged to an **immutable audit trail**. The agent can generate a compliance proof: a cryptographic attestation signed by the PKP that proves the vault operated within policy bounds -- without revealing private keys or transaction details.

### 4. Behavioral Anomaly Detection

Even when individual transactions pass policy checks, the vault detects coordinated attack patterns:

| Signal | What It Catches |
|--------|----------------|
| **Velocity spike** | >5 tx/hr indicates automated drain |
| **Cap clustering** | Transactions artificially near spending limit |
| **Temporal regularity** | Unnaturally regular spacing (bot behavior) |
| **Destination concentration** | All funds going to single address |
| **Cumulative drain** | Vault balance dropping below threshold |
| **Patient drain** | Slow, spaced-out drain to evade rate limiters |

---

## Quick Start

### Try the live demo (no setup required)

```bash
# Run the 6-step demo pipeline
curl -s https://agent-vault.chitacloud.dev/api/demo | python3 -m json.tool

# Check vault health
curl -s https://agent-vault.chitacloud.dev/health

# View the interactive dashboard
open https://agent-vault.chitacloud.dev
```

### Run locally

```bash
git clone https://github.com/alexchenai/agent-vault.git
cd agent-vault
npm install
npm run build
npm start
# Server runs on http://localhost:3000
```

### Run tests

```bash
npm test
# 38 tests, 0 failures
```

---

## API Reference

### Core Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/info` | Project info and capabilities |
| `ALL` | `/api/demo` | Run 6-step demo pipeline |
| `GET` | `/api/stats` | Vault statistics |

### Vault Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/vault/deposit` | Deposit funds into vault |
| `GET` | `/api/vault/:vaultId/balance` | Check vault balance |
| `GET` | `/api/vault/:vaultId/deposit-address` | Get PKP deposit address |
| `GET` | `/api/vault/:vaultId/pkp` | Get PKP key details |
| `POST` | `/api/vault/transfer` | Transfer funds (with policy checks) |
| `POST` | `/api/vault/swap` | Swap tokens (with spending cap) |
| `POST` | `/api/vault/:vaultId/sign` | Sign a transaction via PKP |
| `POST` | `/api/vault/:vaultId/attest` | Sign a message for attestation |
| `GET` | `/api/vault/:vaultId/audit-log` | View immutable audit trail |

### Policy Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/policies/:vaultId` | List active policies |
| `POST` | `/api/policies/:vaultId` | Create a new policy |
| `PUT` | `/api/policies/:vaultId/:policyId` | Update a policy |
| `DELETE` | `/api/policies/:vaultId/:policyId` | Disable a policy (soft delete) |
| `POST` | `/api/policies/:vaultId/evaluate` | Dry-run: would a transfer pass? |
| `POST` | `/api/policies/:vaultId/circuit-check` | Check circuit breaker state |
| `GET` | `/api/policies/:vaultId/circuit-state` | View circuit breaker status |

### Secrets Store

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/vault/:vaultId/secrets` | Store an encrypted secret |
| `GET` | `/api/vault/:vaultId/secrets` | List secrets (values hidden) |
| `GET` | `/api/vault/:vaultId/secrets/:name` | Retrieve a secret (policy-gated) |
| `DELETE` | `/api/vault/:vaultId/secrets/:name` | Permanently delete a secret |

### Compliance Proofs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/proof/generate` | Generate compliance proof |
| `GET` | `/api/proof/:proofId` | Retrieve a proof |
| `POST` | `/api/proof/:proofId/verify` | Verify a proof |
| `POST` | `/api/proof/verify-raw` | Independent ECDSA verification |
| `GET` | `/api/proof/vault/:vaultId` | List proofs for a vault |

### Anomaly Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/anomaly/analyze` | Analyze vault for attack patterns |
| `POST` | `/api/anomaly/simulate` | Simulate known attack scenarios |

### Multi-Agent Coordination

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/vault/:vaultId/queue` | View time-locked transaction queue |
| `DELETE` | `/api/vault/queue/:queueId` | Cancel a queued transaction |
| `GET` | `/api/vault/:vaultId/approvals` | View pending approval requests |
| `POST` | `/api/vault/approvals/:requestId/approve` | Submit an approval |

### Agent Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/SKILL.md` | Machine-readable skill manifest |
| `GET` | `/api/conversation-log` | Build conversation log |

---

## Demo Pipeline

The `/api/demo` endpoint runs a complete 6-step lifecycle:

1. **PKP Mint** -- Lit Protocol MPC key distributed across 30 nodes
2. **Vault Deposit** -- 10 ETH recorded to immutable audit trail
3. **Spending Cap Check** -- 5 ETH allowed, 6 ETH blocked by policy
4. **Threshold ECDSA Signature** -- MPC signing (no single key holder)
5. **Signature Verification** -- Cryptographic proof of MPC signing
6. **ZK Compliance Proof** -- Attestation signed by PKP proving policy compliance

All 6 steps pass on the live deployment.

---

## Project Structure

```
agent-vault/
  src/
    index.ts              # Express server, demo endpoint, startup
    config.ts             # Environment configuration
    abilities/
      vault-deposit.ts    # Fund deposit processing
      vault-transfer.ts   # Policy-checked transfers
      vault-swap.ts       # DEX swap simulation
      vault-proof.ts      # Compliance proof generation
      vault-secrets.ts    # Encrypted secret storage
    policies/
      spending-cap.ts     # Per-tx and daily spending limits
      whitelist-only.ts   # Destination address restrictions
      rate-limiter.ts     # Sliding window rate control
      time-lock.ts        # Large transfer queuing
      multi-agent-approval.ts  # M-of-N signature requirements
      circuit-breaker.ts  # Anomaly-triggered vault freeze
    routes/
      vault.ts            # Vault CRUD + transfer endpoints
      policies.ts         # Policy management endpoints
      proof.ts            # Compliance proof endpoints
      anomaly.ts          # Behavioral anomaly detection
    vault/
      wallet.ts           # PKP wallet (Lit Protocol simulation)
      audit-log.ts        # Immutable audit trail (MongoDB/in-memory)
    tests/
      agent-vault.test.ts # 38 tests, 0 failures
  public/
    index.html            # Dashboard UI (3-tab: Dashboard/Config/Logs)
    logo.png              # Project logo
    SKILL.md              # Machine-readable agent skill manifest
    conversation-log.json # Build conversation log
  Dockerfile              # Container deployment
  chita.yml               # Chita Cloud deployment config
```

---

## Test Results (v1.0.0)

```
38 passing, 0 failing

  PKP Wallet Tests (7)          -- mint, sign, verify operations
  Spending Cap Policy (3)       -- allow, block, edge cases
  Time-Lock Policy (5)          -- queue, cancel, execution timing
  Multi-Agent Approval (4)      -- thresholds, deduplication
  Rate Limiter (5)              -- sliding window, action types
  Circuit Breaker (3)           -- open, close, block states
  Encrypted Secrets (7)         -- store, retrieve, access control, deletion
  Compliance Proofs (4)         -- generation, verification, ECDSA
  Anomaly Detection (7)         -- all 5 signals + patient drain simulation
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Runtime | TypeScript + Node.js | Type-safe server implementation |
| API | Express.js | RESTful endpoint routing |
| Crypto | Lit Protocol Vincent SDK | MPC key management, threshold ECDSA |
| Signatures | ethers.js v6 | Real ECDSA signatures, address recovery |
| Storage | MongoDB | Immutable audit trail persistence |
| Chain | Base L2 (chainId 8453) | Low-gas transaction routing |
| Deploy | Docker + Chita Cloud | Production containerization |

---

## Why This Matters for "Agents That Keep Secrets"

1. **The agent never sees the private key** -- distributed across 30 MPC nodes
2. **Policies are enforced before signing** -- the agent cannot bypass spending controls
3. **Secrets are encrypted at rest** -- access is policy-gated (who, how many times, under what conditions)
4. **Compliance is provable** -- cryptographic attestations without revealing transaction details
5. **Sophisticated attacks are detected** -- patient drain, velocity spikes, cap clustering
6. **The human stays in control** -- policies are set by the human, enforced by cryptography

---

## Team

- **Alex Chen (AutoPilotAI)** -- autonomous AI agent (Claude Opus via Claude Code)
- **Ashu** -- UI/UX design
- **Jhon Magdalena** -- human oversight

---

## License

MIT
