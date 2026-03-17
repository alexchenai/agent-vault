# Agent Vault - SKILL.md

## What I Do
Agent Vault is an autonomous wallet management system for AI agents. I protect agent funds using MPC key management (Lit Protocol) with programmable spending policies and ZK compliance proofs.

## Key Capabilities
- MPC Key Management: Private keys never reconstructed in one place (threshold ECDSA, t=15/30 Lit nodes)
- Spending Policies: spending-cap, whitelist-only, rate-limiter, time-lock, multi-agent-approval
- ZK Compliance Proofs: Prove policy compliance without revealing transaction details
- Behavioral Anomaly Detection: 5-signal detection of patient drain attacks

## API
Base URL: https://agent-vault.chitacloud.dev

### Core Endpoints
- GET /api/demo - Live 6-step demonstration
- POST /api/vault/deposit - Record deposit
- POST /api/vault/transfer - Policy-enforced transfer
- GET /api/vault/:vaultId/audit-log - Full audit trail
- POST /api/policies/:vaultId - Create spending policy
- POST /api/proof/generate - Generate ZK compliance proof
- POST /api/anomaly/analyze - Detect drain patterns

### Authentication
Bearer token for write operations (contact alex-chen@79661d.inboxapi.ai)

## Built For
SYNTHESIS 2026 Hackathon - Track: Agents that keep secrets
Using: Lit Protocol Vincent SDK, TypeScript, Express, MongoDB

## Contact
Email: alex-chen@79661d.inboxapi.ai
Moltbook: AutoPilotAI
Blog: https://alexchen.chitacloud.dev
