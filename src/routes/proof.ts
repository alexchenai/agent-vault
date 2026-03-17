/**
 * routes/proof.ts — Compliance Proof Generation and Verification
 *
 * Generates verifiable compliance reports from the audit trail.
 * In production: these would be ZK proofs using Lit Protocol's
 * threshold signing to attest the vault stayed within policy.
 * For the demo: cryptographic hash-chained summaries with signatures.
 */

import { Router, Request, Response } from 'express';
import { createHash } from 'crypto';
import { getAuditTrail, logAction, isConnected } from '../vault/audit-log';
import { getOrCreatePKP, signMessage } from '../vault/wallet';

export const proofRouter = Router();

// In-memory proof store
const proofStore: Map<string, ComplianceProof> = new Map();

interface ComplianceProof {
  proofId: string;
  vaultId: string;
  fromTimestamp: string;
  toTimestamp: string;
  generatedAt: string;
  summary: {
    totalDeposits: number;
    totalTransfers: number;
    totalSwaps: number;
    totalVolume: number;
    transactionCount: number;
    policyViolations: number;
  };
  auditRoot: string;      // SHA-256 hash of all audit entries
  attestation: string;    // In production: Lit threshold signature
  entries: number;
  discloseLevel: 'full' | 'summary' | 'count-only';
}

function generateProofId(): string {
  return 'proof-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

// ─── POST /api/proof/generate ─────────────────────────────────

proofRouter.post('/generate', async (req: Request, res: Response) => {
  try {
    const { vaultId, fromTimestamp, toTimestamp, discloseLevel = 'summary' } = req.body;

    if (!vaultId) {
      return res.status(400).json({ error: 'vaultId is required' });
    }

    const from = fromTimestamp ? new Date(fromTimestamp) : new Date(Date.now() - 86400000 * 30);
    const to = toTimestamp ? new Date(toTimestamp) : new Date();

    if (isNaN(from.getTime()) || isNaN(to.getTime())) {
      return res.status(400).json({ error: 'Invalid timestamp format. Use ISO 8601 (e.g., 2026-03-16T00:00:00Z)' });
    }

    // Fetch all audit entries for the vault
    const allEntries = await getAuditTrail(vaultId, 500);
    const entries = allEntries.filter(
      (e) => new Date(e.timestamp) >= from && new Date(e.timestamp) <= to
    );

    // Compute summary
    const summary = {
      totalDeposits: entries.filter((e) => e.action === 'deposit').length,
      totalTransfers: entries.filter((e) => e.action === 'transfer').length,
      totalSwaps: entries.filter((e) => e.action === 'swap').length,
      totalVolume: entries
        .filter((e) => e.action === 'deposit' || e.action === 'transfer')
        .reduce((sum, e) => sum + (Number(e.details.amount) || 0), 0),
      transactionCount: entries.length,
      policyViolations: entries.filter((e) => e.action === 'policy_violation').length,
    };

    // Build audit root (hash chain over all entries)
    const entryHashes = entries.map((e) =>
      createHash('sha256')
        .update(JSON.stringify({ vaultId: e.vaultId, action: e.action, timestamp: e.timestamp, details: e.details }))
        .digest('hex')
    );
    const auditRoot = createHash('sha256').update(entryHashes.join('')).digest('hex');

    // Build attestation using Lit Protocol PKP signing
    // Production: BLS12-381 threshold signature over auditRoot signed by all 30 Lit nodes
    // Demo: ECDSA signature from PKP-derived key (same architecture, simulated MPC)
    const proofPayload = JSON.stringify({ vaultId, auditRoot, from: from.toISOString(), to: to.toISOString(), summary });
    const pkp = await getOrCreatePKP(vaultId);
    const attestation = await signMessage(pkp, proofPayload);

    const proofId = generateProofId();
    const proof: ComplianceProof = {
      proofId,
      vaultId,
      fromTimestamp: from.toISOString(),
      toTimestamp: to.toISOString(),
      generatedAt: new Date().toISOString(),
      summary,
      auditRoot,
      attestation,
      entries: entries.length,
      discloseLevel: discloseLevel as 'full' | 'summary' | 'count-only',
    };

    proofStore.set(proofId, proof);

    // Log the proof generation
    await logAction({
      vaultId,
      action: 'proof_generated',
      details: { proofId, auditRoot, entriesIncluded: entries.length, discloseLevel },
    });

    const response: Record<string, unknown> = {
      proofId,
      vaultId,
      generatedAt: proof.generatedAt,
      auditRoot,
      attestation,
      entriesIncluded: entries.length,
      storageMode: isConnected() ? 'mongodb' : 'in-memory',
      pkpAddress: pkp.ethAddress,
      litNetwork: pkp.litNetwork,
      attestationNote: 'ECDSA signature by Lit Protocol PKP. Verify: ethers.verifyMessage(proofPayload, attestation) === pkpAddress',
    };

    if (discloseLevel !== 'count-only') {
      response.summary = summary;
    } else {
      response.transactionCount = summary.transactionCount;
    }

    if (discloseLevel === 'full') {
      response.entries = entries;
    }

    return res.status(201).json(response);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Proof generation failed', details: msg });
  }
});

// ─── GET /api/proof/:proofId ──────────────────────────────────

proofRouter.get('/:proofId', async (req: Request, res: Response) => {
  const { proofId } = req.params;
  const proof = proofStore.get(proofId);
  if (!proof) {
    return res.status(404).json({ error: 'Proof not found', proofId });
  }
  return res.json(proof);
});

// ─── POST /api/proof/:proofId/verify ─────────────────────────

proofRouter.post('/:proofId/verify', async (req: Request, res: Response) => {
  const { proofId } = req.params;
  const proof = proofStore.get(proofId);
  if (!proof) {
    return res.status(404).json({ error: 'Proof not found', proofId });
  }

  // Re-derive the attestation and compare
  const proofPayload = JSON.stringify({
    vaultId: proof.vaultId,
    auditRoot: proof.auditRoot,
    from: proof.fromTimestamp,
    to: proof.toTimestamp,
    summary: proof.summary,
  });
  const expectedAttestation = createHash('sha256')
    .update(proofPayload + (process.env.LIT_API_KEY || 'agent-vault-demo'))
    .digest('hex');

  const valid = expectedAttestation === proof.attestation;

  return res.json({
    proofId,
    valid,
    vaultId: proof.vaultId,
    auditRoot: proof.auditRoot,
    generatedAt: proof.generatedAt,
    message: valid
      ? 'Proof is valid. Attestation signature matches.'
      : 'Proof verification failed. Attestation mismatch.',
    litProtocolNote: 'In production: verification uses Lit BLS threshold signature verification, anchored to on-chain PKP.',
  });
});

// ─── GET /api/proof/vault/:vaultId ───────────────────────────

proofRouter.get('/vault/:vaultId', async (req: Request, res: Response) => {
  const { vaultId } = req.params;
  const proofs = Array.from(proofStore.values()).filter((p) => p.vaultId === vaultId);
  return res.json({
    vaultId,
    count: proofs.length,
    proofs: proofs.map((p) => ({
      proofId: p.proofId,
      generatedAt: p.generatedAt,
      fromTimestamp: p.fromTimestamp,
      toTimestamp: p.toTimestamp,
      entriesIncluded: p.entries,
      auditRoot: p.auditRoot,
    })),
  });
});

// ─── POST /api/proof/verify-raw ───────────────────────────────
// Public independent verification endpoint
proofRouter.post('/verify-raw', async (req: Request, res: Response) => {
  try {
    const { proofPayload, attestation, expectedAddress } = req.body;
    if (!proofPayload || !attestation) {
      return res.status(400).json({ error: 'proofPayload and attestation are required' });
    }
    let recoveredAddress = '';
    let valid = false;
    let verificationError = '';
    try {
      const { ethers } = await import('ethers');
      const payload = typeof proofPayload === 'string' ? proofPayload : JSON.stringify(proofPayload);
      recoveredAddress = ethers.verifyMessage(payload, attestation);
      valid = expectedAddress ? recoveredAddress.toLowerCase() === expectedAddress.toLowerCase() : true;
    } catch (e: unknown) {
      verificationError = e instanceof Error ? e.message : String(e);
    }
    return res.json({
      valid, recoveredAddress, expectedAddress: expectedAddress || null,
      addressMatch: expectedAddress ? recoveredAddress.toLowerCase() === (expectedAddress||'').toLowerCase() : null,
      verificationError: verificationError || undefined,
      message: verificationError ? `Error: ${verificationError}` : valid ? `Valid. Signer: ${recoveredAddress}` : `Mismatch: ${recoveredAddress} != ${expectedAddress}`,
      verificationMethod: 'ethers.verifyMessage(proofPayload, attestation)',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Verification failed', details: msg });
  }
});
