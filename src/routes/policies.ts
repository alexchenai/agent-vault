/**
 * routes/policies.ts — CRUD Operations for Vault Policies
 */

import { Router, Request, Response } from 'express';
import {
  savePolicy,
  getPolicies,
  getAllPolicies,
  updatePolicy,
  logAction,
  isConnected,
} from '../vault/audit-log';
import { evaluateSpendingCap } from '../policies/spending-cap';

export const policiesRouter = Router();

const SUPPORTED_TYPES = ['spending-cap', 'whitelist-only', 'rate-limiter', 'time-lock', 'multi-agent-approval'] as const;
type PolicyType = typeof SUPPORTED_TYPES[number];

function storageMode(): string {
  return isConnected() ? 'mongodb' : 'in-memory';
}

// ─── GET /api/policies/:vaultId ───────────────────────────────

policiesRouter.get('/:vaultId', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const includeDisabled = req.query.all === 'true';
    const policies = includeDisabled
      ? await getAllPolicies(vaultId)
      : await getPolicies(vaultId);

    return res.json({
      vaultId,
      count: policies.length,
      policies,
      storageMode: storageMode(),
      supportedTypes: SUPPORTED_TYPES,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Failed to list policies', details: msg });
  }
});

// ─── POST /api/policies/:vaultId ─────────────────────────────

policiesRouter.post('/:vaultId', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const { type, config } = req.body;

    if (!type) {
      return res.status(400).json({
        error: 'type is required',
        supportedTypes: SUPPORTED_TYPES,
      });
    }

    if (!SUPPORTED_TYPES.includes(type as PolicyType)) {
      return res.status(400).json({
        error: `Unsupported policy type: ${type}`,
        supportedTypes: SUPPORTED_TYPES,
      });
    }

    if (!config || typeof config !== 'object') {
      return res.status(400).json({ error: 'config object is required' });
    }

    // Validate config per type
    if (type === 'spending-cap') {
      if (typeof config.perTransactionLimit !== 'number' || config.perTransactionLimit <= 0) {
        return res.status(400).json({ error: 'spending-cap requires perTransactionLimit (positive number in ETH)' });
      }
      if (typeof config.dailyLimit !== 'number' || config.dailyLimit <= 0) {
        return res.status(400).json({ error: 'spending-cap requires dailyLimit (positive number in ETH)' });
      }
    }

    if (type === 'whitelist-only') {
      if (!Array.isArray(config.addresses) || config.addresses.length === 0) {
        return res.status(400).json({ error: 'whitelist-only requires addresses array with at least one address' });
      }
    }

    const policyId = await savePolicy({
      vaultId,
      type: type as PolicyType,
      config,
      enabled: true,
    });

    // Log the policy creation
    await logAction({
      vaultId,
      action: 'policy_change',
      details: {
        operation: 'created',
        policyId,
        type,
        config,
      },
    });

    return res.status(201).json({
      success: true,
      policyId,
      vaultId,
      type,
      config,
      enabled: true,
      storageMode: storageMode(),
      message: `Policy of type '${type}' created for vault ${vaultId}`,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Failed to create policy', details: msg });
  }
});

// ─── PUT /api/policies/:vaultId/:policyId ────────────────────

policiesRouter.put('/:vaultId/:policyId', async (req: Request, res: Response) => {
  try {
    const { vaultId, policyId } = req.params;
    const updates = req.body;

    // Disallow changing immutable fields
    delete updates._id;
    delete updates.vaultId;
    delete updates.createdAt;

    const ok = await updatePolicy(vaultId, policyId, updates);
    if (!ok) {
      return res.status(404).json({ error: 'Policy not found', vaultId, policyId });
    }

    await logAction({
      vaultId,
      action: 'policy_change',
      details: { operation: 'updated', policyId, updates },
    });

    return res.json({
      success: true,
      policyId,
      vaultId,
      updates,
      storageMode: storageMode(),
      message: `Policy ${policyId} updated`,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Failed to update policy', details: msg });
  }
});

// ─── DELETE /api/policies/:vaultId/:policyId ─────────────────

policiesRouter.delete('/:vaultId/:policyId', async (req: Request, res: Response) => {
  try {
    const { vaultId, policyId } = req.params;

    // Soft delete: set enabled = false
    const ok = await updatePolicy(vaultId, policyId, { enabled: false });
    if (!ok) {
      return res.status(404).json({ error: 'Policy not found', vaultId, policyId });
    }

    await logAction({
      vaultId,
      action: 'policy_change',
      details: { operation: 'disabled', policyId },
    });

    return res.json({
      success: true,
      policyId,
      vaultId,
      storageMode: storageMode(),
      message: `Policy ${policyId} disabled (soft delete)`,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Failed to disable policy', details: msg });
  }
});

// ─── POST /api/policies/:vaultId/evaluate ────────────────────
// Check whether a hypothetical transfer would pass all policies

policiesRouter.post('/:vaultId/evaluate', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const { amount, to } = req.body;

    if (amount === undefined) {
      return res.status(400).json({ error: 'amount is required for evaluation' });
    }

    const parsedAmount = parseFloat(amount);
    const policies = await getPolicies(vaultId);
    const results = [];
    let allPassed = true;

    for (const policy of policies) {
      if (policy.type === 'spending-cap') {
        const cfg = policy.config as { perTransactionLimit: number; dailyLimit: number };
        const result = await evaluateSpendingCap(String(policy._id), cfg, vaultId, parsedAmount);
        results.push(result);
        if (!result.passed) allPassed = false;
      }
      if (policy.type === 'whitelist-only' && to) {
        const cfg = policy.config as { addresses: string[] };
        const isAllowed = cfg.addresses.map((a: string) => a.toLowerCase()).includes(to.toLowerCase());
        const result = {
          policyId: String(policy._id),
          policyType: 'whitelist-only',
          passed: isAllowed,
          reason: isAllowed ? `${to} is whitelisted` : `${to} is not whitelisted`,
        };
        results.push(result);
        if (!result.passed) allPassed = false;
      }
    }

    return res.json({
      vaultId,
      amount: parsedAmount,
      to: to ?? null,
      wouldPass: allPassed,
      policiesEvaluated: results.length,
      results,
      storageMode: storageMode(),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Policy evaluation failed', details: msg });
  }
});

// ─── POST /api/policies/:vaultId/circuit-check ───────────────
// Evaluate circuit breaker before a transaction
// Requires body: { amount_usd: number, policy: CircuitBreakerPolicy }

import { evaluateCircuitBreaker, getCircuitState, resetCircuit, CircuitBreakerPolicy } from '../policies/circuit-breaker';

policiesRouter.post('/:vaultId/circuit-check', (req: Request, res: Response) => {
  const { vaultId } = req.params;
  const { amount_usd, policy } = req.body;

  if (amount_usd === undefined || !policy) {
    return res.status(400).json({ error: 'amount_usd and policy are required' });
  }

  const defaultPolicy: CircuitBreakerPolicy = {
    failureThreshold: policy.failureThreshold ?? 3,
    cooldownSeconds: policy.cooldownSeconds ?? 300,
    maxSingleTransactionUsd: policy.maxSingleTransactionUsd ?? 1000,
    maxWindowSpendUsd: policy.maxWindowSpendUsd ?? 5000,
    windowSeconds: policy.windowSeconds ?? 3600,
  };

  const result = evaluateCircuitBreaker(vaultId, parseFloat(amount_usd), defaultPolicy);
  return res.json({ vaultId, amount_usd, ...result });
});

// ─── GET /api/policies/:vaultId/circuit-state ────────────────
policiesRouter.get('/:vaultId/circuit-state', (req: Request, res: Response) => {
  const { vaultId } = req.params;
  const state = getCircuitState(vaultId);
  if (!state) {
    return res.json({ vaultId, state: 'CLOSED', message: 'No circuit state recorded (never triggered)' });
  }
  return res.json(state);
});

// ─── DELETE /api/policies/:vaultId/circuit-reset ─────────────
policiesRouter.delete('/:vaultId/circuit-reset', (req: Request, res: Response) => {
  const { vaultId } = req.params;
  resetCircuit(vaultId);
  return res.json({ vaultId, message: 'Circuit state reset to CLOSED' });
});
