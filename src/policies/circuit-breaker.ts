/**
 * Circuit Breaker Policy — Agent Vault v0.5.0
 * Automatically halts agent spending when anomaly thresholds are exceeded.
 * States: CLOSED (normal), OPEN (halted), HALF_OPEN (testing recovery).
 */

import * as crypto from 'crypto';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerPolicy {
  failureThreshold: number;
  cooldownSeconds: number;
  maxSingleTransactionUsd: number;
  maxWindowSpendUsd: number;
  windowSeconds: number;
}

export interface CircuitRecord {
  vaultId: string;
  state: CircuitState;
  consecutiveFailures: number;
  lastFailureAt: number | null;
  openedAt: number | null;
  lastTestedAt: number | null;
  windowSpendUsd: number;
  windowStartAt: number;
  stateHash: string;
}

const circuitStore = new Map<string, CircuitRecord>();

function computeStateHash(r: Omit<CircuitRecord, 'stateHash'>): string {
  const payload = `${r.vaultId}:${r.state}:${r.consecutiveFailures}:${r.lastFailureAt}:${r.openedAt}:${r.windowSpendUsd}`;
  return crypto.createHmac('sha256', process.env.HMAC_SECRET || 'agent-vault-circuit-key')
    .update(payload).digest('hex').slice(0, 16);
}

function getOrCreate(vaultId: string): CircuitRecord {
  if (!circuitStore.has(vaultId)) {
    const base = {
      vaultId,
      state: 'CLOSED' as CircuitState,
      consecutiveFailures: 0,
      lastFailureAt: null,
      openedAt: null,
      lastTestedAt: null,
      windowSpendUsd: 0,
      windowStartAt: Date.now(),
    };
    circuitStore.set(vaultId, { ...base, stateHash: computeStateHash(base) });
  }
  return circuitStore.get(vaultId)!;
}

export function evaluateCircuitBreaker(
  vaultId: string,
  transactionAmountUsd: number,
  policy: CircuitBreakerPolicy
): { allowed: boolean; state: CircuitState; reason: string; stateHash: string } {
  const record = getOrCreate(vaultId);
  const now = Date.now();

  if (now - record.windowStartAt > policy.windowSeconds * 1000) {
    record.windowSpendUsd = 0;
    record.windowStartAt = now;
  }

  if (record.state === 'OPEN') {
    const cooldownMs = policy.cooldownSeconds * 1000;
    if (record.openedAt && (now - record.openedAt) > cooldownMs) {
      record.state = 'HALF_OPEN';
      record.lastTestedAt = now;
    } else {
      const remainingSec = Math.ceil(((record.openedAt || now) + cooldownMs - now) / 1000);
      record.stateHash = computeStateHash(record);
      return {
        allowed: false, state: 'OPEN',
        reason: `Circuit OPEN: ${remainingSec}s cooldown remaining`,
        stateHash: record.stateHash,
      };
    }
  }

  const exceedsSingle = transactionAmountUsd > policy.maxSingleTransactionUsd;
  const exceedsWindow = (record.windowSpendUsd + transactionAmountUsd) > policy.maxWindowSpendUsd;

  if (exceedsSingle || exceedsWindow) {
    record.consecutiveFailures += 1;
    record.lastFailureAt = now;
    if (record.consecutiveFailures >= policy.failureThreshold) {
      record.state = 'OPEN';
      record.openedAt = now;
      record.stateHash = computeStateHash(record);
      return {
        allowed: false, state: 'OPEN',
        reason: `Circuit tripped after ${record.consecutiveFailures} violations`,
        stateHash: record.stateHash,
      };
    }
    const reason = exceedsSingle
      ? `Tx $${transactionAmountUsd} > single limit $${policy.maxSingleTransactionUsd}`
      : `Window $${(record.windowSpendUsd + transactionAmountUsd).toFixed(2)} > limit $${policy.maxWindowSpendUsd}`;
    record.stateHash = computeStateHash(record);
    return { allowed: false, state: record.state, reason, stateHash: record.stateHash };
  }

  if (record.state === 'HALF_OPEN') {
    record.state = 'CLOSED';
    record.consecutiveFailures = 0;
  }

  record.windowSpendUsd += transactionAmountUsd;
  record.stateHash = computeStateHash(record);
  circuitStore.set(vaultId, record);

  return {
    allowed: true, state: record.state,
    reason: 'Circuit CLOSED: within policy limits',
    stateHash: record.stateHash,
  };
}

export function getCircuitState(vaultId: string): CircuitRecord | null {
  return circuitStore.get(vaultId) || null;
}

export function resetCircuit(vaultId: string): void {
  circuitStore.delete(vaultId);
}
