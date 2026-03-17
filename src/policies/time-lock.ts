/**
 * policies/time-lock.ts — Delay Large Transfers for Review Period
 *
 * Transactions above a threshold are queued for a mandatory delay
 * period before execution, giving the vault owner time to cancel
 * if the transaction looks suspicious.
 *
 * Architecture:
 * - Small transfers (below threshold): immediate
 * - Large transfers (above threshold): queued, released after delaySeconds
 * - Cancellation window: any time before executeAfter
 * - Auto-release: GET /api/vault/:vaultId/queue processes due items
 */

import { PolicyCheckResult, logAction } from '../vault/audit-log';
import { randomBytes } from 'crypto';

/** Time-lock policy configuration */
export interface TimeLockConfig {
  id?: string;
  type?: string;
  enabled?: boolean;
  createdAt?: string;
  /** Amount threshold that triggers the lock (in ETH) */
  thresholdAmount: number;
  /** Delay period in seconds (default: 3600 = 1h) */
  delaySeconds: number;
}

/** A queued (time-locked) transaction */
export interface QueuedTransaction {
  queueId: string;
  vaultId: string;
  to: string;
  amount: number;
  memo?: string;
  queuedAt: string;
  executeAfter: string;
  status: 'pending' | 'executed' | 'cancelled';
  cancelledAt?: string;
  cancelledBy?: string;
  executedAt?: string;
}

// In-memory queue (MongoDB-backed in production)
const queue: Map<string, QueuedTransaction> = new Map();

/**
 * Evaluate a transfer against time-lock policy.
 * Returns PolicyCheckResult with optional queue info.
 */
export async function evaluateTimeLock(
  policyId: string,
  config: TimeLockConfig,
  vaultId: string,
  to: string,
  amount: number,
  memo?: string
): Promise<PolicyCheckResult & { requiresDelay?: boolean; queuedTransaction?: QueuedTransaction }> {
  const { thresholdAmount, delaySeconds } = config;

  // Below threshold: pass immediately
  if (amount <= thresholdAmount) {
    return {
      policyId,
      policyType: 'time-lock',
      passed: true,
      reason: `Amount ${amount} ETH is below threshold ${thresholdAmount} ETH — immediate execution`,
    };
  }

  // Above threshold: queue the transaction
  const queueId = 'tl-' + randomBytes(8).toString('hex');
  const now = new Date();
  const executeAfter = new Date(now.getTime() + delaySeconds * 1000);

  const queued: QueuedTransaction = {
    queueId,
    vaultId,
    to,
    amount,
    memo,
    queuedAt: now.toISOString(),
    executeAfter: executeAfter.toISOString(),
    status: 'pending',
  };

  queue.set(queueId, queued);

  // Log the time-lock event
  await logAction({
    vaultId,
    action: 'policy_violation',
    details: {
      policyType: 'time-lock',
      queueId,
      to,
      amount,
      executeAfter: executeAfter.toISOString(),
      delaySeconds,
      reason: 'Transfer queued for time-lock review',
    },
  });

  return {
    policyId,
    policyType: 'time-lock',
    passed: false,
    reason: `Amount ${amount} ETH exceeds threshold ${thresholdAmount} ETH — queued for ${delaySeconds}s delay (execute after ${executeAfter.toISOString()})`,
    requiresDelay: true,
    queuedTransaction: queued,
  };
}

/**
 * Get all queued transactions for a vault.
 */
export function getQueue(vaultId?: string): QueuedTransaction[] {
  const items = [...queue.values()];
  if (vaultId) return items.filter((t) => t.vaultId === vaultId);
  return items;
}

/**
 * Cancel a queued transaction.
 */
export function cancelQueuedTransaction(queueId: string, cancelledBy?: string): QueuedTransaction | null {
  const item = queue.get(queueId);
  if (!item || item.status !== 'pending') return null;
  item.status = 'cancelled';
  item.cancelledAt = new Date().toISOString();
  item.cancelledBy = cancelledBy;
  return item;
}

/**
 * Check if a queued transaction is ready for execution (delay period passed).
 */
export function isReadyForExecution(queueId: string): boolean {
  const item = queue.get(queueId);
  if (!item || item.status !== 'pending') return false;
  return new Date() >= new Date(item.executeAfter);
}

/**
 * Mark a transaction as executed.
 */
export function markExecuted(queueId: string): QueuedTransaction | null {
  const item = queue.get(queueId);
  if (!item || item.status !== 'pending') return null;
  item.status = 'executed';
  item.executedAt = new Date().toISOString();
  return item;
}
