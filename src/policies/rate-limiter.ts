/**
 * policies/rate-limiter.ts — Max N Transactions Per Time Window
 *
 * Prevents rapid-fire transactions that could indicate a compromised
 * agent or a bug in the automation logic.
 *
 * Features:
 * - Sliding time window (count tx in last N seconds)
 * - Configurable max transactions per window
 * - Optional filter by action types (transfers vs swaps)
 * - Cooldown period after hitting the limit
 */

import { PolicyCheckResult, getAuditTrail } from '../vault/audit-log';

/** Rate limiter policy configuration */
export interface RateLimiterPolicy {
  id: string;
  type: 'rate-limiter';
  /** Maximum transactions allowed in the window */
  maxTransactions: number;
  /** Time window in seconds */
  windowSeconds: number;
  /** Optional: only count specific action types */
  actionTypes?: ('transfer' | 'swap')[];
  /** Cooldown in seconds after limit is hit */
  cooldownSeconds: number;
  enabled: boolean;
  createdAt: Date | string;
}

/**
 * Evaluate a transaction against rate limiter policy.
 * Uses sliding window over the audit log.
 */
export async function evaluateRateLimit(
  policy: RateLimiterPolicy,
  vaultId: string
): Promise<PolicyCheckResult> {
  const now = Date.now();
  const windowMs = policy.windowSeconds * 1000;
  const windowStart = new Date(now - windowMs);
  const cooldownMs = policy.cooldownSeconds * 1000;

  // Pull recent audit entries (generous limit to cover the window)
  const entries = await getAuditTrail(vaultId, 500);

  // Filter to the sliding window
  const relevantActions = policy.actionTypes ?? ['transfer', 'swap'];
  const windowEntries = entries.filter((e) => {
    const ts = e.timestamp instanceof Date ? e.timestamp : new Date(e.timestamp);
    if (ts < windowStart) return false;
    return relevantActions.includes(e.action as 'transfer' | 'swap');
  });

  const txCount = windowEntries.length;

  // Check cooldown: was the limit already hit recently?
  if (txCount >= policy.maxTransactions) {
    // Find the most recent entry that pushed us over (or kept us over)
    const mostRecent = windowEntries[0]; // already sorted desc by getAuditTrail
    if (mostRecent) {
      const mostRecentTs = mostRecent.timestamp instanceof Date
        ? mostRecent.timestamp
        : new Date(mostRecent.timestamp);
      const timeSinceLast = now - mostRecentTs.getTime();
      if (timeSinceLast < cooldownMs) {
        const secondsLeft = Math.ceil((cooldownMs - timeSinceLast) / 1000);
        return {
          policyId: policy.id,
          policyType: 'rate-limiter',
          passed: false,
          reason: `Rate limit exceeded (${txCount}/${policy.maxTransactions} tx in ${policy.windowSeconds}s window). Cooldown: ${secondsLeft}s remaining.`,
        };
      }
    }

    // Cooldown expired but still in window — still blocked until window clears
    const oldestInWindow = windowEntries[windowEntries.length - 1];
    if (oldestInWindow) {
      const oldestTs = oldestInWindow.timestamp instanceof Date
        ? oldestInWindow.timestamp
        : new Date(oldestInWindow.timestamp);
      const windowClearsIn = Math.ceil(
        (oldestTs.getTime() + windowMs - now) / 1000
      );
      return {
        policyId: policy.id,
        policyType: 'rate-limiter',
        passed: false,
        reason: `Rate limit exceeded (${txCount}/${policy.maxTransactions} tx in ${policy.windowSeconds}s window). Window clears in ${windowClearsIn}s.`,
      };
    }
  }

  return {
    policyId: policy.id,
    policyType: 'rate-limiter',
    passed: true,
    reason: `${txCount}/${policy.maxTransactions} transactions used in current ${policy.windowSeconds}s window.`,
  };
}
