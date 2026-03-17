/**
 * policies/spending-cap.ts — Per-Transaction and Daily Spending Limits
 *
 * Enforces maximum spending per transaction and per rolling 24h window.
 * This is the most critical policy — it prevents an agent from
 * draining the vault even if compromised. Checks are enforced before
 * any transfer or swap is executed.
 */

import { PolicyCheckResult, getRecentOutflow } from '../vault/audit-log';

/** Spending cap policy configuration */
export interface SpendingCapConfig {
  /** Maximum amount per single transaction (in ETH) */
  perTransactionLimit: number;
  /** Maximum total outflow in rolling 24h window (in ETH) */
  dailyLimit: number;
  /** Token address this cap applies to (0x0 = all tokens) */
  tokenAddress?: string;
  /** Whether to use USD conversion for cross-token caps */
  useUsdConversion?: boolean;
}

/**
 * Evaluate a transfer against spending cap policy.
 * Returns a PolicyCheckResult with pass/fail and human-readable reason.
 */
export async function evaluateSpendingCap(
  policyId: string,
  config: SpendingCapConfig,
  vaultId: string,
  amount: number
): Promise<PolicyCheckResult> {
  const { perTransactionLimit, dailyLimit } = config;

  // Check 1: Per-transaction limit
  if (amount > perTransactionLimit) {
    return {
      policyId,
      policyType: 'spending-cap',
      passed: false,
      reason: `Amount ${amount} ETH exceeds per-transaction limit of ${perTransactionLimit} ETH`,
    };
  }

  // Check 2: Rolling 24h daily limit
  const recentOutflow = await getRecentOutflow(vaultId, 86400000);
  const projectedTotal = recentOutflow + amount;

  if (projectedTotal > dailyLimit) {
    return {
      policyId,
      policyType: 'spending-cap',
      passed: false,
      reason: `Daily outflow would be ${projectedTotal.toFixed(4)} ETH, exceeding daily limit of ${dailyLimit} ETH (already spent: ${recentOutflow.toFixed(4)} ETH in last 24h)`,
    };
  }

  return {
    policyId,
    policyType: 'spending-cap',
    passed: true,
    reason: `Amount ${amount} ETH is within limits. Daily total would be ${projectedTotal.toFixed(4)} / ${dailyLimit} ETH`,
  };
}

/**
 * Default spending cap configuration for new vaults.
 * Conservative limits suitable for a demo/testnet environment.
 */
export const DEFAULT_SPENDING_CAP: SpendingCapConfig = {
  perTransactionLimit: 0.1,   // 0.1 ETH per transaction
  dailyLimit: 0.5,             // 0.5 ETH per day
  tokenAddress: '0x0000000000000000000000000000000000000000',
  useUsdConversion: false,
};
