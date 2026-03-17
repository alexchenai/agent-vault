/**
 * policies/whitelist-only.ts — Restrict Destinations to Approved Addresses
 *
 * Only allows transfers to pre-approved addresses. Prevents the agent
 * from sending funds to unknown or malicious addresses.
 */

import { PolicyCheckResult } from '../vault/audit-log';

/** Whitelist policy configuration */
export interface WhitelistConfig {
  /** List of approved destination addresses (lowercase) */
  addresses: string[];
  /** Whether strict mode is enabled (deny all non-whitelisted) */
  strictMode?: boolean;
}

/**
 * Evaluate a transfer against whitelist policy.
 */
export async function evaluateWhitelist(
  policyId: string,
  config: WhitelistConfig,
  destinationAddress: string
): Promise<PolicyCheckResult> {
  const normalized = destinationAddress.toLowerCase();
  const whitelist = config.addresses.map((a) => a.toLowerCase());
  const isAllowed = whitelist.includes(normalized);

  if (!isAllowed) {
    return {
      policyId,
      policyType: 'whitelist-only',
      passed: false,
      reason: `Destination ${destinationAddress} is not in the approved whitelist (${whitelist.length} addresses approved)`,
    };
  }

  return {
    policyId,
    policyType: 'whitelist-only',
    passed: true,
    reason: `Destination ${destinationAddress} is whitelisted`,
  };
}
