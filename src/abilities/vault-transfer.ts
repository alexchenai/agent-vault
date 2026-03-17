/**
 * abilities/vault-transfer.ts — Send Funds with Policy Enforcement
 *
 * This ability handles outgoing transfers from the vault.
 * Every transfer MUST pass all active policies before the
 * Lit Action signs the transaction.
 *
 * Flow:
 * 1. Load active policies for the vault
 * 2. Evaluate ALL policies against the transfer request
 * 3. If ANY policy fails → reject, log violation
 * 4. If ALL pass → sign via PKP, log success
 * 5. Return full audit record with policy results
 */

import { evaluateSpendingCap } from '../policies/spending-cap';
import { evaluateWhitelist } from '../policies/whitelist-only';
import { evaluateRateLimit, RateLimiterPolicy } from '../policies/rate-limiter';
import { evaluateTimeLock, TimeLockConfig as TimeLockPolicy } from '../policies/time-lock';
import { evaluateMultiAgentApproval, MultiAgentApprovalConfig as MultiAgentPolicy } from '../policies/multi-agent-approval';
import {
  PolicyCheckResult,
  PolicyDoc,
  getPolicies,
  logAction,
  getVaultBalance,
  updateVaultBalance,
  getRecentOutflow,
} from '../vault/audit-log';
import { getOrCreatePKP, signTransaction } from '../vault/wallet';

/** Transfer request parameters */
export interface TransferRequest {
  /** Vault ID to send from */
  vaultId: string;
  /** Recipient address */
  to: string;
  /** Amount in ETH (decimal string, e.g. "0.1") */
  amount: string;
  /** Token address (0x0 for native ETH) */
  tokenAddress?: string;
  /** Optional memo for audit trail */
  memo?: string;
  /** Requesting agent ID (for multi-agent approval) */
  requestedBy?: string;
}

/** Transfer result */
export interface TransferResult {
  /** Transaction hash (or pending ID if not broadcast) */
  txHash: string;
  /** From address (vault's PKP address) */
  from: string;
  /** Recipient */
  to: string;
  /** Amount transferred */
  amount: string;
  /** Gas used estimate */
  gasUsed: string;
  /** Policy check results */
  policyResults: PolicyCheckResult[];
  /** Status */
  status: 'completed' | 'rejected' | 'pending_approval';
  /** If rejected, the reason */
  rejectionReason?: string;
  /** Queue ID if time-lock created a deferred transaction */
  queueId?: string;
}

/**
 * Execute a transfer with full policy enforcement.
 *
 * All active policies must pass. If any policy fails, the transfer
 * is rejected and a policy_violation event is logged. If all pass,
 * the PKP signs the transaction and the transfer is executed.
 */
export async function executeTransfer(request: TransferRequest): Promise<TransferResult> {
  const { vaultId, to, amount, requestedBy = 'unknown' } = request;
  const amountFloat = parseFloat(amount);

  if (isNaN(amountFloat) || amountFloat <= 0) {
    throw new Error(`Invalid transfer amount: ${amount}`);
  }

  // 1. Check vault balance
  const balance = await getVaultBalance(vaultId);
  if (balance < amountFloat) {
    await logAction({
      vaultId,
      action: 'policy_violation',
      details: {
        reason: 'Insufficient balance',
        requested: amountFloat,
        available: balance,
        to,
      },
    });
    return {
      txHash: '',
      from: '',
      to,
      amount,
      gasUsed: '0',
      policyResults: [],
      status: 'rejected',
      rejectionReason: `Insufficient balance: vault has ${balance} ETH, requested ${amountFloat} ETH`,
    };
  }

  // 2. Load all active policies for this vault
  const activePolicies: PolicyDoc[] = await getPolicies(vaultId);
  const policyResults: PolicyCheckResult[] = [];
  let rejected = false;
  let rejectionReason = '';
  let queueId: string | undefined;
  let pendingApproval = false;

  // 3. Evaluate each policy
  for (const policyDoc of activePolicies) {
    if (!policyDoc.enabled) continue;

    const config = policyDoc.config;
    let result: PolicyCheckResult;

    switch (policyDoc.type) {
      case 'spending-cap': {
        const dailyOutflow = await getRecentOutflow(vaultId, 86400000);
        result = await evaluateSpendingCap(
          String(policyDoc._id ?? policyDoc.type),
          {
            perTransactionLimit: (config.perTransactionLimit as number) ?? 1.0,
            dailyLimit: (config.dailyLimit as number) ?? 10.0,
          },
          vaultId,
          amountFloat,
        );
        break;
      }

      case 'whitelist-only': {
        result = await evaluateWhitelist(
          String(policyDoc._id ?? policyDoc.type),
          {
            addresses: (config.addresses as string[]) ?? [],
            strictMode: config.strictMode as boolean | undefined,
          },
          to
        );
        break;
      }

      case 'rate-limiter': {
        const rlPolicy: RateLimiterPolicy = {
          id: String(policyDoc._id ?? policyDoc.type),
          type: 'rate-limiter',
          maxTransactions: (config.maxTransactions as number) ?? 10,
          windowSeconds: (config.windowSeconds as number) ?? 3600,
          cooldownSeconds: (config.cooldownSeconds as number) ?? 60,
          actionTypes: config.actionTypes as ('transfer' | 'swap')[] | undefined,
          enabled: true,
          createdAt: String(policyDoc.createdAt ?? ""),
        };
        result = await evaluateRateLimit(rlPolicy, vaultId);
        break;
      }

      case 'time-lock': {
        const tlPolicy: TimeLockPolicy = {
          id: String(policyDoc._id ?? policyDoc.type),
          type: 'time-lock',
          thresholdAmount: (config.thresholdAmount as number) ?? 1.0,
          delaySeconds: (config.delaySeconds as number) ?? 3600,
          enabled: true,
          createdAt: String(policyDoc.createdAt ?? ""),
        };
        const tlResult = await evaluateTimeLock(
          tlPolicy.id ?? "tl-policy",
          { thresholdAmount: tlPolicy.thresholdAmount, delaySeconds: tlPolicy.delaySeconds },
          vaultId,
          to,
          amountFloat
        );
        result = {
          policyId: tlPolicy.id ?? "tl-policy",
          policyType: 'time-lock',
          passed: tlResult.passed,
          reason: tlResult.reason,
        };
        if (!tlResult.passed && tlResult.requiresDelay && tlResult.queuedTransaction) {
          queueId = tlResult.queuedTransaction.queueId;
          pendingApproval = true;
        }
        break;
      }

      case 'multi-agent-approval': {
        const maPolicy: MultiAgentPolicy = {
          id: String(policyDoc._id ?? policyDoc.type),
          type: 'multi-agent-approval',
          thresholdAmount: (config.thresholdAmount as number) ?? 0.5,
          requiredApprovals: (config.requiredApprovals as number) ?? 2,
          timeoutSeconds: (config.timeoutSeconds as number) ?? 3600,
          approvers: (config.approvers as string[]) ?? [],
          enabled: true,
          createdAt: String(policyDoc.createdAt ?? ""),
        };
        const maResult = await evaluateMultiAgentApproval(
          maPolicy.id ?? "ma-policy",
          {
            thresholdAmount: maPolicy.thresholdAmount,
            requiredApprovals: maPolicy.requiredApprovals,
            timeoutSeconds: maPolicy.timeoutSeconds,
            approvers: maPolicy.approvers,
          },
          vaultId,
          to,
          amountFloat
        );
        result = {
          policyId: maPolicy.id ?? "ma-policy",
          policyType: 'multi-agent-approval',
          passed: maResult.passed,
          reason: maResult.reason,
        };
        if (!maResult.passed && maResult.approvalRequest) {
          pendingApproval = true;
        }
        break;
      }

      default:
        // Unknown policy type: allow (fail-open for forward compatibility)
        result = {
          policyId: String(policyDoc._id ?? policyDoc.type),
          policyType: policyDoc.type,
          passed: true,
          reason: 'Unknown policy type (fail-open)',
        };
    }

    policyResults.push(result);

    if (!result.passed && !pendingApproval) {
      rejected = true;
      rejectionReason = result.reason ?? `Policy ${policyDoc.type} rejected the transfer`;
      break; // Stop at first hard rejection
    }
  }

  // 4. If pending approval (time-lock or multi-agent), return pending status
  if (pendingApproval) {
    await logAction({
      vaultId,
      action: 'policy_violation',
      details: {
        reason: 'Pending approval',
        to,
        amount: amountFloat,
        requestedBy,
        queueId,
      },
      policyResults,
    });
    return {
      txHash: '',
      from: '',
      to,
      amount,
      gasUsed: '0',
      policyResults,
      status: 'pending_approval',
      rejectionReason: 'Transfer queued for approval (time-lock or multi-agent requirement)',
      queueId,
    };
  }

  // 5. If hard rejected by policy
  if (rejected) {
    await logAction({
      vaultId,
      action: 'policy_violation',
      details: {
        reason: rejectionReason,
        to,
        amount: amountFloat,
        requestedBy,
      },
      policyResults,
    });
    return {
      txHash: '',
      from: '',
      to,
      amount,
      gasUsed: '0',
      policyResults,
      status: 'rejected',
      rejectionReason,
    };
  }

  // 6. All policies passed — sign and execute via PKP
  const pkp = await getOrCreatePKP(vaultId);
  const signed = await signTransaction(pkp, {
    to,
    value: amount,
    chainId: 8453, // Base L2
  });

  // 7. Update vault balance
  await updateVaultBalance(vaultId, -amountFloat);

  // 8. Log successful transfer
  await logAction({
    vaultId,
    action: 'transfer',
    details: {
      to,
      amount: amountFloat,
      requestedBy,
      memo: request.memo,
      litActionCid: signed.litActionCid,
    },
    txHash: signed.txHash,
    policyResults,
  });

  return {
    txHash: signed.txHash,
    from: pkp.ethAddress,
    to,
    amount,
    gasUsed: '21000', // Standard ETH transfer gas
    policyResults,
    status: 'completed',
  };
}
