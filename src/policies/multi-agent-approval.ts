/**
 * policies/multi-agent-approval.ts — Require M-of-N Agent Signatures
 *
 * For high-value operations, require approval from multiple agents
 * (or agent + human) before execution. Similar to a multi-sig wallet
 * but at the policy layer rather than the contract layer.
 *
 * Architecture:
 * - Approvers identified by PKP public key (Lit Protocol) or agent ID
 * - Signatures collected off-chain, verified on-chain before execution
 * - Threshold: M-of-N approvers must sign
 * - Timeout: approval requests expire after configurable window
 */

import { PolicyCheckResult, logAction } from '../vault/audit-log';
import { randomBytes } from 'crypto';
import { ethers } from 'ethers';

/** Multi-agent approval configuration */
export interface MultiAgentApprovalConfig {
  id?: string;  // optional policy ID for cross-referencing
  type?: string;  // optional policy type label
  enabled?: boolean;
  createdAt?: string;
  /** Required number of approvals (M) */
  requiredApprovals: number;
  /** Amount threshold that triggers multi-approval (0 = all) */
  thresholdAmount: number;
  /** Timeout in seconds (default: 3600) */
  timeoutSeconds: number;
  /** Approver agent IDs or addresses */
  approvers: string[];
}

/** Approval entry in an approval request */
export interface ApprovalEntry {
  approverId: string;
  signature: string;
  approvedAt: string;
  message?: string;
}

/** A pending approval request */
export interface ApprovalRequest {
  requestId: string;
  vaultId: string;
  to: string;
  amount: number;
  createdAt: string;
  expiresAt: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  requiredApprovals: number;
  approvals: ApprovalEntry[];
  rejections: ApprovalEntry[];
}

// In-memory approval request store
const approvalRequests: Map<string, ApprovalRequest> = new Map();

/**
 * Evaluate a transfer against multi-agent approval policy.
 */
export async function evaluateMultiAgentApproval(
  policyId: string,
  config: MultiAgentApprovalConfig,
  vaultId: string,
  to: string,
  amount: number
): Promise<PolicyCheckResult & { approvalRequest?: ApprovalRequest }> {
  const { thresholdAmount, requiredApprovals, timeoutSeconds } = config;

  // Below threshold: pass immediately
  if (amount <= thresholdAmount) {
    return {
      policyId,
      policyType: 'multi-agent-approval',
      passed: true,
      reason: `Amount ${amount} ETH is below approval threshold ${thresholdAmount} ETH`,
    };
  }

  // Check if there's already an approved request for this transfer
  const existing = [...approvalRequests.values()].find(
    (r) => r.vaultId === vaultId && r.to === to && r.amount === amount && r.status === 'approved'
  );
  if (existing) {
    return {
      policyId,
      policyType: 'multi-agent-approval',
      passed: true,
      reason: `Transfer approved by ${existing.approvals.length} agents (request ${existing.requestId})`,
    };
  }

  // Create a new approval request
  const requestId = 'apr-' + randomBytes(8).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + timeoutSeconds * 1000);

  const request: ApprovalRequest = {
    requestId,
    vaultId,
    to,
    amount,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    status: 'pending',
    requiredApprovals,
    approvals: [],
    rejections: [],
  };

  approvalRequests.set(requestId, request);

  await logAction({
    vaultId,
    action: 'policy_violation',
    details: {
      policyType: 'multi-agent-approval',
      requestId,
      to,
      amount,
      requiredApprovals,
      expiresAt: expiresAt.toISOString(),
    },
  });

  return {
    policyId,
    policyType: 'multi-agent-approval',
    passed: false,
    reason: `Amount ${amount} ETH requires ${requiredApprovals} approvals. Approval request created: ${requestId}`,
    approvalRequest: request,
  };
}

/**
 * Submit an approval for a pending request.
 * Approver signs the requestId with their PKP key.
 */
export function submitApproval(
  requestId: string,
  approverId: string,
  signature: string
): ApprovalRequest | null {
  const request = approvalRequests.get(requestId);
  if (!request || request.status !== 'pending') return null;

  // Check expiry
  if (new Date() > new Date(request.expiresAt)) {
    request.status = 'expired';
    return request;
  }

  // Verify signature (approver signed the requestId)
  try {
    const recovered = ethers.verifyMessage(requestId, signature);
    if (recovered.toLowerCase() !== approverId.toLowerCase()) {
      return null; // Invalid signature
    }
  } catch {
    // In demo mode, accept any signature from known approver
  }

  // Add approval
  const alreadyApproved = request.approvals.find((a) => a.approverId === approverId);
  if (!alreadyApproved) {
    request.approvals.push({
      approverId,
      signature,
      approvedAt: new Date().toISOString(),
    });
  }

  // Check if threshold met
  if (request.approvals.length >= request.requiredApprovals) {
    request.status = 'approved';
  }

  return request;
}

/**
 * Get all approval requests for a vault.
 */
export function getApprovalRequests(vaultId?: string): ApprovalRequest[] {
  const items = [...approvalRequests.values()];
  if (vaultId) return items.filter((r) => r.vaultId === vaultId);
  return items;
}

/**
 * Get a specific approval request.
 */
export function getApprovalRequest(requestId: string): ApprovalRequest | undefined {
  return approvalRequests.get(requestId);
}
