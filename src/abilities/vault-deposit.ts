/**
 * abilities/vault-deposit.ts — Receive Funds into MPC-Managed Vault
 *
 * Handles deposits into the agent's vault. In production this would use
 * Lit Protocol PKPs as the deposit address. For the hackathon demo, we
 * use a deterministic address derived from the vaultId and record deposits
 * in MongoDB with a full audit trail.
 */

import { logAction, updateVaultBalance, getVaultBalance } from '../vault/audit-log';

/** Deposit request parameters */
export interface DepositRequest {
  /** Vault ID to deposit into */
  vaultId: string;
  /** Amount to deposit (in ETH) */
  amount: number;
  /** Token address (0x0 for native ETH, or ERC-20 address) */
  tokenAddress?: string;
  /** Optional transaction hash from on-chain deposit */
  txHash?: string;
  /** Optional note or memo */
  memo?: string;
}

/** Deposit result */
export interface DepositResult {
  success: boolean;
  vaultId: string;
  depositAddress: string;
  amountDeposited: number;
  newBalance: number;
  token: string;
  txHash?: string;
  auditLogId: string | null;
  timestamp: string;
  message: string;
}

/**
 * Derive a deterministic deposit address for a vault.
 * In production: returns the PKP-derived Ethereum address from Lit Protocol.
 * For demo: returns a deterministic pseudo-address based on vaultId hash.
 */
export function getDepositAddress(vaultId: string): string {
  // Deterministic address derivation for demo purposes
  // In production: query the PKP NFT from Lit Chronicle chain
  let hash = 0;
  for (let i = 0; i < vaultId.length; i++) {
    const char = vaultId.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `0x${hex}${'0'.repeat(32)}`.slice(0, 42);
}

/**
 * Process a deposit into the vault.
 * Records the deposit in the audit trail and updates the balance.
 */
export async function processDeposit(request: DepositRequest): Promise<DepositResult> {
  const { vaultId, amount, tokenAddress = '0x0000000000000000000000000000000000000000', txHash, memo } = request;

  if (!vaultId || typeof vaultId !== 'string' || vaultId.trim() === '') {
    throw new Error('vaultId is required');
  }
  if (typeof amount !== 'number' || amount <= 0) {
    throw new Error('amount must be a positive number');
  }

  const depositAddress = getDepositAddress(vaultId);
  const token = tokenAddress === '0x0000000000000000000000000000000000000000' ? 'ETH' : tokenAddress.slice(0, 8) + '...';

  // Update balance in DB / memory
  const newBalance = await updateVaultBalance(vaultId, amount);

  // Log to audit trail
  const auditLogId = await logAction({
    vaultId,
    action: 'deposit',
    details: {
      amount,
      tokenAddress,
      depositAddress,
      token,
      memo: memo ?? null,
    },
    txHash,
  });

  return {
    success: true,
    vaultId,
    depositAddress,
    amountDeposited: amount,
    newBalance,
    token,
    txHash,
    auditLogId,
    timestamp: new Date().toISOString(),
    message: `Deposit of ${amount} ${token} recorded. Vault balance is now ${newBalance} ${token}.`,
  };
}

/**
 * Get the current balance of a vault.
 */
export async function getBalance(vaultId: string): Promise<{ vaultId: string; balance: number; depositAddress: string }> {
  const balance = await getVaultBalance(vaultId);
  const depositAddress = getDepositAddress(vaultId);
  return { vaultId, balance, depositAddress };
}
