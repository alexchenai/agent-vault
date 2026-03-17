/**
 * routes/vault.ts — Deposit, Transfer, Swap, Balance, and Audit Log Routes
 */

import { Router, Request, Response } from 'express';
import { processDeposit, getBalance, getDepositAddress } from '../abilities/vault-deposit';
import { getAuditTrail, logAction, isConnected, getPolicies, updateVaultBalance } from '../vault/audit-log';
import { evaluateSpendingCap } from '../policies/spending-cap';
import { getOrCreatePKP, signTransaction, signMessage, getSessionSigs } from '../vault/wallet';
import { evaluateTimeLock, getQueue, cancelQueuedTransaction, isReadyForExecution, markExecuted } from '../policies/time-lock';
import { evaluateMultiAgentApproval, submitApproval, getApprovalRequests, getApprovalRequest } from '../policies/multi-agent-approval';
import { storeSecret, retrieveSecret, listSecrets, deleteSecret } from '../abilities/vault-secrets';

export const vaultRouter = Router();

// ─── Storage mode info ───────────────────────────────────────

function storageMode(): string {
  return isConnected() ? 'mongodb' : 'in-memory';
}

// ─── POST /api/vault/deposit ─────────────────────────────────

vaultRouter.post('/deposit', async (req: Request, res: Response) => {
  try {
    const { vaultId, amount, tokenAddress, txHash, memo } = req.body;

    if (!vaultId) {
      return res.status(400).json({ error: 'vaultId is required' });
    }
    if (amount === undefined || amount === null) {
      return res.status(400).json({ error: 'amount is required (number, in ETH)' });
    }
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }

    const result = await processDeposit({
      vaultId,
      amount: parsedAmount,
      tokenAddress,
      txHash,
      memo,
    });

    return res.status(201).json({
      ...result,
      storageMode: storageMode(),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Deposit failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/balance ─────────────────────────

vaultRouter.get('/:vaultId/balance', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const result = await getBalance(vaultId);
    return res.json({
      ...result,
      storageMode: storageMode(),
      currency: 'ETH',
      note: 'Deposit address is the PKP-derived Ethereum address managed by Lit Protocol (stub in demo)',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Balance check failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/audit-log ───────────────────────

vaultRouter.get('/:vaultId/audit-log', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const limit = Math.min(parseInt(req.query.limit as string || '50', 10), 200);
    const entries = await getAuditTrail(vaultId, limit);
    return res.json({
      vaultId,
      count: entries.length,
      entries,
      storageMode: storageMode(),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Audit log query failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/audit (alias) ───────────────────

vaultRouter.get('/:vaultId/audit', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const limit = Math.min(parseInt(req.query.limit as string || '50', 10), 200);
    const entries = await getAuditTrail(vaultId, limit);
    return res.json({
      vaultId,
      count: entries.length,
      entries,
      storageMode: storageMode(),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Audit log query failed', details: msg });
  }
});

// ─── POST /api/vault/transfer ─────────────────────────────────

vaultRouter.post('/transfer', async (req: Request, res: Response) => {
  try {
    const { vaultId, to, amount, tokenAddress, memo } = req.body;

    if (!vaultId || !to || amount === undefined) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: { vaultId: 'string', to: 'string (address)', amount: 'number (ETH)' },
      });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }

    // Evaluate all active policies for this vault
    const policies = await getPolicies(vaultId);
    const policyResults = [];
    let blocked = false;
    let blockReason = '';

    for (const policy of policies) {
      if (policy.type === 'spending-cap') {
        const cfg = policy.config as { perTransactionLimit: number; dailyLimit: number };
        const result = await evaluateSpendingCap(String(policy._id), cfg, vaultId, parsedAmount);
        policyResults.push(result);
        if (!result.passed) {
          blocked = true;
          blockReason = result.reason ?? 'Spending cap exceeded';
        }
      }
      if (policy.type === 'whitelist-only') {
        const cfg = policy.config as { addresses: string[] };
        const normalized = to.toLowerCase();
        const isAllowed = cfg.addresses.map((a: string) => a.toLowerCase()).includes(normalized);
        const result = {
          policyId: String(policy._id),
          policyType: 'whitelist-only',
          passed: isAllowed,
          reason: isAllowed
            ? `Destination ${to} is whitelisted`
            : `Destination ${to} is not in the approved whitelist`,
        };
        policyResults.push(result);
        if (!result.passed) {
          blocked = true;
          blockReason = result.reason;
        }
      }
      if (policy.type === 'time-lock') {
        const cfg = policy.config as { thresholdAmount: number; delaySeconds: number };
        const result = await evaluateTimeLock(
          String(policy._id), cfg, vaultId, to, parsedAmount, memo
        );
        policyResults.push({ policyId: result.policyId, policyType: result.policyType, passed: result.passed, reason: result.reason });
        if (!result.passed) {
          blocked = true;
          blockReason = result.reason ?? 'Transfer queued for time-lock';
          if (result.queuedTransaction) {
            return res.status(202).json({
              success: false,
              queued: true,
              queuedTransaction: result.queuedTransaction,
              policyResults,
              message: 'Transfer queued for time-lock review period',
            });
          }
        }
      }
      if (policy.type === 'multi-agent-approval') {
        const cfg = policy.config as { thresholdAmount: number; requiredApprovals: number; timeoutSeconds: number; approvers: string[] };
        const result = await evaluateMultiAgentApproval(
          String(policy._id), cfg, vaultId, to, parsedAmount
        );
        policyResults.push({ policyId: result.policyId, policyType: result.policyType, passed: result.passed, reason: result.reason });
        if (!result.passed) {
          blocked = true;
          blockReason = result.reason ?? 'Multi-agent approval required';
          if (result.approvalRequest) {
            return res.status(202).json({
              success: false,
              awaitingApproval: true,
              approvalRequest: result.approvalRequest,
              policyResults,
              message: 'Transfer requires multi-agent approval',
            });
          }
        }
      }
    }

    if (blocked) {
      // Log the policy violation
      await logAction({
        vaultId,
        action: 'policy_violation',
        details: { to, amount: parsedAmount, tokenAddress, blockReason, memo },
        policyResults,
      });

      return res.status(403).json({
        success: false,
        blocked: true,
        blockReason,
        policyResults,
        message: 'Transfer blocked by policy',
      });
    }

    // Deduct from balance
    const newBalance = await updateVaultBalance(vaultId, -parsedAmount);

    // Sign via Lit Protocol PKP
    const pkp = await getOrCreatePKP(vaultId);
    const signed = await signTransaction(pkp, {
      to,
      value: parsedAmount.toFixed(6),
      chainId: 8453,
    });

    // Log the transfer
    const auditLogId = await logAction({
      vaultId,
      action: 'transfer',
      details: {
        to,
        amount: parsedAmount,
        tokenAddress: tokenAddress ?? '0x0000000000000000000000000000000000000000',
        memo: memo ?? null,
        newBalance,
        signedViaPKP: true,
        pkpAddress: pkp.ethAddress,
        litNetwork: pkp.litNetwork,
      },
      txHash: signed.txHash,
      policyResults,
    });

    return res.json({
      success: true,
      vaultId,
      to,
      amountTransferred: parsedAmount,
      newBalance,
      txHash: signed.txHash,
      signedTx: signed.signedTx.slice(0, 40) + '...',
      pkpAddress: pkp.ethAddress,
      litNetwork: pkp.litNetwork,
      litActionCid: signed.litActionCid,
      auditLogId,
      policyResults,
      storageMode: storageMode(),
      timestamp: new Date().toISOString(),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Transfer failed', details: msg });
  }
});

// ─── POST /api/vault/swap ─────────────────────────────────────

vaultRouter.post('/swap', async (req: Request, res: Response) => {
  try {
    const { vaultId, tokenIn, tokenOut, amountIn, slippageBps } = req.body;

    if (!vaultId || !tokenIn || !tokenOut || amountIn === undefined) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: {
          vaultId: 'string',
          tokenIn: 'string (address)',
          tokenOut: 'string (address)',
          amountIn: 'number (ETH)',
          slippageBps: 'number (optional, default 50)',
        },
      });
    }

    const parsedAmountIn = parseFloat(amountIn);
    if (isNaN(parsedAmountIn) || parsedAmountIn <= 0) {
      return res.status(400).json({ error: 'amountIn must be a positive number' });
    }

    // Apply spending cap policy check
    const policies = await getPolicies(vaultId);
    const policyResults = [];
    let blocked = false;
    let blockReason = '';

    for (const policy of policies) {
      if (policy.type === 'spending-cap') {
        const cfg = policy.config as { perTransactionLimit: number; dailyLimit: number };
        const result = await evaluateSpendingCap(String(policy._id), cfg, vaultId, parsedAmountIn);
        policyResults.push(result);
        if (!result.passed) {
          blocked = true;
          blockReason = result.reason ?? 'Spending cap exceeded';
        }
      }
    }

    if (blocked) {
      await logAction({
        vaultId,
        action: 'policy_violation',
        details: { tokenIn, tokenOut, amountIn: parsedAmountIn, blockReason, operation: 'swap' },
        policyResults,
      });
      return res.status(403).json({
        success: false,
        blocked: true,
        blockReason,
        policyResults,
      });
    }

    // Simulate swap: 1:1 ratio minus 0.3% DEX fee (stub — production: call Uniswap v3 on Base)
    const slippage = (slippageBps ?? 50) / 10000;
    const estimatedAmountOut = parsedAmountIn * (1 - 0.003 - slippage);

    const auditLogId = await logAction({
      vaultId,
      action: 'swap',
      details: {
        tokenIn,
        tokenOut,
        amountIn: parsedAmountIn,
        estimatedAmountOut,
        slippageBps: slippageBps ?? 50,
        dex: 'Uniswap V3 (Base L2)',
        note: 'Stub swap — production: execute via Uniswap V3 on Base, signed by Lit PKP',
      },
      policyResults,
    });

    return res.json({
      success: true,
      vaultId,
      tokenIn,
      tokenOut,
      amountIn: parsedAmountIn,
      estimatedAmountOut,
      slippageBps: slippageBps ?? 50,
      auditLogId,
      policyResults,
      storageMode: storageMode(),
      timestamp: new Date().toISOString(),
      note: 'Swap is simulated. In production: executed via Uniswap V3 on Base L2, signed by Lit Protocol PKP.',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Swap failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/deposit-address ─────────────────

vaultRouter.get('/:vaultId/deposit-address', async (req: Request, res: Response) => {
  const { vaultId } = req.params;
  const pkp = await getOrCreatePKP(vaultId);
  return res.json({
    vaultId,
    depositAddress: pkp.ethAddress,
    pkpTokenId: pkp.pkpTokenId,
    publicKey: pkp.publicKey,
    note: 'PKP-derived Ethereum address managed by Lit Protocol MPC network. Send funds here to deposit into the vault.',
    chain: 'Base L2 (chainId: 8453)',
    litNetwork: pkp.litNetwork,
    demoMode: pkp.demoMode,
  });
});

// ─── GET /api/vault/:vaultId/pkp ─────────────────────────────

vaultRouter.get('/:vaultId/pkp', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const pkp = await getOrCreatePKP(vaultId);
    const sessionSigs = await getSessionSigs(vaultId);
    return res.json({
      vaultId,
      pkp: {
        tokenId: pkp.pkpTokenId,
        publicKey: pkp.publicKey,
        ethAddress: pkp.ethAddress,
        chainId: pkp.chainId,
        litNetwork: pkp.litNetwork,
        createdAt: pkp.createdAt,
        demoMode: pkp.demoMode,
      },
      sessionSigs: {
        expiresAt: sessionSigs.expiresAt,
        capabilities: sessionSigs.capabilities,
        note: 'Session sigs authorize this agent to sign txs via Lit Action execution',
      },
      architecture: {
        keyManagement: 'Lit Protocol 30-node MPC (threshold ECDSA t=15/30)',
        signing: 'Lit Actions (JavaScript TEE on all 30 nodes)',
        policyEnforcement: 'Vincent SDK + on-chain ACL conditions',
        compliance: 'ZK-hash audit trail with threshold attestation',
      },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'PKP query failed', details: msg });
  }
});

// ─── POST /api/vault/:vaultId/sign ───────────────────────────

vaultRouter.post('/:vaultId/sign', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const { to, value, data, chainId = 8453, gasLimit, nonce } = req.body;

    if (!to || !value) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: { to: 'string (address)', value: 'string (ETH amount)' },
      });
    }

    const pkp = await getOrCreatePKP(vaultId);
    const signed = await signTransaction(pkp, { to, value, data, chainId, gasLimit, nonce });

    await logAction({
      vaultId,
      action: 'transfer',
      details: {
        to,
        amount: parseFloat(value),
        signedViaPKP: true,
        litNetwork: pkp.litNetwork,
        litActionCid: signed.litActionCid,
      },
      txHash: signed.txHash,
    });

    return res.json({
      success: true,
      ...signed,
      pkpAddress: pkp.ethAddress,
      litNetwork: pkp.litNetwork,
      note: 'Transaction signed by Lit Protocol PKP via threshold ECDSA (demo mode)',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'PKP signing failed', details: msg });
  }
});

// ─── POST /api/vault/:vaultId/attest ─────────────────────────

vaultRouter.post('/:vaultId/attest', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'message is required' });
    }

    const pkp = await getOrCreatePKP(vaultId);
    const signature = await signMessage(pkp, message);

    return res.json({
      success: true,
      vaultId,
      message,
      signature,
      signer: pkp.ethAddress,
      litNetwork: pkp.litNetwork,
      note: 'Message signed by Lit Protocol PKP for off-chain attestation',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Attestation failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/queue ───────────────────────────

vaultRouter.get('/:vaultId/queue', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const queue = getQueue(vaultId);
    const now = new Date();
    const enriched = queue.map((item) => ({
      ...item,
      readyForExecution: item.status === 'pending' && now >= new Date(item.executeAfter),
      secondsRemaining: Math.max(0, Math.ceil((new Date(item.executeAfter).getTime() - now.getTime()) / 1000)),
    }));
    return res.json({ vaultId, count: enriched.length, queue: enriched });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Queue query failed', details: msg });
  }
});

// ─── DELETE /api/vault/queue/:queueId ────────────────────────

vaultRouter.delete('/queue/:queueId', async (req: Request, res: Response) => {
  try {
    const { queueId } = req.params;
    const { cancelledBy } = req.body;
    const item = cancelQueuedTransaction(queueId, cancelledBy);
    if (!item) {
      return res.status(404).json({ error: 'Queue item not found or not cancellable' });
    }
    return res.json({ success: true, cancelled: item });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Cancel failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/approvals ───────────────────────

vaultRouter.get('/:vaultId/approvals', async (req: Request, res: Response) => {
  try {
    const { vaultId } = req.params;
    const requests = getApprovalRequests(vaultId);
    return res.json({ vaultId, count: requests.length, approvalRequests: requests });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Approvals query failed', details: msg });
  }
});

// ─── POST /api/vault/approvals/:requestId/approve ────────────

vaultRouter.post('/approvals/:requestId/approve', async (req: Request, res: Response) => {
  try {
    const { requestId } = req.params;
    const { approverId, signature } = req.body;

    if (!approverId || !signature) {
      return res.status(400).json({
        error: 'approverId and signature are required',
        note: 'Sign the requestId with your PKP key: ethers.signMessage(requestId)',
      });
    }

    const result = submitApproval(requestId, approverId, signature);
    if (!result) {
      return res.status(404).json({ error: 'Approval request not found or already processed' });
    }

    return res.json({
      success: true,
      requestId,
      status: result.status,
      approvalsReceived: result.approvals.length,
      required: result.requiredApprovals,
      approved: result.status === 'approved',
      request: result,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Approval submission failed', details: msg });
  }
});

// ─── POST /api/vault/:vaultId/secrets ─────────────────────────
vaultRouter.post('/:vaultId/secrets', async (req, res) => {
  try {
    const { vaultId } = req.params;
    const { vaultAddress, name, value, accessPolicy } = req.body;
    if (!vaultAddress || !name || value === undefined) {
      return res.status(400).json({ error: 'vaultAddress, name, and value are required' });
    }
    const result = await storeSecret({ vaultId, vaultAddress, name, value, accessPolicy });
    return res.status(201).json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Secret store failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/secrets ──────────────────────────
vaultRouter.get('/:vaultId/secrets', async (req, res) => {
  try {
    const { vaultId } = req.params;
    const result = await listSecrets(vaultId);
    return res.json({ ...result, note: 'Values never returned in listings.' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Secret list failed', details: msg });
  }
});

// ─── GET /api/vault/:vaultId/secrets/:name ────────────────────
vaultRouter.get('/:vaultId/secrets/:name', async (req, res) => {
  try {
    const { vaultId, name } = req.params;
    const { vaultAddress } = req.query;
    if (!vaultAddress) return res.status(400).json({ error: 'vaultAddress query param required' });
    const result = await retrieveSecret({ vaultId, vaultAddress: String(vaultAddress), name });
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: 'Secret retrieval failed', details: msg });
  }
});

// ─── DELETE /api/vault/:vaultId/secrets/:name ─────────────────
vaultRouter.delete('/:vaultId/secrets/:name', async (req, res) => {
  try {
    const { vaultId, name } = req.params;
    const result = await deleteSecret(vaultId, name);
    if (!result.deleted) return res.status(404).json({ error: 'Secret not found' });
    return res.json({ success: true, vaultId, name, message: 'Secret permanently deleted' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: 'Secret delete failed', details: msg });
  }
});
