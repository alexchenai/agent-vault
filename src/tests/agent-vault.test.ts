/**
 * Agent Vault Test Suite — SYNTHESIS Hackathon Demo
 *
 * Tests all core functionality:
 * - PKP wallet: mint, sign, attest
 * - Policies: spending-cap, whitelist, time-lock, multi-agent approval, rate-limiter
 * - Compliance proofs: generate, verify
 * - Audit trail: persistence and pagination
 */

import { ethers } from 'ethers';
import { mintPKP, signTransaction, signMessage, getOrCreatePKP, verifyPKPSignature } from '../vault/wallet';
import { evaluateSpendingCap } from '../policies/spending-cap';
import { evaluateTimeLock, getQueue, cancelQueuedTransaction } from '../policies/time-lock';
import { evaluateMultiAgentApproval, submitApproval, getApprovalRequest } from '../policies/multi-agent-approval';
import { evaluateRateLimit, RateLimiterPolicy } from '../policies/rate-limiter';
import { logAction } from '../vault/audit-log';
import { evaluateCircuitBreaker, getCircuitState, resetCircuit, CircuitBreakerPolicy } from '../policies/circuit-breaker';
import { storeSecret, retrieveSecret, listSecrets, deleteSecret } from '../abilities/vault-secrets';

// ─── Minimal test runner ──────────────────────────────────────

let passed = 0;
let failed = 0;
const errors: string[] = [];

async function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  PASS ${name}`);
  } catch (err) {
    failed++;
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`${name}: ${msg}`);
    console.error(`  FAIL ${name}: ${msg}`);
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function assertEqual<T>(actual: T, expected: T, label?: string): void {
  if (actual !== expected) {
    throw new Error(`${label ?? 'assertEqual'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertMatch(str: string, pattern: RegExp, label?: string): void {
  if (!pattern.test(str)) {
    throw new Error(`${label ?? 'assertMatch'}: "${str}" does not match ${pattern}`);
  }
}

// ─── PKP Wallet Tests ─────────────────────────────────────────

async function testPKPWallet(): Promise<void> {
  console.log('\n== PKP Wallet Tests ==');

  await test('mintPKP returns a VaultWallet', async () => {
    const wallet = await mintPKP('test-vault-001');
    assert(wallet.ethAddress.startsWith('0x'), 'ethAddress starts with 0x');
    assert(wallet.ethAddress.length === 42, 'ethAddress is 42 chars');
    assert(wallet.publicKey.startsWith('0x'), 'publicKey starts with 0x');
    assert(wallet.pkpTokenId.startsWith('0x'), 'pkpTokenId starts with 0x');
    assertEqual(wallet.chainId, 8453, 'chainId is Base');
    assertEqual(wallet.litNetwork, 'datil-dev', 'litNetwork is datil-dev');
    assertEqual(wallet.demoMode, true, 'demoMode is true');
  });

  await test('mintPKP is deterministic (same vaultId = same address)', async () => {
    const w1 = await mintPKP('determinism-test-vault');
    const w2 = await getOrCreatePKP('determinism-test-vault');
    assertEqual(w1.ethAddress, w2.ethAddress, 'same address on second call');
  });

  await test('different vaultIds produce different PKPs', async () => {
    const w1 = await mintPKP('vault-a-' + Date.now());
    const w2 = await mintPKP('vault-b-' + Date.now());
    assert(w1.ethAddress !== w2.ethAddress, 'different vaults have different addresses');
  });

  await test('signTransaction produces valid RLP-encoded tx', async () => {
    const wallet = await mintPKP('sign-test-vault');
    const signed = await signTransaction(wallet, {
      to: '0x1234567890123456789012345678901234567890',
      value: '0.001',
      chainId: 8453,
    });
    assert(signed.signedTx.startsWith('0x02'), 'EIP-1559 tx starts with 0x02');
    assert(signed.txHash.startsWith('0x'), 'txHash starts with 0x');
    assertEqual(signed.txHash.length, 66, 'txHash is 32 bytes hex');
    assertEqual(signed.from, wallet.ethAddress, 'from matches PKP address');
    assertEqual(signed.to, '0x1234567890123456789012345678901234567890', 'to matches');
    assertEqual(signed.litActionCid, 'QmAgentVaultTransferAction_v1_demo', 'Lit Action CID set');
  });

  await test('signTransaction produces verifiable signature', async () => {
    const wallet = await mintPKP('verify-sign-test');
    const signed = await signTransaction(wallet, {
      to: '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
      value: '0.0001',
      chainId: 8453,
    });

    // Recover the signer from the signed tx
    const tx = ethers.Transaction.from(signed.signedTx);
    assert(tx.from !== null, 'tx.from is recoverable');
    assertEqual(
      tx.from!.toLowerCase(),
      wallet.ethAddress.toLowerCase(),
      'recovered signer matches PKP address'
    );
  });

  await test('signMessage produces verifiable ECDSA signature', async () => {
    const wallet = await mintPKP('attest-test-vault');
    const message = 'Agent Vault compliance proof: vaultId=attest-test-vault';
    const signature = await signMessage(wallet, message);

    assert(signature.startsWith('0x'), 'signature starts with 0x');

    const verified = verifyPKPSignature(message, signature, wallet.ethAddress);
    assertEqual(verified, true, 'signature is verifiable against PKP address');
  });

  await test('signMessage with wrong address fails verification', async () => {
    const wallet = await mintPKP('attest-wrong-test');
    const message = 'test message';
    const signature = await signMessage(wallet, message);

    const fakeAddress = '0x0000000000000000000000000000000000000001';
    const verified = verifyPKPSignature(message, signature, fakeAddress);
    assertEqual(verified, false, 'wrong address fails verification');
  });
}

// ─── Spending Cap Policy Tests ────────────────────────────────

async function testSpendingCap(): Promise<void> {
  console.log('\n== Spending Cap Policy Tests ==');

  await test('spending-cap: allows transfer below per-tx limit', async () => {
    const result = await evaluateSpendingCap('cap-1', { perTransactionLimit: 1.0, dailyLimit: 5.0 }, 'sc-vault-new', 0.5);
    assertEqual(result.passed, true, 'below limit passes');
    assertEqual(result.policyType, 'spending-cap', 'type is spending-cap');
  });

  await test('spending-cap: blocks transfer above per-tx limit', async () => {
    const result = await evaluateSpendingCap('cap-2', { perTransactionLimit: 1.0, dailyLimit: 5.0 }, 'sc-vault-new-2', 2.0);
    assertEqual(result.passed, false, 'above limit fails');
    assert(result.reason!.includes('exceeds per-transaction limit'), 'reason mentions limit');
  });

  await test('spending-cap: allows transfer at exact per-tx limit', async () => {
    const result = await evaluateSpendingCap('cap-3', { perTransactionLimit: 1.0, dailyLimit: 5.0 }, 'sc-vault-exact', 1.0);
    assertEqual(result.passed, true, 'exactly at limit passes');
  });
}

// ─── Time-Lock Policy Tests ───────────────────────────────────

async function testTimeLock(): Promise<void> {
  console.log('\n== Time-Lock Policy Tests ==');

  const cfg = { thresholdAmount: 1.0, delaySeconds: 600 };

  await test('time-lock: allows small transfer immediately', async () => {
    const result = await evaluateTimeLock('tl-1', cfg, 'tl-vault', '0xABC', 0.5);
    assertEqual(result.passed, true, 'below threshold passes immediately');
    assert(!result.requiresDelay, 'no delay required');
  });

  await test('time-lock: queues large transfer', async () => {
    const result = await evaluateTimeLock('tl-2', cfg, 'tl-vault', '0xABC', 2.0);
    assertEqual(result.passed, false, 'above threshold is queued');
    assertEqual(result.requiresDelay, true, 'requiresDelay is true');
    assert(result.queuedTransaction !== undefined, 'queuedTransaction is set');
    assert(result.queuedTransaction!.queueId.startsWith('tl-'), 'queueId starts with tl-');
    assert(result.queuedTransaction!.status === 'pending', 'status is pending');
  });

  await test('time-lock: queued transaction appears in queue', async () => {
    await evaluateTimeLock('tl-3', cfg, 'tl-list-vault', '0xDEF', 5.0);
    const queue = getQueue('tl-list-vault');
    assert(queue.length > 0, 'queue has items');
    assertEqual(queue[0].status, 'pending', 'item is pending');
    assertEqual(queue[0].vaultId, 'tl-list-vault', 'vaultId matches');
  });

  await test('time-lock: cancelled transaction is removed from pending', async () => {
    const result = await evaluateTimeLock('tl-4', cfg, 'tl-cancel-vault', '0xGHI', 3.0);
    const queueId = result.queuedTransaction!.queueId;

    const cancelled = cancelQueuedTransaction(queueId, 'admin');
    assert(cancelled !== null, 'cancellation returns the item');
    assertEqual(cancelled!.status, 'cancelled', 'status is cancelled');
    assertEqual(cancelled!.cancelledBy, 'admin', 'cancelledBy is admin');
  });

  await test('time-lock: executeAfter is in the future', async () => {
    const result = await evaluateTimeLock('tl-5', cfg, 'tl-future-vault', '0xJKL', 2.0);
    const executeAfter = new Date(result.queuedTransaction!.executeAfter);
    assert(executeAfter > new Date(), 'executeAfter is in the future');
    const delayMs = executeAfter.getTime() - new Date().getTime();
    assert(delayMs > 590_000 && delayMs < 610_000, 'delay is approximately 600s');
  });
}

// ─── Multi-Agent Approval Tests ───────────────────────────────

async function testMultiAgentApproval(): Promise<void> {
  console.log('\n== Multi-Agent Approval Tests ==');

  const cfg = { thresholdAmount: 0.5, requiredApprovals: 2, timeoutSeconds: 3600, approvers: [] };

  await test('multi-agent: allows small transfer without approval', async () => {
    const result = await evaluateMultiAgentApproval('ma-1', cfg, 'ma-vault', '0xABC', 0.3);
    assertEqual(result.passed, true, 'below threshold passes without approval');
  });

  await test('multi-agent: creates approval request for large transfer', async () => {
    const result = await evaluateMultiAgentApproval('ma-2', cfg, 'ma-vault', '0xABC', 1.0);
    assertEqual(result.passed, false, 'above threshold requires approval');
    assert(result.approvalRequest !== undefined, 'approvalRequest created');
    assert(result.approvalRequest!.requestId.startsWith('apr-'), 'requestId starts with apr-');
    assertEqual(result.approvalRequest!.status, 'pending', 'status is pending');
    assertEqual(result.approvalRequest!.requiredApprovals, 2, 'requiredApprovals matches');
  });

  await test('multi-agent: approval threshold triggers status change', async () => {
    const result = await evaluateMultiAgentApproval('ma-3', cfg, 'ma-threshold-vault', '0xDEF', 2.0);
    const requestId = result.approvalRequest!.requestId;

    // Generate two approver wallets
    const approver1 = ethers.Wallet.createRandom();
    const approver2 = ethers.Wallet.createRandom();

    // First approval - not enough
    const sig1 = await approver1.signMessage(requestId);
    const after1 = submitApproval(requestId, approver1.address, sig1);
    assertEqual(after1!.approvals.length, 1, 'one approval recorded');
    assertEqual(after1!.status, 'pending', 'still pending after 1 approval');

    // Second approval - threshold met
    const sig2 = await approver2.signMessage(requestId);
    const after2 = submitApproval(requestId, approver2.address, sig2);
    assertEqual(after2!.approvals.length, 2, 'two approvals recorded');
    assertEqual(after2!.status, 'approved', 'approved after 2 approvals');
  });

  await test('multi-agent: duplicate approver is ignored', async () => {
    const result = await evaluateMultiAgentApproval('ma-4', cfg, 'ma-dup-vault', '0xGHI', 3.0);
    const requestId = result.approvalRequest!.requestId;

    const approver = ethers.Wallet.createRandom();
    const sig = await approver.signMessage(requestId);

    submitApproval(requestId, approver.address, sig);
    submitApproval(requestId, approver.address, sig); // duplicate

    const req = getApprovalRequest(requestId);
    assertEqual(req!.approvals.length, 1, 'duplicate approval not counted twice');
  });
}

// ─── Rate Limiter Policy Tests ────────────────────────────────

async function testRateLimiter(): Promise<void> {
  console.log('\n== Rate Limiter Policy Tests ==');

  const makePolicy = (overrides: Partial<RateLimiterPolicy> = {}): RateLimiterPolicy => ({
    id: 'rl-test-' + Date.now(),
    type: 'rate-limiter',
    maxTransactions: 3,
    windowSeconds: 60,
    cooldownSeconds: 30,
    enabled: true,
    createdAt: new Date(),
    ...overrides,
  });

  await test('rate-limiter: allows first transaction (empty history)', async () => {
    const vaultId = 'rl-vault-empty-' + Date.now();
    const result = await evaluateRateLimit(makePolicy(), vaultId);
    assertEqual(result.passed, true, 'first tx allowed');
    assertEqual(result.policyType, 'rate-limiter', 'policyType correct');
    assert(result.reason!.includes('0/3'), 'reason shows 0/3 usage');
  });

  await test('rate-limiter: allows transactions below limit', async () => {
    const vaultId = 'rl-vault-under-' + Date.now();
    // Log 2 transfers (below limit of 3)
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    const result = await evaluateRateLimit(makePolicy(), vaultId);
    assertEqual(result.passed, true, 'under limit passes');
    assert(result.reason!.includes('2/3'), 'reason shows 2/3 usage');
  });

  await test('rate-limiter: blocks when limit reached', async () => {
    const vaultId = 'rl-vault-full-' + Date.now();
    // Log 3 transfers (at the limit)
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    const result = await evaluateRateLimit(makePolicy(), vaultId);
    assertEqual(result.passed, false, 'at limit is blocked');
    assert(result.reason!.includes('3/3'), 'reason shows 3/3');
  });

  await test('rate-limiter: deposits do not count against transfer limit', async () => {
    const vaultId = 'rl-vault-deposits-' + Date.now();
    // Log 5 deposits — should NOT count if actionTypes = ['transfer','swap']
    for (let i = 0; i < 5; i++) {
      await logAction({ vaultId, action: 'deposit', details: { amount: 1.0 } });
    }
    const result = await evaluateRateLimit(makePolicy({ actionTypes: ['transfer', 'swap'] }), vaultId);
    assertEqual(result.passed, true, 'deposits do not count against transfer limit');
    assert(result.reason!.includes('0/3'), 'reason shows 0/3 (deposits not counted)');
  });

  await test('rate-limiter: swaps count toward combined action limit', async () => {
    const vaultId = 'rl-vault-swaps-' + Date.now();
    // Mix of transfers and swaps — 3 total should hit limit
    await logAction({ vaultId, action: 'transfer', details: { amount: 0.1 } });
    await logAction({ vaultId, action: 'swap', details: { fromToken: 'ETH', toToken: 'USDC' } });
    await logAction({ vaultId, action: 'swap', details: { fromToken: 'ETH', toToken: 'USDC' } });
    const result = await evaluateRateLimit(makePolicy({ actionTypes: ['transfer', 'swap'] }), vaultId);
    assertEqual(result.passed, false, 'mixed transfers+swaps hit limit');
    assert(result.reason!.includes('3/3'), 'reason shows 3/3');
  });
}

// ─── Compliance Proof Integration Test ───────────────────────

async function testComplianceProof(): Promise<void> {
  console.log('\n== Compliance Proof (Integration) ==');

  await test('attestation signature is verifiable', async () => {
    const wallet = await mintPKP('proof-vault');
    const message = 'auditRoot:abc123';
    const sig = await signMessage(wallet, message);
    const verified = verifyPKPSignature(message, sig, wallet.ethAddress);
    assertEqual(verified, true, 'proof attestation verifiable');
  });
}

// ─── Main test runner ─────────────────────────────────────────

// ─── Circuit Breaker Tests ──────────────────────────────────────

async function testCircuitBreaker(): Promise<void> {
  console.log("\n== Circuit Breaker Tests ==");

  const policy: CircuitBreakerPolicy = {
    failureThreshold: 2,
    cooldownSeconds: 60,
    maxSingleTransactionUsd: 100,
    maxWindowSpendUsd: 200,
    windowSeconds: 3600,
  };

  resetCircuit("cb-test-vault");

  await test("allows normal transaction", () => {
    const r = evaluateCircuitBreaker("cb-test-vault", 50, policy);
    assert(r.allowed, "50 USD should be allowed");
    assertEqual(r.state, "CLOSED", "state should be CLOSED");
  });

  await test("blocks transaction exceeding single limit", () => {
    const r = evaluateCircuitBreaker("cb-test-vault", 150, policy);
    assert(!r.allowed, "150 USD should be blocked (> 100 limit)");
    assert(r.reason.includes("150"), "reason should mention amount");
  });

  await test("opens circuit after failure threshold", () => {
    resetCircuit("cb-trip-vault");
    evaluateCircuitBreaker("cb-trip-vault", 150, policy);
    const r = evaluateCircuitBreaker("cb-trip-vault", 150, policy);
    assert(!r.allowed, "should be blocked");
    assertEqual(r.state, "OPEN", "circuit should be OPEN after 2 failures");
  });

  await test("OPEN circuit blocks normal transactions", () => {
    const r = evaluateCircuitBreaker("cb-trip-vault", 10, policy);
    assert(!r.allowed, "OPEN circuit blocks all transactions");
    assertEqual(r.state, "OPEN");
  });

  await test("getCircuitState returns correct state", () => {
    const s = getCircuitState("cb-trip-vault");
    assert(s !== null, "should have state");
    assertEqual(s!.state, "OPEN");
    assert(s!.consecutiveFailures >= 2, "should have 2+ failures");
  });

  await test("stateHash is a non-empty string", () => {
    const r = evaluateCircuitBreaker("cb-hash-vault", 10, policy);
    assert(r.stateHash.length > 0, "stateHash should be non-empty");
    assertMatch(r.stateHash, /^[a-f0-9]+$/, "stateHash should be hex");
  });
}


// ─── Vault Secrets Tests ─────────────────────────────────────
async function testVaultSecrets(): Promise<void> {
  const vaultId = 'test-vault-secrets-001';
  const vaultAddress = '0xDeadBeef0000000000000000000000000000dEaD';

  await test('Store a secret with default policy', async () => {
    const result = await storeSecret({
      vaultId,
      vaultAddress,
      name: 'api-key',
      value: 'sk-supersecret-12345',
    });
    assert(result.secretId.length > 0, 'secretId should be generated');
    assert(result.name === 'api-key', 'name should match');
    assert(result.accessPolicy === 'vault-only', 'default policy should be vault-only');
    assert(result.keyHash.length > 0, 'keyHash should be present');
  });

  await test('Retrieve and decrypt a stored secret', async () => {
    const result = await retrieveSecret({ vaultId, vaultAddress, name: 'api-key' });
    assert(result.value === 'sk-supersecret-12345', 'decrypted value should match original');
    assert(result.accessCount === 1, 'access count should increment');
    assert(result.lastAccessedAt !== undefined, 'lastAccessedAt should be set');
  });

  await test('Store a second secret with multi-agent policy', async () => {
    const result = await storeSecret({
      vaultId,
      vaultAddress,
      name: 'shared-key',
      value: 'shared-secret-xyz',
      accessPolicy: 'multi-agent',
    });
    assert(result.accessPolicy === 'multi-agent', 'policy should be multi-agent');
  });

  await test('List secrets - values should not be exposed', async () => {
    const result = await listSecrets(vaultId);
    assert(result.count >= 2, 'should list at least 2 secrets');
    const secretNames = result.secrets.map(s => s.name);
    assert(secretNames.includes('api-key'), 'api-key should be in list');
    assert(secretNames.includes('shared-key'), 'shared-key should be in list');
    // Values must not appear in listing
    result.secrets.forEach(s => {
      assert(!('value' in s), 'listing should never expose secret values');
    });
  });

  await test('Access count increments on each retrieval', async () => {
    await retrieveSecret({ vaultId, vaultAddress, name: 'api-key' });
    const result = await retrieveSecret({ vaultId, vaultAddress, name: 'api-key' });
    assert(result.accessCount === 3, 'access count should be 3 after 3 total retrievals');
  });

  await test('Delete a secret permanently', async () => {
    const deleteResult = await deleteSecret(vaultId, 'api-key');
    assert(deleteResult.deleted === true, 'should confirm deletion');
    const listResult = await listSecrets(vaultId);
    const names = listResult.secrets.map(s => s.name);
    assert(!names.includes('api-key'), 'deleted secret should not appear in listing');
  });

  await test('Retrieve non-existent secret throws error', async () => {
    let threw = false;
    try {
      await retrieveSecret({ vaultId, vaultAddress, name: 'doesnt-exist' });
    } catch (e) {
      threw = true;
    }
    assert(threw, 'should throw error for missing secret');
  });
}

async function runAllTests(): Promise<void> {
  console.log('=== Agent Vault Test Suite ===');
  console.log('Testing: PKP Wallet, Policies, Compliance Proofs\n');

  await testPKPWallet();
  await testSpendingCap();
  await testTimeLock();
  await testMultiAgentApproval();
  await testRateLimiter();
  await testComplianceProof();
  await testCircuitBreaker();
  await testVaultSecrets();

  console.log('\n=== Results ===');
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);

  if (errors.length > 0) {
    console.error('\nFailed tests:');
    errors.forEach((e) => console.error(`  - ${e}`));
    process.exit(1);
  } else {
    console.log('\nAll tests passed!');
    process.exit(0);
  }
}

runAllTests().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
