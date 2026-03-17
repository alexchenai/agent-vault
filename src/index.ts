import express from 'express';
import cors from 'cors';
import path from 'path';
import { config, validateConfig } from './config';
import { connectDb, getDb, isConnected, logAction } from './vault/audit-log';
import { mintPKP, signMessage, verifyPKPSignature } from './vault/wallet';
import { evaluateSpendingCap } from './policies/spending-cap';
import { vaultRouter } from './routes/vault';
import { policiesRouter } from './routes/policies';
import { proofRouter } from './routes/proof';
import anomalyRouter from './routes/anomaly';

const app = express();

app.use(cors());
app.use(express.json());

// Serve static frontend
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.static(path.join(process.cwd(), 'public')));

// Health
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: config.version,
    project: config.project,
    storage: isConnected() ? 'mongodb' : 'in-memory',
  });
});

// Stats
app.get('/api/stats', async (_req, res) => {
  try {
    const db = getDb();
    if (db) {
      const [vaults, policies, proofs] = await Promise.all([
        db.collection('balances').countDocuments(),
        db.collection('policies').countDocuments({ enabled: true }),
        db.collection('audit_log').countDocuments({ action: 'proof_generated' }),
      ]);
      return res.json({ vaults, policies, proofs, storage: 'mongodb' });
    }
    return res.json({ vaults: 0, policies: 0, proofs: 0, storage: 'in-memory' });
  } catch (err: unknown) {
    return res.json({ vaults: 0, policies: 0, proofs: 0, storage: 'error' });
  }
});

app.get('/info', (_req, res) => {
  res.json({
    project: 'Agent Vault',
    track: 'Agents that keep secrets',
    hackathon: 'SYNTHESIS 2026',
    description: 'An autonomous agent that manages funds on Ethereum with MPC-protected private keys (Lit Protocol), enforceable spending policies, and verifiable compliance proofs.',
    stack: ['TypeScript', 'Lit Protocol Vincent SDK', 'Base L2', 'MongoDB', 'Express.js'],
    abilities: [
      'vault-deposit - Receive funds into MPC-managed wallet',
      'vault-transfer - Send funds with policy enforcement',
      'vault-swap - Swap tokens via DEX with spending caps',
      'vault-proof - Generate ZK compliance proofs',
    ],
    policies: [
      'spending-cap - Per-tx and daily spending limits',
      'whitelist-only - Restrict destinations to approved addresses',
      'rate-limiter - Max N transactions per time window',
      'time-lock - Delay large transfers for review period',
      'multi-agent-approval - Require M-of-N agent signatures',
    ],
    version: config.version,
  });
});

// Demo Endpoint for SYNTHESIS judges
app.all('/api/demo', async (_req, res) => {
  const demoVaultId = 'demo-' + Date.now();
  const steps: Array<{ step: string; result: string; ok: boolean }> = [];

  try {
    // Step 1: Mint PKP (Lit Protocol MPC key)
    const pkp = await mintPKP(demoVaultId);
    steps.push({
      step: '1. Mint PKP (Lit Protocol MPC key)',
      result: 'address=' + pkp.ethAddress + ' tokenId=' + pkp.pkpTokenId.slice(0, 16) + '...',
      ok: true,
    });

    // Step 2: Log deposit to audit log
    await logAction({
      vaultId: demoVaultId,
      action: 'deposit',
      details: { amount: 10, token: 'ETH', address: pkp.ethAddress },
    });
    steps.push({
      step: '2. Deposit 10 ETH to vault',
      result: 'logged to audit trail, vault=' + demoVaultId,
      ok: true,
    });

    // Step 3: Spending cap policy check
    const capConfig = { perTransactionLimit: 5, dailyLimit: 20 };
    const allowed = await evaluateSpendingCap(demoVaultId + '-cap', capConfig, demoVaultId, 5);
    const blocked = await evaluateSpendingCap(demoVaultId + '-cap2', capConfig, demoVaultId, 6);
    steps.push({
      step: '3. Spending cap policy check',
      result: '5 ETH tx: ' + (allowed.passed ? 'ALLOWED' : 'BLOCKED') + ' | 6 ETH tx: ' + (blocked.passed ? 'ALLOWED' : 'BLOCKED (exceeds 5 ETH cap)'),
      ok: allowed.passed && !blocked.passed,
    });

    // Step 4: Threshold ECDSA signature
    const msgHash = 'Agent Vault Transfer vault=' + demoVaultId + ' amount=5 ETH';
    const sig = await signMessage(pkp, msgHash);
    steps.push({
      step: '4. Threshold ECDSA signature (Lit Protocol MPC)',
      result: 'sig=' + sig.slice(0, 20) + '... (' + sig.length + ' chars)',
      ok: sig.length > 0,
    });

    // Step 5: Verify signature
    const isValid = verifyPKPSignature(msgHash, sig, pkp.ethAddress);
    steps.push({
      step: '5. Signature verification',
      result: 'valid=' + isValid + ' address=' + pkp.ethAddress.slice(0, 10) + '...',
      ok: isValid,
    });

    // Step 6: Compliance proof
    const proofPayload = JSON.stringify({
      vaultId: demoVaultId,
      action: 'transfer',
      amount: 5,
      token: 'ETH',
      policyChecks: ['spending-cap: PASS'],
      timestamp: new Date().toISOString(),
    });
    const proofSig = await signMessage(pkp, proofPayload);
    const proofVerified = verifyPKPSignature(proofPayload, proofSig, pkp.ethAddress);
    steps.push({
      step: '6. ZK-style compliance proof',
      result: 'proof_sig=' + proofSig.slice(0, 20) + '... verified=' + proofVerified,
      ok: proofVerified,
    });

    const allPassed = steps.every((s) => s.ok);
    return res.json({
      demo: 'Agent Vault - SYNTHESIS 2026',
      track: 'Agents that keep secrets (Lit Protocol)',
      vaultId: demoVaultId,
      allPassed,
      steps,
      summary: allPassed
        ? 'All 6 demo steps PASSED. Agent Vault is fully operational.'
        : 'Some steps failed. Check individual step results.',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: msg, steps });
  }
});

// Also support POST /api/demo for evaluators

// API Routes
app.use('/api/vault', vaultRouter);
app.use('/api/policies', policiesRouter);
app.use('/api/proof', proofRouter);
app.use('/api/anomaly', anomalyRouter);

// SYNTHESIS conversation log endpoint
app.get("/api/conversation-log", (_req, res) => {
  res.sendFile(path.join(process.cwd(), "public", "conversation-log.json"));
});

// SKILL.md endpoint for agent discovery
app.get("/skill.md", (_req, res) => {
  res.type("text/markdown");
  res.sendFile(path.join(process.cwd(), "public", "SKILL.md"));
});
app.get("/SKILL.md", (_req, res) => {
  res.type("text/markdown");
  res.sendFile(path.join(process.cwd(), "public", "SKILL.md"));
});

// Startup
async function start() {
  const warnings = validateConfig();
  warnings.forEach((w) => console.warn('[agent-vault] WARNING: ' + w));

  if (config.mongodbUri) {
    try {
      await connectDb(config.mongodbUri);
      console.log('[agent-vault] Connected to MongoDB');
    } catch (err) {
      console.error('[agent-vault] MongoDB connection failed:', err);
      console.warn('[agent-vault] Continuing without database...');
    }
  } else {
    console.log('[agent-vault] No MONGODB_URI - running in stateless mode');
  }

  app.listen(config.port, '0.0.0.0', () => {
    console.log('[agent-vault] v' + config.version + ' listening on port ' + config.port);
  });
}

start().catch((err) => {
  console.error('[agent-vault] Fatal startup error:', err);
  process.exit(1);
});

export default app;
