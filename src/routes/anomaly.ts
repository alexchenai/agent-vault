/**
 * Behavioral Anomaly Detector
 * 
 * Addresses the "patient attacker" problem: an agent manipulated into 
 * authorized-looking transactions that individually pass policy checks
 * but collectively represent a drain attack.
 * 
 * Analyzes spend velocity, time spacing, destination diversity, and
 * prompt injection patterns to detect behavioral anomalies.
 */

import { Router } from 'express';
import { getDb } from '../vault/audit-log';

export const anomalyRouter = Router();

interface AnomalyResult {
  vaultId: string;
  riskScore: number;       // 0-100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  signals: AnomalySignal[];
  recommendation: string;
  analyzedAt: string;
}

interface AnomalySignal {
  type: string;
  description: string;
  weight: number;           // contribution to risk score
  detected: boolean;
  evidence?: string;
}

/**
 * POST /api/anomaly/analyze
 * Analyze a vault's transaction history for behavioral anomalies.
 */
anomalyRouter.post('/analyze', async (req, res) => {
  const { vaultId, windowHours = 24 } = req.body as { vaultId: string; windowHours?: number };
  if (!vaultId) return res.status(400).json({ error: 'vaultId required' });

  try {
    // Get audit log entries for this vault
    const db = getDb();
    let entries: Array<{ action: string; details: Record<string, unknown>; timestamp?: Date }> = [];
    
    if (db) {
      const since = new Date(Date.now() - windowHours * 3600 * 1000);
      entries = await db.collection('audit_log')
        .find({ vaultId, timestamp: { $gte: since } })
        .sort({ timestamp: 1 })
        .toArray() as unknown as typeof entries;
    } else {
      // Stateless fallback: use request body history if provided
      entries = (req.body.history || []) as typeof entries;
    }

    const transfers = entries.filter(e => e.action === 'transfer' || e.action === 'spend');
    const amounts = transfers.map(e => parseFloat(String(e.details?.amount ?? 0)));
    const timestamps = transfers.map(e => new Date(e.timestamp ?? Date.now()).getTime());

    const signals: AnomalySignal[] = [];

    // Signal 1: Velocity spike (many transfers in short window)
    const transfersPerHour = transfers.length / Math.max(windowHours, 1);
    const velocityAnomaly = transfersPerHour > 5;
    signals.push({
      type: 'velocity_spike',
      description: 'Unusually high transfer rate (>5/hr)',
      weight: 30,
      detected: velocityAnomaly,
      evidence: velocityAnomaly ? `${transfersPerHour.toFixed(1)} transfers/hr in ${windowHours}h window` : undefined,
    });

    // Signal 2: Amount clustering just below cap (attacker staying under limits)
    const capValue = parseFloat(String(req.body.spendingCapEth ?? 5));
    const justBelowCap = amounts.filter(a => a >= capValue * 0.8 && a <= capValue).length;
    const clusteringAnomaly = justBelowCap >= 3;
    signals.push({
      type: 'cap_clustering',
      description: 'Multiple transactions clustered just below spending cap (manipulation pattern)',
      weight: 35,
      detected: clusteringAnomaly,
      evidence: clusteringAnomaly ? `${justBelowCap} transactions in 80-100% of ${capValue} ETH cap` : undefined,
    });

    // Signal 3: Temporal spacing regularity (bots space transactions at regular intervals)
    const gaps = timestamps.slice(1).map((t, i) => t - timestamps[i]);
    const avgGap = gaps.length > 0 ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
    const stdDev = gaps.length > 1
      ? Math.sqrt(gaps.map(g => Math.pow(g - avgGap, 2)).reduce((a, b) => a + b, 0) / gaps.length)
      : 0;
    const regularityAnomaly = gaps.length >= 3 && stdDev / (avgGap || 1) < 0.15;
    signals.push({
      type: 'temporal_regularity',
      description: 'Unnaturally regular spacing between transactions (automated manipulation)',
      weight: 25,
      detected: regularityAnomaly,
      evidence: regularityAnomaly ? `StdDev/Mean ratio: ${(stdDev / (avgGap || 1)).toFixed(3)} (< 0.15 threshold)` : undefined,
    });

    // Signal 4: Single destination dominance (draining to one address)
    const destinations = transfers.map(e => String(e.details?.to ?? e.details?.destination ?? 'unknown'));
    const destCounts: Record<string, number> = {};
    destinations.forEach(d => { destCounts[d] = (destCounts[d] || 0) + 1; });
    const maxDestCount = Math.max(...Object.values(destCounts), 0);
    const singleDestAnomaly = transfers.length >= 3 && maxDestCount / transfers.length > 0.7;
    signals.push({
      type: 'destination_concentration',
      description: 'Over 70% of transfers going to same destination (drain pattern)',
      weight: 20,
      detected: singleDestAnomaly,
      evidence: singleDestAnomaly ? `${((maxDestCount / transfers.length) * 100).toFixed(0)}% concentration` : undefined,
    });

    // Signal 5: Total cumulative spend approaching vault balance
    const totalSpent = amounts.reduce((a, b) => a + b, 0);
    const vaultBalance = parseFloat(String(req.body.vaultBalanceEth ?? 10));
    const drainAnomaly = vaultBalance > 0 && totalSpent / vaultBalance > 0.8;
    signals.push({
      type: 'cumulative_drain',
      description: 'Cumulative spend >80% of vault balance in window',
      weight: 40,
      detected: drainAnomaly,
      evidence: drainAnomaly ? `${totalSpent.toFixed(2)} ETH spent of ${vaultBalance} ETH balance (${((totalSpent/vaultBalance)*100).toFixed(0)}%)` : undefined,
    });

    // Calculate risk score
    const detectedSignals = signals.filter(s => s.detected);
    const riskScore = Math.min(100, detectedSignals.reduce((sum, s) => sum + s.weight, 0));
    
    const riskLevel: AnomalyResult['riskLevel'] =
      riskScore >= 75 ? 'CRITICAL' :
      riskScore >= 50 ? 'HIGH' :
      riskScore >= 25 ? 'MEDIUM' : 'LOW';

    const recommendation =
      riskLevel === 'CRITICAL' ? 'FREEZE vault immediately. Require multi-agent review before any further transactions.' :
      riskLevel === 'HIGH' ? 'Escalate to time-lock mode. All transactions require 24h delay for review.' :
      riskLevel === 'MEDIUM' ? 'Reduce spending cap by 50% and enable enhanced audit logging.' :
      'No action required. Continue normal monitoring.';

    const result: AnomalyResult = {
      vaultId,
      riskScore,
      riskLevel,
      signals,
      recommendation,
      analyzedAt: new Date().toISOString(),
    };

    return res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: msg });
  }
});

/**
 * POST /api/anomaly/simulate
 * Simulate a known attack pattern to demonstrate detection.
 */
anomalyRouter.post('/simulate', async (req, res) => {
  const { attackType = 'patient_drain' } = req.body as { attackType?: string };

  const scenarios: Record<string, {
    description: string;
    history: Array<{ action: string; details: Record<string, unknown>; timestamp: string }>;
    spendingCapEth: number;
    vaultBalanceEth: number;
  }> = {
    patient_drain: {
      description: 'Patient attacker spacing out transactions to stay under rate limits',
      history: Array.from({ length: 8 }, (_, i) => ({
        action: 'transfer',
        details: { amount: 4.8, to: '0xAttacker000', token: 'ETH' },
        timestamp: new Date(Date.now() - (8 - i) * 3605000).toISOString(), // ~1hr apart
      })),
      spendingCapEth: 5,
      vaultBalanceEth: 50,
    },
    burst_drain: {
      description: 'Rapid burst of transactions just below cap',
      history: Array.from({ length: 6 }, (_, i) => ({
        action: 'transfer',
        details: { amount: 4.9 + (i % 2) * 0.05, to: '0xAttacker000', token: 'ETH' },
        timestamp: new Date(Date.now() - (6 - i) * 300000).toISOString(), // 5min apart
      })),
      spendingCapEth: 5,
      vaultBalanceEth: 30,
    },
    normal_activity: {
      description: 'Normal agent spending across multiple recipients',
      history: [
        { action: 'transfer', details: { amount: 0.5, to: '0xService001', token: 'ETH' }, timestamp: new Date(Date.now() - 14400000).toISOString() },
        { action: 'transfer', details: { amount: 1.2, to: '0xService002', token: 'ETH' }, timestamp: new Date(Date.now() - 7200000).toISOString() },
        { action: 'transfer', details: { amount: 0.3, to: '0xService003', token: 'ETH' }, timestamp: new Date(Date.now() - 3600000).toISOString() },
      ],
      spendingCapEth: 5,
      vaultBalanceEth: 20,
    },
  };

  const scenario = scenarios[attackType] || scenarios['patient_drain'];

  // Run the analyzer on the simulated history
  const analyzeBody = {
    vaultId: 'simulate-' + attackType,
    history: scenario.history,
    spendingCapEth: scenario.spendingCapEth,
    vaultBalanceEth: scenario.vaultBalanceEth,
    windowHours: 24,
  };

  // Inline analysis (reuse same logic)
  const transfers = scenario.history.filter(e => e.action === 'transfer');
  const amounts = transfers.map(e => parseFloat(String(e.details?.amount ?? 0)));
  const timestamps = transfers.map(e => new Date(e.timestamp).getTime());

  const signals = [];

  const transfersPerHour = transfers.length / 24;
  const velocityAnomaly = transfersPerHour > 5;
  signals.push({ type: 'velocity_spike', detected: velocityAnomaly, weight: 30,
    evidence: `${transfersPerHour.toFixed(2)} tx/hr` });

  const justBelowCap = amounts.filter(a => a >= scenario.spendingCapEth * 0.8 && a <= scenario.spendingCapEth).length;
  const clusteringAnomaly = justBelowCap >= 3;
  signals.push({ type: 'cap_clustering', detected: clusteringAnomaly, weight: 35,
    evidence: `${justBelowCap} tx in 80-100% cap range` });

  const gaps = timestamps.slice(1).map((t, i) => t - timestamps[i]);
  const avgGap = gaps.length > 0 ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
  const stdDev = gaps.length > 1
    ? Math.sqrt(gaps.map(g => Math.pow(g - avgGap, 2)).reduce((a, b) => a + b, 0) / gaps.length)
    : 0;
  const regularityAnomaly = gaps.length >= 3 && stdDev / (avgGap || 1) < 0.15;
  signals.push({ type: 'temporal_regularity', detected: regularityAnomaly, weight: 25,
    evidence: `ratio: ${(stdDev / (avgGap || 1)).toFixed(3)}` });

  const destinations = transfers.map(e => String(e.details?.to ?? 'unknown'));
  const destCounts: Record<string, number> = {};
  destinations.forEach(d => { destCounts[d] = (destCounts[d] || 0) + 1; });
  const maxDestCount = Math.max(...Object.values(destCounts), 0);
  const singleDestAnomaly = transfers.length >= 3 && maxDestCount / transfers.length > 0.7;
  signals.push({ type: 'destination_concentration', detected: singleDestAnomaly, weight: 20,
    evidence: `${transfers.length > 0 ? ((maxDestCount / transfers.length) * 100).toFixed(0) : 0}% to single dest` });

  const totalSpent = amounts.reduce((a, b) => a + b, 0);
  const drainAnomaly = scenario.vaultBalanceEth > 0 && totalSpent / scenario.vaultBalanceEth > 0.8;
  signals.push({ type: 'cumulative_drain', detected: drainAnomaly, weight: 40,
    evidence: `${totalSpent.toFixed(2)} of ${scenario.vaultBalanceEth} ETH` });

  const detectedSignals = signals.filter(s => s.detected);
  const riskScore = Math.min(100, detectedSignals.reduce((sum, s) => sum + s.weight, 0));
  const riskLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';

  return res.json({
    attackType,
    scenario: scenario.description,
    transactionCount: transfers.length,
    totalSpentEth: totalSpent,
    analysis: { riskScore, riskLevel, signals, detectedSignals: detectedSignals.length },
    simulatedAt: new Date().toISOString(),
  });
});

export default anomalyRouter;
