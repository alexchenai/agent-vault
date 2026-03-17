/**
 * vault/audit-log.ts — MongoDB Audit Trail with in-memory fallback
 *
 * Every action the agent takes is logged immutably:
 * deposits, transfers, swaps, policy changes, proof generations.
 * Falls back to in-memory store when MongoDB is not available,
 * ensuring the demo works end-to-end in all environments.
 */

import { MongoClient, Db, ObjectId } from 'mongodb';

let client: MongoClient | null = null;
let db: Db | null = null;

// In-memory fallback store keyed by vaultId
const memoryStore: AuditEntry[] = [];
// In-memory vault balances: vaultId -> amount (in ETH units as string)
const vaultBalances: Map<string, number> = new Map();
// In-memory policies store
const vaultPolicies: Map<string, PolicyDoc[]> = new Map();

/** Connect to MongoDB */
export async function connectDb(uri: string): Promise<Db> {
  client = new MongoClient(uri);
  await client.connect();
  db = client.db('agent_vault');
  const col = db.collection('audit_log');
  await col.createIndex({ vaultId: 1, timestamp: -1 });
  await col.createIndex({ action: 1 });
  const policiesCol = db.collection('policies');
  await policiesCol.createIndex({ vaultId: 1, enabled: 1 });
  const balancesCol = db.collection('balances');
  await balancesCol.createIndex({ vaultId: 1 }, { unique: true });
  console.log('[audit-log] MongoDB indexes created');
  return db;
}

/** Get database instance */
export function getDb(): Db | null {
  return db;
}

/** Whether we have a live DB connection */
export function isConnected(): boolean {
  return db !== null;
}

/** Audit log entry structure */
export interface AuditEntry {
  _id?: string;
  vaultId: string;
  action: 'deposit' | 'transfer' | 'swap' | 'policy_change' | 'proof_generated' | 'policy_violation';
  details: Record<string, unknown>;
  timestamp: Date;
  txHash?: string;
  policyResults?: PolicyCheckResult[];
}

/** Result of a policy evaluation */
export interface PolicyCheckResult {
  policyId: string;
  policyType: string;
  passed: boolean;
  reason?: string;
}

/** Policy document stored in DB */
export interface PolicyDoc {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  _id?: any;
  vaultId: string;
  type: 'spending-cap' | 'whitelist-only' | 'rate-limiter' | 'time-lock' | 'multi-agent-approval';
  config: Record<string, unknown>;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Log an action to the audit trail
 */
export async function logAction(entry: Omit<AuditEntry, 'timestamp'>): Promise<string | null> {
  const doc: AuditEntry = { ...entry, timestamp: new Date() };

  if (db) {
    const col = db.collection('audit_log');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = await col.insertOne(doc as any);
    return result.insertedId.toString();
  }

  // In-memory fallback
  const id = new ObjectId().toString();
  doc._id = id;
  memoryStore.push(doc);
  // Keep max 1000 entries in memory
  if (memoryStore.length > 1000) {
    memoryStore.splice(0, memoryStore.length - 1000);
  }
  return id;
}

/**
 * Query audit trail for a specific vault
 */
export async function getAuditTrail(
  vaultId: string,
  limit: number = 50
): Promise<AuditEntry[]> {
  if (db) {
    const col = db.collection('audit_log');
    const results = await col
      .find({ vaultId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
    return results as unknown as AuditEntry[];
  }

  // In-memory fallback
  return memoryStore
    .filter((e) => e.vaultId === vaultId)
    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
    .slice(0, limit);
}

/**
 * Get or initialize vault balance
 */
export async function getVaultBalance(vaultId: string): Promise<number> {
  if (db) {
    const col = db.collection('balances');
    const doc = await col.findOne({ vaultId });
    return (doc?.balance as number) ?? 0;
  }
  return vaultBalances.get(vaultId) ?? 0;
}

/**
 * Update vault balance (add delta, can be negative for withdrawals)
 */
export async function updateVaultBalance(vaultId: string, delta: number): Promise<number> {
  if (db) {
    const col = db.collection('balances');
    const result = await col.findOneAndUpdate(
      { vaultId },
      {
        $inc: { balance: delta },
        $set: { updatedAt: new Date() },
        $setOnInsert: { createdAt: new Date() },
      },
      { upsert: true, returnDocument: 'after' }
    );
    return (result?.balance as number) ?? delta;
  }
  const current = vaultBalances.get(vaultId) ?? 0;
  const newBalance = Math.max(0, current + delta);
  vaultBalances.set(vaultId, newBalance);
  return newBalance;
}

/**
 * Save a policy for a vault
 */
export async function savePolicy(policy: Omit<PolicyDoc, '_id' | 'createdAt' | 'updatedAt'>): Promise<string> {
  const now = new Date();
  const doc: PolicyDoc = { ...policy, createdAt: now, updatedAt: now };

  if (db) {
    const col = db.collection('policies');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = await col.insertOne(doc as any);
    return result.insertedId.toString();
  }

  const id = new ObjectId().toString();
  doc._id = id;
  const existing = vaultPolicies.get(policy.vaultId) ?? [];
  existing.push(doc);
  vaultPolicies.set(policy.vaultId, existing);
  return id;
}

/**
 * Get all policies for a vault
 */
export async function getPolicies(vaultId: string): Promise<PolicyDoc[]> {
  if (db) {
    const col = db.collection('policies');
    return col.find({ vaultId, enabled: true }).toArray() as unknown as PolicyDoc[];
  }
  return (vaultPolicies.get(vaultId) ?? []).filter((p) => p.enabled);
}

/**
 * Get all policies (including disabled) for a vault
 */
export async function getAllPolicies(vaultId: string): Promise<PolicyDoc[]> {
  if (db) {
    const col = db.collection('policies');
    return col.find({ vaultId }).toArray() as unknown as PolicyDoc[];
  }
  return vaultPolicies.get(vaultId) ?? [];
}

/**
 * Update a policy
 */
export async function updatePolicy(
  vaultId: string,
  policyId: string,
  updates: Partial<PolicyDoc>
): Promise<boolean> {
  const now = new Date();

  if (db) {
    const col = db.collection('policies');
    try {
      const oid = new ObjectId(policyId);
      const result = await col.updateOne(
        { _id: oid, vaultId },
        { $set: { ...updates, updatedAt: now } }
      );
      return result.matchedCount > 0;
    } catch {
      // policyId is not a valid ObjectId — not found
      return false;
    }
  }

  const policies = vaultPolicies.get(vaultId) ?? [];
  const idx = policies.findIndex((p) => p._id === policyId);
  if (idx === -1) return false;
  policies[idx] = { ...policies[idx], ...updates, updatedAt: now };
  return true;
}

/**
 * Get 24h outflow total for spending cap check
 */
export async function getRecentOutflow(vaultId: string, windowMs: number = 86400000): Promise<number> {
  const since = new Date(Date.now() - windowMs);

  if (db) {
    const col = db.collection('audit_log');
    const pipeline = [
      {
        $match: {
          vaultId,
          action: { $in: ['transfer', 'swap'] },
          timestamp: { $gte: since },
        },
      },
      {
        $group: {
          _id: null,
          total: { $sum: { $toDouble: '$details.amount' } },
        },
      },
    ];
    const result = await col.aggregate(pipeline).toArray();
    return (result[0]?.total as number) ?? 0;
  }

  return memoryStore
    .filter(
      (e) =>
        e.vaultId === vaultId &&
        (e.action === 'transfer' || e.action === 'swap') &&
        e.timestamp >= since
    )
    .reduce((sum, e) => sum + (Number(e.details.amount) || 0), 0);
}

/** Close database connection */
export async function closeDb(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    db = null;
  }
}
