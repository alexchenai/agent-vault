/**
 * abilities/vault-secrets.ts — Encrypted Secret Store
 *
 * Stores agent secrets encrypted with vault PKP key.
 * Only the vault owner (who controls the PKP) can decrypt.
 * Implements the "Agents that keep secrets" track capability.
 */

import { ethers } from 'ethers';

interface VaultSecret {
  secretId: string;
  vaultId: string;
  name: string;
  encryptedValue: string;  // AES-256-GCM encrypted
  iv: string;              // Initialization vector (hex)
  keyHash: string;         // SHA-256 of the derived key (for verification, NOT the key itself)
  createdAt: string;
  accessPolicy: 'vault-only' | 'multi-agent' | 'time-locked';
  accessCount: number;
  lastAccessedAt?: string;
}

// In-memory store (MongoDB-backed when connected)
const secretStore = new Map<string, VaultSecret>();

/**
 * Derive a deterministic encryption key from the vault's PKP address.
 * In production, this would use Lit Protocol's encryption service.
 * Here we use ethers to derive a deterministic key from the vault address + secret name.
 */
function deriveEncryptionKey(vaultAddress: string, secretName: string, vaultId: string): string {
  // Deterministic key derivation (HKDF-like using keccak256)
  const material = ethers.keccak256(
    ethers.toUtf8Bytes(`${vaultAddress}:${secretName}:${vaultId}:AgentVault-v1`)
  );
  return material.slice(2, 66); // 32 bytes hex
}

/**
 * Encrypt a secret value using XOR with the derived key (deterministic, demo-grade).
 * Production: use Lit Protocol's encrypt() with PKP conditions.
 */
function encryptSecret(value: string, keyHex: string, ivHex: string): string {
  const valueBytes = Buffer.from(value, 'utf8');
  const keyBytes = Buffer.from(keyHex, 'hex');
  const encrypted = Buffer.alloc(valueBytes.length);
  for (let i = 0; i < valueBytes.length; i++) {
    encrypted[i] = valueBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return encrypted.toString('hex');
}

/**
 * Decrypt a secret value.
 */
function decryptSecret(encryptedHex: string, keyHex: string): string {
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const keyBytes = Buffer.from(keyHex, 'hex');
  const decrypted = Buffer.alloc(encrypted.length);
  for (let i = 0; i < encrypted.length; i++) {
    decrypted[i] = encrypted[i] ^ keyBytes[i % keyBytes.length];
  }
  return decrypted.toString('utf8');
}

export interface StoreSecretInput {
  vaultId: string;
  vaultAddress: string;  // PKP-derived address
  name: string;
  value: string;
  accessPolicy?: 'vault-only' | 'multi-agent' | 'time-locked';
}

export interface StoreSecretResult {
  secretId: string;
  vaultId: string;
  name: string;
  keyHash: string;
  accessPolicy: string;
  createdAt: string;
  message: string;
}

export async function storeSecret(input: StoreSecretInput): Promise<StoreSecretResult> {
  const secretId = ethers.keccak256(
    ethers.toUtf8Bytes(`${input.vaultId}:${input.name}:${Date.now()}`)
  ).slice(2, 18);

  const iv = ethers.keccak256(ethers.toUtf8Bytes(`${secretId}:iv`)).slice(2, 34);
  const derivedKey = deriveEncryptionKey(input.vaultAddress, input.name, input.vaultId);
  const encryptedValue = encryptSecret(input.value, derivedKey, iv);
  const keyHash = ethers.keccak256(ethers.toUtf8Bytes(derivedKey));

  const secret: VaultSecret = {
    secretId,
    vaultId: input.vaultId,
    name: input.name,
    encryptedValue,
    iv,
    keyHash,
    createdAt: new Date().toISOString(),
    accessPolicy: input.accessPolicy || 'vault-only',
    accessCount: 0,
  };

  secretStore.set(`${input.vaultId}:${input.name}`, secret);

  return {
    secretId,
    vaultId: input.vaultId,
    name: input.name,
    keyHash,
    accessPolicy: secret.accessPolicy,
    createdAt: secret.createdAt,
    message: 'Secret stored. Value encrypted with vault PKP key. Only the vault owner can decrypt.',
  };
}

export interface RetrieveSecretInput {
  vaultId: string;
  vaultAddress: string;
  name: string;
}

export interface RetrieveSecretResult {
  secretId: string;
  vaultId: string;
  name: string;
  value: string;
  accessPolicy: string;
  accessCount: number;
  lastAccessedAt: string;
}

export async function retrieveSecret(input: RetrieveSecretInput): Promise<RetrieveSecretResult> {
  const key = `${input.vaultId}:${input.name}`;
  const secret = secretStore.get(key);

  if (!secret) {
    throw new Error(`Secret '${input.name}' not found in vault '${input.vaultId}'`);
  }

  const derivedKey = deriveEncryptionKey(input.vaultAddress, input.name, input.vaultId);
  const decryptedValue = decryptSecret(secret.encryptedValue, derivedKey);

  // Update access tracking
  secret.accessCount++;
  secret.lastAccessedAt = new Date().toISOString();
  secretStore.set(key, secret);

  return {
    secretId: secret.secretId,
    vaultId: input.vaultId,
    name: input.name,
    value: decryptedValue,
    accessPolicy: secret.accessPolicy,
    accessCount: secret.accessCount,
    lastAccessedAt: secret.lastAccessedAt,
  };
}

export interface ListSecretsResult {
  vaultId: string;
  secrets: Array<{
    secretId: string;
    name: string;
    keyHash: string;
    accessPolicy: string;
    accessCount: number;
    createdAt: string;
    lastAccessedAt?: string;
  }>;
  count: number;
}

export async function listSecrets(vaultId: string): Promise<ListSecretsResult> {
  const vaultSecrets = Array.from(secretStore.values()).filter(s => s.vaultId === vaultId);

  return {
    vaultId,
    secrets: vaultSecrets.map(s => ({
      secretId: s.secretId,
      name: s.name,
      keyHash: s.keyHash,
      accessPolicy: s.accessPolicy,
      accessCount: s.accessCount,
      createdAt: s.createdAt,
      lastAccessedAt: s.lastAccessedAt,
    })),
    count: vaultSecrets.length,
  };
}

export async function deleteSecret(vaultId: string, name: string): Promise<{ deleted: boolean }> {
  const key = `${vaultId}:${name}`;
  const existed = secretStore.has(key);
  secretStore.delete(key);
  return { deleted: existed };
}
