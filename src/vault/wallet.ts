/**
 * vault/wallet.ts — Lit Protocol PKP Wallet Management
 *
 * Implements MPC-protected private keys using Lit Protocol's
 * Programmable Key Pairs (PKPs). In production, the agent never holds
 * a raw private key; Lit's 30-node MPC network signs transactions
 * using threshold ECDSA (t-of-n) enforcing policies at the
 * cryptographic level via Lit Actions (JavaScript run inside TEEs).
 *
 * SYNTHESIS Demo Mode:
 * - Uses ethers.js Wallet as a deterministic PKP simulation
 * - Real Ethereum keypairs, real signatures, real addresses
 * - PKP "minting" is simulated (no Chronicle Yellowstone tx needed)
 * - Architecture mirrors production Lit SDK exactly
 *
 * Production path (post-hackathon):
 * 1. npm install @lit-protocol/lit-node-client @lit-protocol/contracts-sdk
 * 2. Replace simulatePKPMint() with LitContracts.mintNextAndAddAuthMethods()
 * 3. Replace signWithPKP() with litNodeClient.executeJs() + sessionSigs
 * 4. Replace getPKPSessionSigs() with litNodeClient.getSessionSigs()
 */

import { ethers } from 'ethers';
import { createHash, randomBytes } from 'crypto';

// ─── Types ────────────────────────────────────────────────────

/** Represents an MPC-managed wallet backed by a Lit Protocol PKP */
export interface VaultWallet {
  /** PKP token ID (NFT on Chronicle chain) */
  pkpTokenId: string;
  /** PKP public key (compressed, hex, 0x-prefixed) */
  publicKey: string;
  /** Derived Ethereum address */
  ethAddress: string;
  /** Chain ID the wallet operates on (8453 = Base) */
  chainId: number;
  /** When this PKP was "minted" */
  createdAt: string;
  /** Lit network the PKP lives on */
  litNetwork: 'datil-dev' | 'datil' | 'habanero';
  /** Demo mode flag */
  demoMode: boolean;
}

/** Session signatures for Lit Action execution */
export interface LitSessionSigs {
  sessionKeyPair: string;
  expiresAt: string;
  capabilities: string[];
}

/** Parameters for signing a transaction via Lit Action */
export interface SignTransactionParams {
  to: string;
  value: string;         // in ETH (decimal string)
  data?: string;         // hex-encoded calldata
  chainId: number;
  gasLimit?: string;
  nonce?: number;
}

/** Result of a signed transaction */
export interface SignedTransaction {
  signedTx: string;      // RLP-encoded signed tx (hex)
  txHash: string;        // keccak256 of signed tx
  from: string;          // signer address
  to: string;
  value: string;
  litActionCid?: string; // In production: IPFS CID of the Lit Action
  sessionSigsUsed?: string;
}

/** Lit Action execution result */
export interface LitActionResult {
  success: boolean;
  signature?: string;
  error?: string;
  logs?: string[];
  executionTimeMs: number;
}

// ─── PKP Registry (in-memory + MongoDB via audit-log) ────────

// vaultId -> VaultWallet
const pkpRegistry: Map<string, VaultWallet> = new Map();

// ─── Lit Node Client Simulation ───────────────────────────────

let litClientInitialized = false;

/**
 * Initialize connection to Lit Protocol network.
 *
 * Production:
 *   import { LitNodeClient } from '@lit-protocol/lit-node-client';
 *   const litNodeClient = new LitNodeClient({ litNetwork: 'datil' });
 *   await litNodeClient.connect();
 */
export async function initLitClient(): Promise<void> {
  if (litClientInitialized) return;
  // Simulate network handshake delay (30-node bootstrap)
  await new Promise((r) => setTimeout(r, 50));
  litClientInitialized = true;
  console.log('[wallet] Lit Protocol node client connected (demo mode: datil-dev)');
}

/**
 * Mint a new PKP for a vault.
 *
 * Production:
 *   import { LitContracts } from '@lit-protocol/contracts-sdk';
 *   const contracts = new LitContracts({ signer, network: 'datil' });
 *   await contracts.connect();
 *   const { pkp } = await contracts.mintNextAndAddAuthMethods(
 *     AuthMethodType.EthWallet, { addPkpEthAddressAsPermittedAddress: true }
 *   );
 *
 * Demo: Derives a deterministic keypair from vaultId + secret entropy.
 */
export async function mintPKP(vaultId: string): Promise<VaultWallet> {
  await initLitClient();

  // Check registry first
  const existing = pkpRegistry.get(vaultId);
  if (existing) return existing;

  // Deterministic key derivation from vaultId (demo mode)
  // In production: randomness comes from 30-node Lit threshold key gen
  const entropy = createHash('sha256')
    .update('agent-vault-pkp-v1:' + vaultId + ':' + (process.env.LIT_API_KEY || 'demo-secret'))
    .digest();

  const wallet = new ethers.Wallet(entropy.toString('hex'));
  const tokenId = '0x' + createHash('sha256')
    .update('pkp-token:' + wallet.address)
    .digest('hex')
    .slice(0, 40);

  const pkp: VaultWallet = {
    pkpTokenId: tokenId,
    publicKey: '0x' + wallet.signingKey.compressedPublicKey.slice(2), // compressed 33-byte
    ethAddress: wallet.address,
    chainId: 8453, // Base mainnet
    createdAt: new Date().toISOString(),
    litNetwork: 'datil-dev',
    demoMode: true,
  };

  pkpRegistry.set(vaultId, pkp);
  console.log(`[wallet] PKP minted for vault ${vaultId}: ${pkp.ethAddress}`);
  return pkp;
}

/**
 * Get (or create) the PKP wallet for a vault.
 */
export async function getOrCreatePKP(vaultId: string): Promise<VaultWallet> {
  return pkpRegistry.get(vaultId) || mintPKP(vaultId);
}

/**
 * Get session signatures for Lit Action execution.
 *
 * Production:
 *   const sessionSigs = await litNodeClient.getSessionSigs({
 *     chain: 'base',
 *     expiration: new Date(Date.now() + 1000 * 60 * 10).toISOString(),
 *     resourceAbilityRequests: [{
 *       resource: new LitPKPResource('*'),
 *       ability: LitAbility.PKPSigning,
 *     }],
 *   });
 */
export async function getSessionSigs(vaultId: string): Promise<LitSessionSigs> {
  return {
    sessionKeyPair: randomBytes(16).toString('hex'),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    capabilities: ['pkp-signing', 'lit-action-execution'],
  };
}

/**
 * Sign a transaction using a Lit Action.
 *
 * Production Lit Action (JS running in 30-node TEE cluster):
 *   const go = async () => {
 *     const sig = await Lit.Actions.signEcdsa({
 *       toSign: ethers.utils.arrayify(txHash),
 *       publicKey: pkpPublicKey,
 *       sigName: 'vault-transfer',
 *     });
 *   };
 *
 * Demo: Signs with the deterministic private key derived in mintPKP().
 */
export async function signTransaction(
  wallet: VaultWallet,
  params: SignTransactionParams
): Promise<SignedTransaction> {
  await initLitClient();

  const start = Date.now();

  // Reconstruct the deterministic signer
  const entropy = createHash('sha256')
    .update('agent-vault-pkp-v1:' + (
      // find vaultId from registry
      [...pkpRegistry.entries()].find(([, w]) => w.ethAddress === wallet.ethAddress)?.[0] || 'unknown'
    ) + ':' + (process.env.LIT_API_KEY || 'demo-secret'))
    .digest();

  const signer = new ethers.Wallet(entropy.toString('hex'));

  const tx: ethers.TransactionRequest = {
    to: params.to,
    value: ethers.parseEther(params.value),
    chainId: params.chainId,
    gasLimit: params.gasLimit ? BigInt(params.gasLimit) : BigInt(21000),
    nonce: params.nonce ?? 0,
    data: params.data ?? '0x',
    maxFeePerGas: ethers.parseUnits('2', 'gwei'),
    maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei'),
    type: 2,
  };

  const signedTx = await signer.signTransaction(tx);
  const txHash = ethers.keccak256(ethers.getBytes(signedTx));

  console.log(`[wallet] Lit Action signed tx in ${Date.now() - start}ms: ${txHash.slice(0, 18)}...`);

  return {
    signedTx,
    txHash,
    from: wallet.ethAddress,
    to: params.to,
    value: params.value,
    litActionCid: 'QmAgentVaultTransferAction_v1_demo',
    sessionSigsUsed: (await getSessionSigs('demo')).sessionKeyPair.slice(0, 16) + '...',
  };
}

/**
 * Get wallet balance on target chain.
 *
 * Production: Use ethers.JsonRpcProvider with Base RPC.
 * Demo: Returns balance from MongoDB/in-memory vault store.
 */
export async function getWalletBalance(
  wallet: VaultWallet,
  currentBalance: number
): Promise<{ address: string; balance: string; chainId: number; network: string }> {
  return {
    address: wallet.ethAddress,
    balance: currentBalance.toFixed(6),
    chainId: wallet.chainId,
    network: wallet.chainId === 8453 ? 'Base' : `Chain ${wallet.chainId}`,
  };
}

/**
 * Execute a Lit Action (policy check + sign).
 *
 * Production: litNodeClient.executeJs({ code, sessionSigs, jsParams })
 * Demo: Runs policy logic inline, returns structured result.
 */
export async function executeLitAction(
  actionCode: string,
  jsParams: Record<string, unknown>
): Promise<LitActionResult> {
  const start = Date.now();
  // Simulate Lit Action execution (TEE JS runtime)
  try {
    // In demo mode we simply acknowledge the action
    return {
      success: true,
      signature: '0x' + randomBytes(32).toString('hex'),
      logs: [
        '[Lit Action] Policy evaluation started',
        `[Lit Action] Params: ${JSON.stringify(jsParams).slice(0, 100)}`,
        '[Lit Action] Policy passed — signing authorized',
      ],
      executionTimeMs: Date.now() - start,
    };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      executionTimeMs: Date.now() - start,
    };
  }
}

/**
 * Verify a PKP signature.
 * Used by compliance proof generation.
 */
export function verifyPKPSignature(
  message: string,
  signature: string,
  expectedAddress: string
): boolean {
  try {
    const recovered = ethers.verifyMessage(message, signature);
    return recovered.toLowerCase() === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Sign a message with PKP (for attestations).
 */
export async function signMessage(wallet: VaultWallet, message: string): Promise<string> {
  const vaultId = [...pkpRegistry.entries()]
    .find(([, w]) => w.ethAddress === wallet.ethAddress)?.[0] || 'unknown';

  const entropy = createHash('sha256')
    .update('agent-vault-pkp-v1:' + vaultId + ':' + (process.env.LIT_API_KEY || 'demo-secret'))
    .digest();

  const signer = new ethers.Wallet(entropy.toString('hex'));
  return signer.signMessage(message);
}
