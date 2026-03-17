import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  mongodbUri: process.env.MONGODB_URI || '',
  litApiKey: process.env.LIT_API_KEY || '',
  nodeEnv: process.env.NODE_ENV || 'development',
  version: '1.0.0',
  project: 'agent-vault',
} as const;

export function validateConfig(): string[] {
  const warnings: string[] = [];
  if (!config.mongodbUri) {
    warnings.push('MONGODB_URI not set — running without database');
  }
  if (!config.litApiKey) {
    warnings.push('LIT_API_KEY not set — Lit Protocol features disabled');
  }
  return warnings;
}
