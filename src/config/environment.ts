import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

/**
 * Environment variables validation schema
 * Ensures all required configuration is present and valid
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3001'),
  
  // JWT Configuration
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('7d'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('30d'),
  
  // Master Database (for user management)
  MASTER_DATABASE_URL: z.string().url(),
  
  // Redis Configuration (for sessions and caching)
  REDIS_URL: z.string().url().optional(),
  
  // N8N Integration
  N8N_WEBHOOK_URL: z.string().url(),
  N8N_API_KEY: z.string().optional(),
  
  // Anthropic API
  ANTHROPIC_API_KEY: z.string(),
  
  // File Storage
  STORAGE_PATH: z.string().default('./storage'),
  MAX_FILE_SIZE: z.string().transform(Number).default('10485760'), // 10MB
  
  // CORS
  ALLOWED_ORIGINS: z.string().default('http://localhost:3000'),
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('900000'), // 15 minutes
  RATE_LIMIT_MAX: z.string().transform(Number).default('100'),
  
  // Database Export/Import
  EXPORT_ENCRYPTION_KEY: z.string().min(32),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
});

const env = envSchema.parse(process.env);

/**
 * Application configuration object
 * Centralized configuration management
 */
export const config = {
  node: {
    env: env.NODE_ENV,
  },
  server: {
    port: env.PORT,
    host: '0.0.0.0',
  },
  jwt: {
    secret: env.JWT_SECRET,
    expiresIn: env.JWT_EXPIRES_IN,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
  },
  database: {
    masterUrl: env.MASTER_DATABASE_URL,
  },
  redis: {
    url: env.REDIS_URL,
  },
  n8n: {
    webhookUrl: env.N8N_WEBHOOK_URL,
    apiKey: env.N8N_API_KEY,
  },
  anthropic: {
    apiKey: env.ANTHROPIC_API_KEY,
  },
  storage: {
    path: env.STORAGE_PATH,
    maxFileSize: env.MAX_FILE_SIZE,
  },
  cors: {
    origin: env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()),
  },
  rateLimit: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX,
  },
  export: {
    encryptionKey: env.EXPORT_ENCRYPTION_KEY,
  },
  logging: {
    level: env.LOG_LEVEL,
  },
} as const;

// Validate configuration on startup
logger.info('Configuration loaded successfully');
logger.debug('Configuration:', { 
  ...config, 
  jwt: { ...config.jwt, secret: '[REDACTED]' },
  export: { ...config.export, encryptionKey: '[REDACTED]' }
});