import { z } from 'zod';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Environment configuration schema with validation
 * Ensures all required environment variables are present and valid
 */
const envSchema = z.object({
  // Server Configuration
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).refine(n => n > 0 && n < 65536, 'Invalid port').default('3001'),
  HOST: z.string().default('localhost'),
  
  // Database Configuration
  DB_HOST: z.string().min(1, 'Database host is required'),
  DB_PORT: z.string().transform(Number).default('5432'),
  DB_NAME: z.string().min(1, 'Database name is required'),
  DB_USER: z.string().min(1, 'Database user is required'),
  DB_PASSWORD: z.string().min(1, 'Database password is required'),
  DB_SSL: z.string().transform(val => val === 'true').default('false'),
  DB_POOL_MIN: z.string().transform(Number).default('2'),
  DB_POOL_MAX: z.string().transform(Number).default('10'),
  
  // Master Database (for multi-tenant architecture)
  MASTER_DB_HOST: z.string().optional(),
  MASTER_DB_PORT: z.string().transform(Number).optional(),
  MASTER_DB_NAME: z.string().optional(),
  MASTER_DB_USER: z.string().optional(),
  MASTER_DB_PASSWORD: z.string().optional(),
  
  // JWT Configuration
  JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT refresh secret must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('1h'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  
  // Security
  BCRYPT_ROUNDS: z.string().transform(Number).default('12'),
  ENCRYPTION_KEY: z.string().min(32, 'Encryption key must be at least 32 characters'),
  
  // Redis Configuration
  REDIS_URL: z.string().url().optional(),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().transform(Number).default('6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).default('0'),
  
  // Claude AI Configuration
  CLAUDE_API_KEY: z.string().min(1, 'Claude API key is required'),
  CLAUDE_API_URL: z.string().url().default('https://api.anthropic.com'),
  CLAUDE_MODEL: z.string().default('claude-3-sonnet-20240229'),
  CLAUDE_MAX_TOKENS: z.string().transform(Number).default('4096'),
  CLAUDE_TEMPERATURE: z.string().transform(Number).optional(),
  
  // File Storage
  STORAGE_TYPE: z.enum(['local', 's3', 'gcs']).default('local'),
  STORAGE_PATH: z.string().default('./uploads'),
  AWS_S3_BUCKET: z.string().optional(),
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_REGION: z.string().optional(),
  
  // Email Configuration
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.string().transform(Number).optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().email().optional(),
  
  // CORS Configuration
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  CORS_CREDENTIALS: z.string().transform(val => val === 'true').default('true'),
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('900000'), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default('100'),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  LOG_FORMAT: z.enum(['json', 'combined', 'simple']).default('json'),
  
  // Monitoring & Health
  HEALTH_CHECK_INTERVAL: z.string().transform(Number).default('30000'), // 30 seconds
  PROMETHEUS_ENABLED: z.string().transform(val => val === 'true').default('false'),
  PROMETHEUS_PORT: z.string().transform(Number).default('9090'),
  
  // WebSocket Configuration
  WS_ENABLED: z.string().transform(val => val === 'true').default('true'),
  WS_HEARTBEAT_INTERVAL: z.string().transform(Number).default('30000'),
  
  // Feature Flags
  ENABLE_SWAGGER: z.string().transform(val => val === 'true').default('true'),
  ENABLE_WEBHOOKS: z.string().transform(val => val === 'true').default('true'),
  ENABLE_ANALYTICS: z.string().transform(val => val === 'true').default('true'),
  ENABLE_AUDIT_LOGS: z.string().transform(val => val === 'true').default('true'),
  
  // Development & Testing
  MOCK_CLAUDE_API: z.string().transform(val => val === 'true').default('false'),
  DISABLE_AUTH: z.string().transform(val => val === 'true').default('false'),
  SEED_DATABASE: z.string().transform(val => val === 'true').default('false'),
});

// Validate environment variables
const parseResult = envSchema.safeParse(process.env);

if (!parseResult.success) {
  console.error('❌ Invalid environment configuration:');
  parseResult.error.issues.forEach(issue => {
    console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
  });
  process.exit(1);
}

export const config = parseResult.data;

/**
 * Database connection configuration
 */
export const databaseConfig = {
  host: config.DB_HOST,
  port: config.DB_PORT,
  database: config.DB_NAME,
  username: config.DB_USER,
  password: config.DB_PASSWORD,
  ssl: config.DB_SSL,
  pool: {
    min: config.DB_POOL_MIN,
    max: config.DB_POOL_MAX,
  },
};

/**
 * Master database configuration (for multi-tenant)
 */
export const masterDatabaseConfig = {
  host: config.MASTER_DB_HOST || config.DB_HOST,
  port: config.MASTER_DB_PORT || config.DB_PORT,
  database: config.MASTER_DB_NAME || 'claude_memory_master',
  username: config.MASTER_DB_USER || config.DB_USER,
  password: config.MASTER_DB_PASSWORD || config.DB_PASSWORD,
  ssl: config.DB_SSL,
  pool: {
    min: config.DB_POOL_MIN,
    max: config.DB_POOL_MAX,
  },
};

/**
 * Redis configuration
 */
export const redisConfig = {
  url: config.REDIS_URL,
  host: config.REDIS_HOST,
  port: config.REDIS_PORT,
  password: config.REDIS_PASSWORD,
  db: config.REDIS_DB,
};

/**
 * JWT configuration
 */
export const jwtConfig = {
  secret: config.JWT_SECRET,
  refreshSecret: config.JWT_REFRESH_SECRET,
  expiresIn: config.JWT_EXPIRES_IN,
  refreshExpiresIn: config.JWT_REFRESH_EXPIRES_IN,
};

/**
 * Claude AI configuration
 */
export const claudeConfig = {
  apiKey: config.CLAUDE_API_KEY,
  apiUrl: config.CLAUDE_API_URL,
  model: config.CLAUDE_MODEL,
  maxTokens: config.CLAUDE_MAX_TOKENS,
  mock: config.MOCK_CLAUDE_API,
  temperature: config.CLAUDE_TEMPERATURE || 0.7
};

/**
 * CORS configuration
 */
export const corsConfig = {
  origin: config.CORS_ORIGIN.split(',').map(origin => origin.trim()),
  credentials: config.CORS_CREDENTIALS,
};

/**
 * Storage configuration
 */
export const storageConfig = {
  type: config.STORAGE_TYPE,
  path: config.STORAGE_PATH,
  s3: {
    bucket: config.AWS_S3_BUCKET,
    accessKeyId: config.AWS_ACCESS_KEY_ID,
    secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
    region: config.AWS_REGION,
  },
};

/**
 * Check if running in development mode
 */
export const isDevelopment = config.NODE_ENV === 'development';

/**
 * Check if running in production mode
 */
export const isProduction = config.NODE_ENV === 'production';

/**
 * Check if running in test mode
 */
export const isTest = config.NODE_ENV === 'test';

/**
 * Application version (from package.json)
 */
export const appVersion = process.env.npm_package_version || '1.0.0';

/**
 * Full application configuration object
 */
export const appConfig = {
  app: {
    name: 'Claude Memory Backend',
    version: appVersion,
    environment: config.NODE_ENV,
    host: config.HOST,
    port: config.PORT,
  },
  database: databaseConfig,
  masterDatabase: masterDatabaseConfig,
  redis: redisConfig,
  jwt: jwtConfig,
  claude: claudeConfig,
  cors: corsConfig,
  storage: storageConfig,
  security: {
    bcryptRounds: config.BCRYPT_ROUNDS,
    encryptionKey: config.ENCRYPTION_KEY,
  },
  rateLimit: {
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    maxRequests: config.RATE_LIMIT_MAX_REQUESTS,
  },
  logging: {
    level: config.LOG_LEVEL,
    format: config.LOG_FORMAT,
  },
  features: {
    swagger: config.ENABLE_SWAGGER,
    webhooks: config.ENABLE_WEBHOOKS,
    analytics: config.ENABLE_ANALYTICS,
    auditLogs: config.ENABLE_AUDIT_LOGS,
    websockets: config.WS_ENABLED,
  },
  development: {
    disableAuth: config.DISABLE_AUTH,
    seedDatabase: config.SEED_DATABASE,
  },
} as const;

// Type exports
export type Config = typeof config;
export type AppConfig = typeof appConfig;