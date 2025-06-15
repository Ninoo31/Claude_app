import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { config } from './environment';
import { logger } from '@/utils/logger';
import * as masterSchema from '@/database/schemas/master.schema';
import * as tenantSchema from '@/database/schemas/tenant.schema';

/**
 * Database Configuration
 * Manages database connections and configurations for multi-tenant architecture
 */

export interface DatabaseConnection {
  client: postgres.Sql;
  db: any;
  schema: typeof masterSchema | typeof tenantSchema;
  type: 'master' | 'tenant';
  connected: boolean;
  lastHealthCheck?: Date;
}

export class DatabaseConfig {
  private connections: Map<string, DatabaseConnection> = new Map();
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private readonly maxConnections = 20;
  private readonly connectionTimeout = 30000; // 30 seconds
  private readonly healthCheckIntervalMs = 60000; // 1 minute

  /**
   * Get master database connection configuration
   */
  static getMasterConfig(): postgres.Options<{}> {
    return {
      host: new URL(config.database.masterUrl).hostname,
      port: parseInt(new URL(config.database.masterUrl).port || '5432'),
      database: new URL(config.database.masterUrl).pathname.substring(1),
      username: new URL(config.database.masterUrl).username,
      password: new URL(config.database.masterUrl).password,
      ssl: config.node.env === 'production' ? 'require' : false,
      max: this.getConnectionPoolSize(),
      idle_timeout: 20,
      connect_timeout: 30,
      prepare: false,
      types: {
        bigint: postgres.BigInt,
      },
      transform: {
        undefined: null,
      },
      connection: {
        application_name: 'claude-memory-backend',
        search_path: 'public',
      },
    };
  }

  /**
   * Get tenant database connection configuration
   */
  static getTenantConfig(connectionString: string, schemaName?: string): postgres.Options<{}> {
    return {
      host: new URL(connectionString).hostname,
      port: parseInt(new URL(connectionString).port || '5432'),
      database: new URL(connectionString).pathname.substring(1),
      username: new URL(connectionString).username,
      password: new URL(connectionString).password,
      ssl: config.node.env === 'production' ? 'require' : false,
      max: this.getConnectionPoolSize() / 2, // Smaller pool for tenant connections
      idle_timeout: 20,
      connect_timeout: 30,
      prepare: false,
      types: {
        bigint: postgres.BigInt,
      },
      transform: {
        undefined: null,
      },
      connection: {
        application_name: 'claude-memory-tenant',
        search_path: schemaName ? `${schemaName}, public` : 'public',
      },
    };
  }

  /**
   * Create master database connection
   */
  static createMasterConnection(): DatabaseConnection {
    try {
      const client = postgres(config.database.masterUrl, this.getMasterConfig());
      const db = drizzle(client, { schema: masterSchema });

      const connection: DatabaseConnection = {
        client,
        db,
        schema: masterSchema,
        type: 'master',
        connected: false,
      };

      logger.info('Master database connection created');
      return connection;
    } catch (error) {
      logger.error('Failed to create master database connection:', error);
      throw error;
    }
  }

  /**
   * Create tenant database connection
   */
  static createTenantConnection(
    connectionString: string, 
    schemaName?: string
  ): DatabaseConnection {
    try {
      const client = postgres(connectionString, this.getTenantConfig(connectionString, schemaName));
      const db = drizzle(client, { schema: tenantSchema });

      const connection: DatabaseConnection = {
        client,
        db,
        schema: tenantSchema,
        type: 'tenant',
        connected: false,
      };

      logger.debug(`Tenant database connection created for schema: ${schemaName || 'default'}`);
      return connection;
    } catch (error) {
      logger.error('Failed to create tenant database connection:', error);
      throw error;
    }
  }

  /**
   * Test database connection
   */
  static async testConnection(connection: DatabaseConnection): Promise<boolean> {
    try {
      await connection.client`SELECT 1`;
      connection.connected = true;
      connection.lastHealthCheck = new Date();
      return true;
    } catch (error) {
      logger.error('Database connection test failed:', error);
      connection.connected = false;
      return false;
    }
  }

  /**
   * Get connection pool size based on environment
   */
  private static getConnectionPoolSize(): number {
    switch (config.node.env) {
      case 'production':
        return 20;
      case 'test':
        return 5;
      default:
        return 10;
    }
  }

  /**
   * Get database migration configuration
   */
  static getMigrationConfig() {
    return {
      migrationsFolder: './src/database/migrations',
      migrationsTable: 'migrations',
      schema: 'public',
    };
  }

  /**
   * Get database seed configuration
   */
  static getSeedConfig() {
    return {
      enabled: config.node.env === 'development',
      seedsFolder: './src/database/seeders',
    };
  }

  /**
   * Database health check configuration
   */
  static getHealthCheckConfig() {
    return {
      enabled: true,
      interval: 60000, // 1 minute
      timeout: 5000,   // 5 seconds
      retries: 3,
    };
  }

  /**
   * Connection string builder for different database types
   */
  static buildConnectionString(config: {
    type: 'postgresql' | 'mysql' | 'mongodb';
    host: string;
    port: number;
    database: string;
    username: string;
    password: string;
    ssl?: boolean;
    options?: Record<string, string>;
  }): string {
    const { type, host, port, database, username, password, ssl, options = {} } = config;

    switch (type) {
      case 'postgresql':
        const pgOptions = [
          ssl && 'sslmode=require',
          ...Object.entries(options).map(([key, value]) => `${key}=${value}`)
        ].filter(Boolean).join('&');
        
        const pgQuery = pgOptions ? `?${pgOptions}` : '';
        return `postgresql://${username}:${password}@${host}:${port}/${database}${pgQuery}`;

      case 'mysql':
        const mysqlOptions = [
          ssl && 'ssl=true',
          ...Object.entries(options).map(([key, value]) => `${key}=${value}`)
        ].filter(Boolean).join('&');
        
        const mysqlQuery = mysqlOptions ? `?${mysqlOptions}` : '';
        return `mysql://${username}:${password}@${host}:${port}/${database}${mysqlQuery}`;

      case 'mongodb':
        const mongoOptions = [
          ssl && 'ssl=true',
          ...Object.entries(options).map(([key, value]) => `${key}=${value}`)
        ].filter(Boolean).join('&');
        
        const mongoQuery = mongoOptions ? `?${mongoOptions}` : '';
        return `mongodb://${username}:${password}@${host}:${port}/${database}${mongoQuery}`;

      default:
        throw new Error(`Unsupported database type: ${type}`);
    }
  }

  /**
   * Parse connection string into components
   */
  static parseConnectionString(connectionString: string): {
    protocol: string;
    username: string;
    password: string;
    hostname: string;
    port: number;
    database: string;
    searchParams: URLSearchParams;
  } {
    try {
      const url = new URL(connectionString);
      return {
        protocol: url.protocol.replace(':', ''),
        username: url.username,
        password: url.password,
        hostname: url.hostname,
        port: parseInt(url.port) || this.getDefaultPort(url.protocol),
        database: url.pathname.substring(1),
        searchParams: url.searchParams,
      };
    } catch (error) {
      throw new Error(`Invalid connection string format: ${connectionString}`);
    }
  }

  /**
   * Get default port for database type
   */
  private static getDefaultPort(protocol: string): number {
    switch (protocol) {
      case 'postgresql:':
        return 5432;
      case 'mysql:':
        return 3306;
      case 'mongodb:':
        return 27017;
      default:
        return 5432;
    }
  }

  /**
   * Validate database configuration
   */
  static validateConfig(dbConfig: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!dbConfig.host) {
      errors.push('Database host is required');
    }

    if (!dbConfig.database) {
      errors.push('Database name is required');
    }

    if (!dbConfig.username) {
      errors.push('Database username is required');
    }

    if (!dbConfig.password) {
      errors.push('Database password is required');
    }

    if (dbConfig.port && (dbConfig.port < 1 || dbConfig.port > 65535)) {
      errors.push('Database port must be between 1 and 65535');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get optimized connection settings based on environment
   */
  static getOptimizedSettings(env: string = config.node.env) {
    const baseSettings = {
      statement_timeout: '30s',
      idle_in_transaction_session_timeout: '60s',
      lock_timeout: '10s',
    };

    switch (env) {
      case 'production':
        return {
          ...baseSettings,
          shared_preload_libraries: 'pg_stat_statements',
          max_connections: 200,
          shared_buffers: '256MB',
          effective_cache_size: '1GB',
          work_mem: '4MB',
          maintenance_work_mem: '64MB',
          checkpoint_completion_target: 0.9,
          wal_buffers: '16MB',
          default_statistics_target: 100,
        };

      case 'development':
        return {
          ...baseSettings,
          log_statement: 'all',
          log_duration: 'on',
          log_min_duration_statement: 100,
        };

      case 'test':
        return {
          ...baseSettings,
          fsync: 'off',
          synchronous_commit: 'off',
          full_page_writes: 'off',
          checkpoint_segments: 32,
          checkpoint_completion_target: 0.9,
          wal_buffers: '16MB',
        };

      default:
        return baseSettings;
    }
  }

  /**
   * Create backup configuration
   */
  static getBackupConfig() {
    return {
      enabled: config.node.env === 'production',
      schedule: '0 2 * * *', // Daily at 2 AM
      retention: {
        daily: 7,
        weekly: 4,
        monthly: 12,
      },
      compression: true,
      encryption: config.node.env === 'production',
      destinations: {
        local: true,
        s3: config.node.env === 'production',
      },
    };
  }

  /**
   * Get monitoring configuration
   */
  static getMonitoringConfig() {
    return {
      enabled: true,
      metrics: {
        connections: true,
        queries: true,
        performance: true,
        locks: true,
        replication: false,
      },
      alerts: {
        connection_threshold: 80, // % of max connections
        slow_query_threshold: 1000, // ms
        lock_timeout_threshold: 5000, // ms
        disk_usage_threshold: 85, // %
      },
      retention: '30d',
    };
  }
}

// Export default configuration
export const databaseConfig = {
  master: DatabaseConfig.getMasterConfig(),
  migration: DatabaseConfig.getMigrationConfig(),
  seed: DatabaseConfig.getSeedConfig(),
  healthCheck: DatabaseConfig.getHealthCheckConfig(),
  backup: DatabaseConfig.getBackupConfig(),
  monitoring: DatabaseConfig.getMonitoringConfig(),
  optimized: DatabaseConfig.getOptimizedSettings(),
};

// Database connection factory
export const createDatabaseConnection = {
  master: () => DatabaseConfig.createMasterConnection(),
  tenant: (connectionString: string, schemaName?: string) => 
    DatabaseConfig.createTenantConnection(connectionString, schemaName),
};

// Database utilities
export const databaseUtils = {
  test: DatabaseConfig.testConnection,
  parse: DatabaseConfig.parseConnectionString,
  build: DatabaseConfig.buildConnectionString,
  validate: DatabaseConfig.validateConfig,
};