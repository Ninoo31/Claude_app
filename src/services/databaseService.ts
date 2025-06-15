import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { eq, sql } from 'drizzle-orm';
import { migrate } from 'drizzle-orm/postgres-js/migrator';

import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import * as masterSchema from '@/database/schemas/master.schema';
import * as tenantSchema from '@/database/schemas/tenant.schema';

/**
 * Database Service - Multi-tenant database management
 * Handles master database and per-user tenant databases
 * Manages connections, migrations, and health checks
 */
class DatabaseService {
  private masterDb: any = null;
  private tenantConnections: Map<string, any> = new Map();
  private connectionPools: Map<string, postgres.Sql> = new Map();
  private readonly maxConnections = 10;
  private readonly connectionTimeout = 30000; // 30 seconds
  private healthCheckInterval: NodeJS.Timeout | null = null;

  /**
   * Initialize the database service
   * Sets up master database connection and starts health checks
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing database service...');
      
      // Initialize master database
      await this.initializeMasterDatabase();
      
      // Start health check routine
      this.startHealthChecks();
      
      logger.info('Database service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database service:', error);
      throw error;
    }
  }

  /**
   * Initialize master database connection
   * Contains user accounts and database configurations
   */
  private async initializeMasterDatabase(): Promise<void> {
    try {
      const masterPool = postgres(config.database.masterUrl, {
        max: this.maxConnections,
        idle_timeout: 20,
        connect_timeout: this.connectionTimeout,
        ssl: config.node.env === 'production' ? 'require' : false,
      });

      this.masterDb = drizzle(masterPool, { schema: masterSchema });
      this.connectionPools.set('master', masterPool);

      // Test connection
      await this.masterDb.execute(sql`SELECT 1`);
      
      // Run migrations if needed
      await this.runMasterMigrations();
      
      logger.info('Master database connected successfully');
    } catch (error) {
      logger.error('Failed to initialize master database:', error);
      throw error;
    }
  }

  /**
   * Run master database migrations
   */
  private async runMasterMigrations(): Promise<void> {
    try {
      await migrate(this.masterDb, { migrationsFolder: './src/database/migrations/master' });
      logger.info('Master database migrations completed');
    } catch (error) {
      logger.warn('Master database migrations failed or not needed:', error);
    }
  }

  /**
   * Get master database instance
   */
  getMasterDb(): any {
    if (!this.masterDb) {
      throw new Error('Master database not initialized');
    }
    return this.masterDb;
  }

  /**
   * Get or create user database connection
   * @param userId - User ID
   */
  async getUserDatabase(userId: string): Promise<any> {
    try {
      // Check if connection already exists
      if (this.tenantConnections.has(userId)) {
        return this.tenantConnections.get(userId);
      }

      // Get user's database configuration
      const dbConfig = await this.getUserDatabaseConfig(userId);
      
      // Create new connection
      const tenantDb = await this.createTenantConnection(userId, dbConfig);
      
      // Cache the connection
      this.tenantConnections.set(userId, tenantDb);
      
      logger.debug(`User database connection created for user: ${userId}`);
      return tenantDb;
    } catch (error) {
      logger.error(`Failed to get user database for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get user's database configuration from master database
   * @param userId - User ID
   */
  private async getUserDatabaseConfig(userId: string): Promise<any> {
    try {
      const [userDb] = await this.masterDb
        .select()
        .from(masterSchema.userDatabases)
        .where(
          eq(masterSchema.userDatabases.user_id, userId),
          eq(masterSchema.userDatabases.is_default, true),
          eq(masterSchema.userDatabases.is_active, true)
        )
        .limit(1);

      if (!userDb) {
        // Create default database configuration for user
        return await this.createDefaultUserDatabase(userId);
      }

      return userDb;
    } catch (error) {
      logger.error(`Failed to get database config for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Create default database configuration for new user
   * @param userId - User ID
   */
  private async createDefaultUserDatabase(userId: string): Promise<any> {
    try {
      // For now, use master database as default tenant database
      // In production, you might want to create separate databases
      const defaultConfig = {
        user_id: userId,
        name: `User Database - ${userId.substring(0, 8)}`,
        type: 'local',
        connection_config: {
          // Use same connection as master for simplicity
          // In production, create separate schemas or databases
          host: new URL(config.database.masterUrl).hostname,
          port: parseInt(new URL(config.database.masterUrl).port || '5432'),
          database: new URL(config.database.masterUrl).pathname.substring(1),
          schema: `tenant_${userId.replace(/-/g, '_')}`,
        },
        is_active: true,
        is_default: true,
        health_status: 'healthy',
      };

      const [userDb] = await this.masterDb
        .insert(masterSchema.userDatabases)
        .values(defaultConfig)
        .returning();

      logger.info(`Created default database configuration for user: ${userId}`);
      return userDb;
    } catch (error) {
      logger.error(`Failed to create default database for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Create tenant database connection
   * @param userId - User ID
   * @param dbConfig - Database configuration
   */
  private async createTenantConnection(userId: string, dbConfig: any): Promise<any> {
    try {
      let connectionString: string;
      
      if (dbConfig.type === 'local') {
        // Use master database with schema separation
        connectionString = config.database.masterUrl;
      } else {
        // Build connection string from config
        const config_data = dbConfig.connection_config;
        connectionString = `postgresql://${config_data.username}:${config_data.password}@${config_data.host}:${config_data.port}/${config_data.database}`;
      }

      const tenantPool = postgres(connectionString, {
        max: this.maxConnections,
        idle_timeout: 20,
        connect_timeout: this.connectionTimeout,
        ssl: config.node.env === 'production' ? 'require' : false,
        // Set search path for schema separation
        ...(dbConfig.connection_config?.schema && {
          search_path: [dbConfig.connection_config.schema, 'public']
        })
      });

      const tenantDb = drizzle(tenantPool, { schema: tenantSchema });
      
      // Store pool for cleanup
      this.connectionPools.set(`tenant_${userId}`, tenantPool);

      // Test connection
      await tenantDb.execute(sql`SELECT 1`);

      // Ensure schema exists for multi-tenant setup
      if (dbConfig.connection_config?.schema) {
        await this.ensureTenantSchema(tenantPool, dbConfig.connection_config.schema);
      }

      // Run tenant migrations
      await this.runTenantMigrations(tenantDb);

      return tenantDb;
    } catch (error) {
      logger.error(`Failed to create tenant connection for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Ensure tenant schema exists
   * @param pool - PostgreSQL connection pool
   * @param schemaName - Schema name
   */
  private async ensureTenantSchema(pool: postgres.Sql, schemaName: string): Promise<void> {
    try {
      await pool`CREATE SCHEMA IF NOT EXISTS ${pool(schemaName)}`;
      logger.debug(`Ensured schema exists: ${schemaName}`);
    } catch (error) {
      logger.error(`Failed to create schema ${schemaName}:`, error);
      throw error;
    }
  }

  /**
   * Run tenant database migrations
   * @param tenantDb - Tenant database instance
   */
  private async runTenantMigrations(tenantDb: any): Promise<void> {
    try {
      await migrate(tenantDb, { migrationsFolder: './src/database/migrations/tenant' });
      logger.debug('Tenant database migrations completed');
    } catch (error) {
      logger.warn('Tenant database migrations failed or not needed:', error);
    }
  }

  /**
   * Create a new database configuration for user
   * @param userId - User ID
   * @param dbConfig - Database configuration
   */
  async createUserDatabase(userId: string, dbConfig: {
    name: string;
    type: 'local' | 'cloud_postgres' | 'cloud_mysql' | 'cloud_mongodb';
    connection: any;
  }): Promise<any> {
    try {
      // Test connection first
      const testResult = await this.testDatabaseConnection(dbConfig.type, dbConfig.connection);
      if (!testResult.success) {
        throw new Error(`Database connection test failed: ${testResult.error}`);
      }

      // Encrypt connection details (implement encryption in production)
      const encryptedConfig = this.encryptConnectionConfig(dbConfig.connection);

      const newDbConfig = {
        user_id: userId,
        name: dbConfig.name,
        type: dbConfig.type,
        connection_config: encryptedConfig,
        is_active: true,
        is_default: false,
        health_status: 'healthy',
      };

      const [userDb] = await this.masterDb
        .insert(masterSchema.userDatabases)
        .values(newDbConfig)
        .returning();

      logger.info(`Created new database configuration: ${userDb.id} for user: ${userId}`);
      return userDb;
    } catch (error) {
      logger.error('Failed to create user database:', error);
      throw error;
    }
  }

  /**
   * Test database connection
   * @param type - Database type
   * @param connection - Connection parameters
   */
  async testDatabaseConnection(type: string, connection: any): Promise<{
    success: boolean;
    error?: string;
    response_time?: number;
  }> {
    const startTime = Date.now();
    
    try {
      switch (type) {
        case 'local':
        case 'cloud_postgres':
          return await this.testPostgresConnection(connection);
        case 'cloud_mysql':
          return await this.testMysqlConnection(connection);
        case 'cloud_mongodb':
          return await this.testMongoConnection(connection);
        default:
          throw new Error(`Unsupported database type: ${type}`);
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        response_time: Date.now() - startTime,
      };
    }
  }

  /**
   * Test PostgreSQL connection
   * @param connection - Connection parameters
   */
  private async testPostgresConnection(connection: any): Promise<any> {
    const startTime = Date.now();
    let testPool: postgres.Sql | null = null;

    try {
      const connectionString = `postgresql://${connection.username}:${connection.password}@${connection.host}:${connection.port}/${connection.database}`;
      
      testPool = postgres(connectionString, {
        max: 1,
        connect_timeout: 10000,
        ssl: connection.ssl || false,
      });

      await testPool`SELECT 1`;
      
      return {
        success: true,
        response_time: Date.now() - startTime,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        response_time: Date.now() - startTime,
      };
    } finally {
      if (testPool) {
        await testPool.end();
      }
    }
  }

  /**
   * Test MySQL connection (placeholder)
   * @param connection - Connection parameters
   */
  private async testMysqlConnection(connection: any): Promise<any> {
    // Implement MySQL connection test
    return {
      success: false,
      error: 'MySQL support not implemented yet',
    };
  }

  /**
   * Test MongoDB connection (placeholder)
   * @param connection - Connection parameters
   */
  private async testMongoConnection(connection: any): Promise<any> {
    // Implement MongoDB connection test
    return {
      success: false,
      error: 'MongoDB support not implemented yet',
    };
  }

  /**
   * Encrypt connection configuration (placeholder)
   * @param config - Connection configuration
   */
  private encryptConnectionConfig(config: any): any {
    // TODO: Implement proper encryption
    // For now, return as-is (NOT SECURE)
    return config;
  }

  /**
   * Get database health status
   * @param userId - User ID (optional, if not provided checks master)
   */
  async getHealthStatus(userId?: string): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    checks: Array<{
      name: string;
      status: 'pass' | 'fail';
      response_time?: number;
      error?: string;
    }>;
  }> {
    const checks: any[] = [];
    
    try {
      // Check master database
      const masterCheck = await this.checkDatabaseHealth('master', this.masterDb);
      checks.push(masterCheck);

      // Check user database if specified
      if (userId) {
        try {
          const userDb = await this.getUserDatabase(userId);
          const userCheck = await this.checkDatabaseHealth(`user_${userId}`, userDb);
          checks.push(userCheck);
        } catch (error: any) {
          checks.push({
            name: `user_${userId}`,
            status: 'fail',
            error: error.message,
          });
        }
      }

      // Determine overall status
      const failedChecks = checks.filter(check => check.status === 'fail');
      const status = failedChecks.length === 0 ? 'healthy' : 
                   failedChecks.length === checks.length ? 'unhealthy' : 'degraded';

      return { status, checks };
    } catch (error: any) {
      return {
        status: 'unhealthy',
        checks: [{
          name: 'database_service',
          status: 'fail',
          error: error.message,
        }],
      };
    }
  }

  /**
   * Check individual database health
   * @param name - Database name for identification
   * @param db - Database instance
   */
  private async checkDatabaseHealth(name: string, db: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      await db.execute(sql`SELECT 1`);
      return {
        name,
        status: 'pass',
        response_time: Date.now() - startTime,
      };
    } catch (error: any) {
      return {
        name,
        status: 'fail',
        response_time: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(async () => {
      try {
        const health = await this.getHealthStatus();
        if (health.status !== 'healthy') {
          logger.warn('Database health check failed:', health);
        }
      } catch (error) {
        logger.error('Health check error:', error);
      }
    }, 60000); // Check every minute
  }

  /**
   * Close all database connections
   */
  async closeAll(): Promise<void> {
    try {
      logger.info('Closing all database connections...');
      
      // Stop health checks
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }

      // Close all connection pools
      for (const [name, pool] of this.connectionPools.entries()) {
        try {
          await pool.end();
          logger.debug(`Closed connection pool: ${name}`);
        } catch (error) {
          logger.error(`Error closing pool ${name}:`, error);
        }
      }

      // Clear caches
      this.tenantConnections.clear();
      this.connectionPools.clear();
      this.masterDb = null;

      logger.info('All database connections closed');
    } catch (error) {
      logger.error('Error closing database connections:', error);
      throw error;
    }
  }

  /**
   * Remove user database connection from cache
   * @param userId - User ID
   */
  async closeUserConnection(userId: string): Promise<void> {
    try {
      const poolKey = `tenant_${userId}`;
      
      if (this.connectionPools.has(poolKey)) {
        const pool = this.connectionPools.get(poolKey);
        await pool?.end();
        this.connectionPools.delete(poolKey);
      }

      this.tenantConnections.delete(userId);
      
      logger.debug(`Closed database connection for user: ${userId}`);
    } catch (error) {
      logger.error(`Error closing connection for user ${userId}:`, error);
    }
  }

  /**
   * Get connection statistics
   */
  getConnectionStats(): {
    master_connected: boolean;
    tenant_connections: number;
    total_pools: number;
    active_users: string[];
  } {
    return {
      master_connected: this.masterDb !== null,
      tenant_connections: this.tenantConnections.size,
      total_pools: this.connectionPools.size,
      active_users: Array.from(this.tenantConnections.keys()),
    };
  }
}

// Export singleton instance
export const databaseService = new DatabaseService();