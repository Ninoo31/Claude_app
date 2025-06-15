import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { 
  createMasterConnection, 
  createTenantConnection, 
  testConnection, 
  closeConnection,
  healthCheck,
  type DatabaseConnection 
} from '@/config/database';
import * as masterSchema from '@/database/schemas/master.schema';
import * as tenantSchema from '@/database/schemas/tenant.schema';
import crypto from 'crypto';

/**
 * Database Service
 * Manages PostgreSQL connections for master and tenant databases
 * Handles multi-tenant architecture with isolated user databases
 */

interface TenantConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl?: boolean;
}

interface ConnectionPool {
  [userId: string]: DatabaseConnection;
}

class DatabaseService {
  private masterConnection: DatabaseConnection | null = null;
  private tenantConnections: ConnectionPool = {};
  private isInitialized = false;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  /**
   * Initialize the database service
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing database service...');

      // Initialize master database connection
      await this.initializeMasterDatabase();

      // Start health monitoring
      this.startHealthMonitoring();

      this.isInitialized = true;
      logger.info('Database service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database service:', error);
      throw error;
    }
  }

  /**
   * Initialize master database connection
   */
  private async initializeMasterDatabase(): Promise<void> {
    try {
      this.masterConnection = createMasterConnection();
      
      // Test master connection
      const isHealthy = await testConnection(this.masterConnection);
      if (!isHealthy) {
        throw new Error('Master database connection test failed');
      }

      // Run master database migrations
      await this.runMasterMigrations();

      logger.info('Master database connection established');
    } catch (error) {
      logger.error('Failed to initialize master database:', error);
      throw error;
    }
  }

  /**
   * Get master database connection
   */
  getMasterDb(): any {
    if (!this.masterConnection) {
      throw new Error('Master database not initialized');
    }
    return this.masterConnection.db;
  }

  /**
   * Get or create tenant database connection for a user
   */
  async getUserDatabase(userId: string): Promise<any> {
    if (!this.isInitialized) {
      throw new Error('Database service not initialized');
    }

    // Check if connection already exists
    if (this.tenantConnections[userId]) {
      return this.tenantConnections[userId].db;
    }

    try {
      // Get user's database configuration from master database
      const tenantConfig = await this.getUserDatabaseConfig(userId);
      
      if (!tenantConfig) {
        // Create new tenant database if it doesn't exist
        const newConfig = await this.createTenantDatabase(userId);
        return await this.connectToTenantDatabase(userId, newConfig);
      }

      return await this.connectToTenantDatabase(userId, tenantConfig);
    } catch (error) {
      logger.error(`Failed to get user database for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Create a new tenant database for a user
   */
  private async createTenantDatabase(userId: string): Promise<TenantConfig> {
    try {
      const masterDb = this.getMasterDb();
      
      // Generate unique database name and credentials
      const dbName = `tenant_${userId.replace(/-/g, '_')}`;
      const dbUser = `user_${userId.replace(/-/g, '_')}`;
      const dbPassword = this.generateSecurePassword();

      // Create database and user using admin connection
      const adminClient = postgres({
        host: config.DB_HOST,
        port: config.DB_PORT,
        database: 'postgres', // Connect to default database
        username: config.DB_USER,
        password: config.DB_PASSWORD,
        ssl: config.DB_SSL,
      });

      try {
        // Create database
        await adminClient`CREATE DATABASE ${adminClient(dbName)}`;
        logger.info(`Created database: ${dbName}`);

        // Create user
        await adminClient`CREATE USER ${adminClient(dbUser)} WITH PASSWORD ${dbPassword}`;
        logger.info(`Created user: ${dbUser}`);

        // Grant privileges
        await adminClient`GRANT ALL PRIVILEGES ON DATABASE ${adminClient(dbName)} TO ${adminClient(dbUser)}`;
        await adminClient`ALTER DATABASE ${adminClient(dbName)} OWNER TO ${adminClient(dbUser)}`;
        
      } finally {
        await adminClient.end();
      }

      // Store configuration in master database
      const tenantConfig: TenantConfig = {
        host: config.DB_HOST,
        port: config.DB_PORT,
        database: dbName,
        username: dbUser,
        password: dbPassword,
        ssl: config.DB_SSL,
      };

      await masterDb
        .insert(masterSchema.userDatabases)
        .values({
          user_id: userId,
          database_name: dbName,
          database_user: dbUser,
          database_password: this.encryptPassword(dbPassword),
          database_host: config.DB_HOST,
          database_port: config.DB_PORT,
          connection_config: {
            ssl: config.DB_SSL,
            max_connections: 5,
          },
          status: 'active',
        });

      logger.info(`Tenant database created for user: ${userId}`);
      return tenantConfig;
    } catch (error) {
      logger.error(`Failed to create tenant database for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Connect to tenant database
   */
  private async connectToTenantDatabase(userId: string, config: TenantConfig): Promise<any> {
    try {
      const connection = createTenantConnection(config);
      
      // Test connection
      const isHealthy = await testConnection(connection);
      if (!isHealthy) {
        throw new Error(`Tenant database connection test failed for user: ${userId}`);
      }

      // Run tenant migrations
      await this.runTenantMigrations(connection);

      // Store connection
      this.tenantConnections[userId] = connection;

      logger.info(`Connected to tenant database for user: ${userId}`);
      return connection.db;
    } catch (error) {
      logger.error(`Failed to connect to tenant database for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get user's database configuration from master database
   */
  private async getUserDatabaseConfig(userId: string): Promise<TenantConfig | null> {
    try {
      const masterDb = this.getMasterDb();
      
      const [dbConfig] = await masterDb
        .select()
        .from(masterSchema.userDatabases)
        .where(masterSchema.userDatabases.user_id.eq(userId))
        .where(masterSchema.userDatabases.status.eq('active'))
        .limit(1);

      if (!dbConfig) {
        return null;
      }

      return {
        host: dbConfig.database_host,
        port: dbConfig.database_port,
        database: dbConfig.database_name,
        username: dbConfig.database_user,
        password: this.decryptPassword(dbConfig.database_password),
        ssl: dbConfig.connection_config?.ssl || config.DB_SSL,
      };
    } catch (error) {
      logger.error(`Failed to get database config for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Run master database migrations
   */
  private async runMasterMigrations(): Promise<void> {
    try {
      if (!this.masterConnection) {
        throw new Error('Master connection not available');
      }

      await migrate(this.masterConnection.db, {
        migrationsFolder: './src/database/migrations/master',
      });

      logger.info('Master database migrations completed');
    } catch (error) {
      logger.error('Master database migration failed:', error);
      throw error;
    }
  }

  /**
   * Run tenant database migrations
   */
  private async runTenantMigrations(connection: DatabaseConnection): Promise<void> {
    try {
      await migrate(connection.db, {
        migrationsFolder: './src/database/migrations/tenant',
      });

      logger.debug('Tenant database migrations completed');
    } catch (error) {
      logger.error('Tenant database migration failed:', error);
      throw error;
    }
  }

  /**
   * Close user database connection
   */
  async closeUserDatabase(userId: string): Promise<void> {
    try {
      const connection = this.tenantConnections[userId];
      if (connection) {
        await closeConnection(connection);
        delete this.tenantConnections[userId];
        logger.info(`Closed database connection for user: ${userId}`);
      }
    } catch (error) {
      logger.error(`Failed to close database connection for user ${userId}:`, error);
    }
  }

  /**
   * Get database health status
   */
  async getHealthStatus(): Promise<{
    master: any;
    tenants: { [userId: string]: any };
    overview: {
      totalConnections: number;
      healthyConnections: number;
      avgLatency: number;
    };
  }> {
    const results = {
      master: { healthy: false, latency: 0, error: 'Not initialized' },
      tenants: {} as { [userId: string]: any },
      overview: {
        totalConnections: 0,
        healthyConnections: 0,
        avgLatency: 0,
      },
    };

    try {
      // Check master database
      if (this.masterConnection) {
        results.master = await healthCheck(this.masterConnection);
      }

      // Check tenant databases
      const healthPromises = Object.entries(this.tenantConnections).map(
        async ([userId, connection]) => {
          const health = await healthCheck(connection);
          results.tenants[userId] = health;
          return health;
        }
      );

      await Promise.all(healthPromises);

      // Calculate overview statistics
      const allHealthChecks = [results.master, ...Object.values(results.tenants)];
      results.overview.totalConnections = allHealthChecks.length;
      results.overview.healthyConnections = allHealthChecks.filter(h => h.healthy).length;
      results.overview.avgLatency = allHealthChecks.reduce((sum, h) => sum + h.latency, 0) / allHealthChecks.length;

    } catch (error) {
      logger.error('Health check failed:', error);
    }

    return results;
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(async () => {
      try {
        const health = await this.getHealthStatus();
        
        if (!health.master.healthy) {
          logger.error('Master database unhealthy:', health.master);
        }

        const unhealthyTenants = Object.entries(health.tenants)
          .filter(([, health]) => !health.healthy);

        if (unhealthyTenants.length > 0) {
          logger.warn('Unhealthy tenant databases:', unhealthyTenants);
        }

        // Log summary
        logger.debug('Database health summary:', {
          totalConnections: health.overview.totalConnections,
          healthyConnections: health.overview.healthyConnections,
          avgLatency: `${health.overview.avgLatency.toFixed(2)}ms`,
        });

      } catch (error) {
        logger.error('Health monitoring error:', error);
      }
    }, 30000); // Every 30 seconds
  }

  /**
   * Cleanup inactive connections
   */
  async cleanupInactiveConnections(): Promise<void> {
    const inactiveThreshold = 30 * 60 * 1000; // 30 minutes
    const now = Date.now();

    for (const [userId, connection] of Object.entries(this.tenantConnections)) {
      try {
        // This would require tracking last activity time
        // For now, we'll keep all connections active
        // In production, implement proper connection pooling with timeouts
        logger.debug(`Connection for user ${userId} is active`);
      } catch (error) {
        logger.error(`Error checking connection for user ${userId}:`, error);
        await this.closeUserDatabase(userId);
      }
    }
  }

  /**
   * Backup user database
   */
  async backupUserDatabase(userId: string): Promise<string> {
    try {
      const connection = this.tenantConnections[userId];
      if (!connection) {
        throw new Error(`No active connection for user: ${userId}`);
      }

      const backupPath = `./backups/${userId}_${Date.now()}.sql`;
      
      // In production, use pg_dump or similar tool
      // This is a simplified example
      logger.info(`Creating backup for user ${userId} at ${backupPath}`);
      
      // Simulate backup creation
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      logger.info(`Backup completed for user: ${userId}`);
      return backupPath;
    } catch (error) {
      logger.error(`Backup failed for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Restore user database from backup
   */
  async restoreUserDatabase(userId: string, backupPath: string): Promise<void> {
    try {
      const connection = this.tenantConnections[userId];
      if (!connection) {
        throw new Error(`No active connection for user: ${userId}`);
      }

      logger.info(`Restoring database for user ${userId} from ${backupPath}`);
      
      // In production, use psql or similar tool
      // This is a simplified example
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      logger.info(`Restore completed for user: ${userId}`);
    } catch (error) {
      logger.error(`Restore failed for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Delete user database
   */
  async deleteUserDatabase(userId: string): Promise<void> {
    try {
      const masterDb = this.getMasterDb();
      
      // Get database configuration
      const [dbConfig] = await masterDb
        .select()
        .from(masterSchema.userDatabases)
        .where(masterSchema.userDatabases.user_id.eq(userId))
        .limit(1);

      if (!dbConfig) {
        logger.warn(`No database found for user: ${userId}`);
        return;
      }

      // Close connection if active
      await this.closeUserDatabase(userId);

      // Create admin connection
      const adminClient = postgres({
        host: config.DB_HOST,
        port: config.DB_PORT,
        database: 'postgres',
        username: config.DB_USER,
        password: config.DB_PASSWORD,
        ssl: config.DB_SSL,
      });

      try {
        // Terminate active connections to the database
        await adminClient`
          SELECT pg_terminate_backend(pid)
          FROM pg_stat_activity
          WHERE datname = ${dbConfig.database_name}
            AND pid <> pg_backend_pid()
        `;

        // Drop database and user
        await adminClient`DROP DATABASE IF EXISTS ${adminClient(dbConfig.database_name)}`;
        await adminClient`DROP USER IF EXISTS ${adminClient(dbConfig.database_user)}`;

        logger.info(`Deleted database and user for: ${userId}`);
      } finally {
        await adminClient.end();
      }

      // Mark as deleted in master database
      await masterDb
        .update(masterSchema.userDatabases)
        .set({ 
          status: 'deleted',
          deleted_at: new Date(),
        })
        .where(masterSchema.userDatabases.user_id.eq(userId));

      logger.info(`Database deletion completed for user: ${userId}`);
    } catch (error) {
      logger.error(`Failed to delete database for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get connection statistics
   */
  getConnectionStats(): {
    master: any;
    tenants: {
      total: number;
      active: number;
      users: string[];
    };
  } {
    return {
      master: this.masterConnection ? {
        connected: true,
        config: this.masterConnection.config,
      } : {
        connected: false,
      },
      tenants: {
        total: Object.keys(this.tenantConnections).length,
        active: Object.values(this.tenantConnections).length,
        users: Object.keys(this.tenantConnections),
      },
    };
  }

  /**
   * Test database connection for a user
   */
  async testUserDatabaseConnection(userId: string): Promise<boolean> {
    try {
      const connection = this.tenantConnections[userId];
      if (!connection) {
        // Try to get the database (will create connection if needed)
        await this.getUserDatabase(userId);
        return true;
      }

      return await testConnection(connection);
    } catch (error) {
      logger.error(`Database connection test failed for user ${userId}:`, error);
      return false;
    }
  }

  /**
   * Execute raw SQL query on user database
   */
  async executeQuery(userId: string, query: string, params: any[] = []): Promise<any> {
    try {
      const db = await this.getUserDatabase(userId);
      const connection = this.tenantConnections[userId];
      
      if (!connection) {
        throw new Error(`No connection available for user: ${userId}`);
      }

      // Execute query with parameters
      const result = await connection.client.unsafe(query, params);
      
      logger.debug(`Query executed for user ${userId}:`, {
        query: query.substring(0, 100),
        paramCount: params.length,
        resultCount: result.length,
      });

      return result;
    } catch (error) {
      logger.error(`Query execution failed for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get database size for a user
   */
  async getUserDatabaseSize(userId: string): Promise<{
    size: number;
    sizeFormatted: string;
    tableCount: number;
  }> {
    try {
      const connection = this.tenantConnections[userId];
      if (!connection) {
        throw new Error(`No connection available for user: ${userId}`);
      }

      const sizeQuery = `
        SELECT pg_database_size(current_database()) as size_bytes,
               pg_size_pretty(pg_database_size(current_database())) as size_formatted
      `;

      const tableCountQuery = `
        SELECT COUNT(*) as table_count
        FROM information_schema.tables
        WHERE table_schema = 'public'
      `;

      const [sizeResult] = await connection.client.unsafe(sizeQuery);
      const [tableResult] = await connection.client.unsafe(tableCountQuery);

      return {
        size: parseInt(sizeResult.size_bytes, 10),
        sizeFormatted: sizeResult.size_formatted,
        tableCount: parseInt(tableResult.table_count, 10),
      };
    } catch (error) {
      logger.error(`Failed to get database size for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Shutdown database service
   */
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down database service...');

      // Clear health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }

      // Close all tenant connections
      const closePromises = Object.keys(this.tenantConnections).map(userId =>
        this.closeUserDatabase(userId)
      );
      await Promise.all(closePromises);

      // Close master connection
      if (this.masterConnection) {
        await closeConnection(this.masterConnection);
        this.masterConnection = null;
      }

      this.isInitialized = false;
      logger.info('Database service shutdown completed');
    } catch (error) {
      logger.error('Error during database service shutdown:', error);
      throw error;
    }
  }

  /**
   * Utility methods
   */

  private generateSecurePassword(): string {
    return crypto.randomBytes(32).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }

  private encryptPassword(password: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', config.ENCRYPTION_KEY);
    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private decryptPassword(encryptedPassword: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', config.ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedPassword, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Get service status
   */
  getStatus(): {
    initialized: boolean;
    masterConnected: boolean;
    tenantConnections: number;
    uptime: number;
  } {
    return {
      initialized: this.isInitialized,
      masterConnected: !!this.masterConnection,
      tenantConnections: Object.keys(this.tenantConnections).length,
      uptime: process.uptime(),
    };
  }
}

// Export singleton instance
export const databaseService = new DatabaseService();

export default databaseService;