import { Request, Response } from 'express';
import { body, query, param, validationResult } from 'express-validator';
import { databaseService } from '@/services/databaseService';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import { asyncHandler, createError } from '@/middleware/errorHandler';
import type { ApiResponse, DatabaseConfig, DatabaseTestResult } from '@/types/database.types';

/**
 * Database Controller
 * Handles database configuration management for users
 */
class DatabaseController {
  /**
   * Get user's database configurations
   * GET /api/v1/database
   */
  getDatabases = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;

    try {
      // Get user's database configurations from master database
      const masterDb = databaseService.getMasterDb();
      
      const databases = await masterDb.execute(`
        SELECT 
          id,
          name,
          type,
          is_active,
          is_default,
          health_status,
          last_health_check,
          created_at,
          updated_at,
          last_backup_at,
          metadata
        FROM user_databases 
        WHERE user_id = $1
        ORDER BY is_default DESC, created_at DESC
      `, [userId]);

      // Remove sensitive connection details
      const safeDatabases = databases.rows.map((db: any) => ({
        ...db,
        connection_summary: this.getConnectionSummary(db.type),
      }));

      const response: ApiResponse = {
        success: true,
        data: { databases: safeDatabases },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get user databases:', error);
      throw createError.database('Failed to retrieve database configurations');
    }
  });

  /**
   * Create new database configuration
   * POST /api/v1/database
   */
  createDatabase = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { name, type, connection } = req.body;

    // Validate connection details based on type
    this.validateConnectionConfig(type, connection);

    const dbConfig: DatabaseConfig = {
      type: type as any,
      connection,
    };

    const database = await databaseService.createUserDatabase(userId, {
      name,
      type,
      connection,
    });

    // Log audit event
    await auditService.logDatabase({
      user_id: userId,
      action: 'create',
      database_id: database.id,
      database_type: type,
      success: true,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    // Remove sensitive data from response
    const safeDatabase = {
      ...database,
      connection_config: this.sanitizeConnectionConfig(database.connection_config),
    };

    const response: ApiResponse = {
      success: true,
      data: { database: safeDatabase },
      message: 'Database configuration created successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Test database connection
   * POST /api/v1/database/test
   */
  testConnection = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { type, connection } = req.body;

    // Validate connection details
    this.validateConnectionConfig(type, connection);

    const testResult = await databaseService.testDatabaseConnection(type, connection);

    // Log audit event
    await auditService.logDatabase({
      user_id: userId,
      action: 'test',
      database_type: type,
      success: testResult.success,
      error: testResult.error,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { test_result: testResult },
      message: testResult.success ? 'Connection test successful' : 'Connection test failed',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Update database configuration
   * PUT /api/v1/database/:databaseId
   */
  updateDatabase = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const databaseId = req.params.databaseId;
    const updates = req.body;

    try {
      const masterDb = databaseService.getMasterDb();

      // Verify ownership
      const [existingDb] = await masterDb.execute(`
        SELECT * FROM user_databases 
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      if (!existingDb.rows[0]) {
        throw createError.notFound('Database configuration');
      }

      // Validate new connection if provided
      if (updates.connection) {
        const dbType = updates.type || existingDb.rows[0].type;
        this.validateConnectionConfig(dbType, updates.connection);
        
        // Test new connection
        const testResult = await databaseService.testDatabaseConnection(dbType, updates.connection);
        if (!testResult.success) {
          throw createError.validation(`Connection test failed: ${testResult.error}`, []);
        }
      }

      // Update database configuration
      const updateFields = [];
      const updateValues = [];
      let paramIndex = 1;

      if (updates.name) {
        updateFields.push(`name = $${paramIndex}`);
        updateValues.push(updates.name);
        paramIndex++;
      }

      if (updates.connection) {
        updateFields.push(`connection_config = $${paramIndex}`);
        updateValues.push(JSON.stringify(updates.connection));
        paramIndex++;
      }

      if (updates.is_active !== undefined) {
        updateFields.push(`is_active = $${paramIndex}`);
        updateValues.push(updates.is_active);
        paramIndex++;
      }

      updateFields.push(`updated_at = $${paramIndex}`);
      updateValues.push(new Date());
      paramIndex++;

      updateValues.push(databaseId);

      const updateQuery = `
        UPDATE user_databases 
        SET ${updateFields.join(', ')}
        WHERE id = $${paramIndex}
        RETURNING *
      `;

      const [updatedDb] = await masterDb.execute(updateQuery, updateValues);

      // Log audit event
      await auditService.logDatabase({
        user_id: userId,
        action: 'update',
        database_id: databaseId,
        success: true,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      // Remove sensitive data
      const safeDatabase = {
        ...updatedDb.rows[0],
        connection_config: this.sanitizeConnectionConfig(updatedDb.rows[0].connection_config),
      };

      const response: ApiResponse = {
        success: true,
        data: { database: safeDatabase },
        message: 'Database configuration updated successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to update database:', error);
      if (error instanceof Error && error.message.includes('not found')) {
        throw error;
      }
      throw createError.database('Failed to update database configuration');
    }
  });

  /**
   * Delete database configuration
   * DELETE /api/v1/database/:databaseId
   */
  /**
   * Delete database configuration
   * DELETE /api/v1/database/:databaseId
   */
  deleteDatabase = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const databaseId = req.params.databaseId;

    try {
      const masterDb = databaseService.getMasterDb();

      // Verify ownership and check if it's the default database
      const [existingDb] = await masterDb.execute(`
        SELECT * FROM user_databases 
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      if (!existingDb.rows[0]) {
        throw createError.notFound('Database configuration');
      }

      if (existingDb.rows[0].is_default) {
        throw createError.validation('Cannot delete the default database configuration', []);
      }

      // Close any active connections to this database
      await databaseService.closeUserConnection(userId);

      // Delete the database configuration
      await masterDb.execute(`
        DELETE FROM user_databases 
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      // Log audit event
      await auditService.logDatabase({
        user_id: userId,
        action: 'delete',
        database_id: databaseId,
        database_type: existingDb.rows[0].type,
        success: true,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        message: 'Database configuration deleted successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to delete database:', error);
      if (error instanceof Error && (error.message.includes('not found') || error.message.includes('Cannot delete'))) {
        throw error;
      }
      throw createError.database('Failed to delete database configuration');
    }
  });

  /**
   * Set database as default
   * POST /api/v1/database/:databaseId/set-default
   */
  setDefaultDatabase = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const databaseId = req.params.databaseId;

    try {
      const masterDb = databaseService.getMasterDb();

      // Verify ownership
      const [existingDb] = await masterDb.execute(`
        SELECT * FROM user_databases 
        WHERE id = $1 AND user_id = $2 AND is_active = true
      `, [databaseId, userId]);

      if (!existingDb.rows[0]) {
        throw createError.notFound('Active database configuration');
      }

      // Update all user databases to not be default
      await masterDb.execute(`
        UPDATE user_databases 
        SET is_default = false, updated_at = NOW()
        WHERE user_id = $1
      `, [userId]);

      // Set the specified database as default
      await masterDb.execute(`
        UPDATE user_databases 
        SET is_default = true, updated_at = NOW()
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      // Close existing connections to force reconnection with new default
      await databaseService.closeUserConnection(userId);

      // Log audit event
      await auditService.logDatabase({
        user_id: userId,
        action: 'set_default',
        database_id: databaseId,
        database_type: existingDb.rows[0].type,
        success: true,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        message: 'Default database set successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to set default database:', error);
      if (error instanceof Error && error.message.includes('not found')) {
        throw error;
      }
      throw createError.database('Failed to set default database');
    }
  });

  /**
   * Get database statistics and health
   * GET /api/v1/database/stats
   */
  getDatabaseStats = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;

    try {
      const masterDb = databaseService.getMasterDb();

      // Get database statistics
      const [stats] = await masterDb.execute(`
        SELECT 
          COUNT(*) as total_databases,
          COUNT(CASE WHEN is_active = true THEN 1 END) as active_databases,
          COUNT(CASE WHEN is_default = true THEN 1 END) as default_databases,
          COUNT(CASE WHEN health_status = 'healthy' THEN 1 END) as healthy_databases,
          COUNT(CASE WHEN health_status = 'unhealthy' THEN 1 END) as unhealthy_databases
        FROM user_databases 
        WHERE user_id = $1
      `, [userId]);

      // Get connection statistics
      const connectionStats = databaseService.getConnectionStats();

      // Get health status for user's database
      const healthStatus = await databaseService.getHealthStatus(userId);

      // Get recent activity
      const [recentActivity] = await masterDb.execute(`
        SELECT 
          action,
          created_at,
          details
        FROM audit_logs 
        WHERE user_id = $1 
          AND resource_type = 'user_database'
          AND created_at >= NOW() - INTERVAL '7 days'
        ORDER BY created_at DESC
        LIMIT 10
      `, [userId]);

      const response: ApiResponse = {
        success: true,
        data: {
          database_stats: stats.rows[0],
          connection_stats: {
            user_connected: connectionStats.active_users.includes(userId),
            master_connected: connectionStats.master_connected,
            total_connections: connectionStats.total_pools,
          },
          health_status: healthStatus,
          recent_activity: recentActivity.rows,
        },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get database stats:', error);
      throw createError.database('Failed to retrieve database statistics');
    }
  });

  /**
   * Backup database
   * POST /api/v1/database/:databaseId/backup
   */
  backupDatabase = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const databaseId = req.params.databaseId;
    const { format = 'json', include_schema = true } = req.body;

    try {
      const masterDb = databaseService.getMasterDb();

      // Verify ownership
      const [existingDb] = await masterDb.execute(`
        SELECT * FROM user_databases 
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      if (!existingDb.rows[0]) {
        throw createError.notFound('Database configuration');
      }

      // This would implement actual backup logic
      // For now, create a placeholder backup job
      const backupJob = {
        id: `backup_${Date.now()}`,
        database_id: databaseId,
        format,
        include_schema,
        status: 'completed',
        created_at: new Date(),
        file_size: 1024 * 1024, // 1MB placeholder
      };

      // Update last backup time
      await masterDb.execute(`
        UPDATE user_databases 
        SET last_backup_at = NOW(), updated_at = NOW()
        WHERE id = $1
      `, [databaseId]);

      // Log audit event
      await auditService.logDatabase({
        user_id: userId,
        action: 'backup',
        database_id: databaseId,
        database_type: existingDb.rows[0].type,
        success: true,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        data: { backup_job: backupJob },
        message: 'Database backup created successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(201).json(response);
    } catch (error: any) {
      logger.error('Failed to backup database:', error);
      if (error instanceof Error && error.message.includes('not found')) {
        throw error;
      }
      throw createError.database('Failed to create database backup');
    }
  });

  /**
   * Get database health check
   * GET /api/v1/database/:databaseId/health
   */
  getDatabaseHealth = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const databaseId = req.params.databaseId;

    try {
      const masterDb = databaseService.getMasterDb();

      // Verify ownership
      const [existingDb] = await masterDb.execute(`
        SELECT * FROM user_databases 
        WHERE id = $1 AND user_id = $2
      `, [databaseId, userId]);

      if (!existingDb.rows[0]) {
        throw createError.notFound('Database configuration');
      }

      // Get health status
      const healthStatus = await databaseService.getHealthStatus(userId);

      // Update health status in database
      await masterDb.execute(`
        UPDATE user_databases 
        SET health_status = $1, last_health_check = NOW()
        WHERE id = $2
      `, [healthStatus.status, databaseId]);

      const response: ApiResponse = {
        success: true,
        data: { health: healthStatus },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get database health:', error);
      if (error instanceof Error && error.message.includes('not found')) {
        throw error;
      }
      throw createError.database('Failed to check database health');
    }
  });

  /**
   * Get supported database types
   * GET /api/v1/database/types
   */
  getSupportedTypes = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const supportedTypes = [
      {
        type: 'local',
        name: 'Local PostgreSQL',
        description: 'Use the same PostgreSQL instance as the master database',
        icon: 'database',
        features: ['Multi-tenant', 'Automatic setup', 'No additional configuration'],
        limitations: ['Limited to PostgreSQL', 'Shared resources'],
      },
      {
        type: 'cloud_postgres',
        name: 'Cloud PostgreSQL',
        description: 'Connect to external PostgreSQL instance (AWS RDS, Google Cloud SQL, etc.)',
        icon: 'cloud',
        features: ['Full control', 'Dedicated resources', 'Scalable'],
        limitations: ['Requires configuration', 'Additional costs'],
        connection_fields: [
          { name: 'host', type: 'string', required: true, description: 'Database host' },
          { name: 'port', type: 'number', required: true, default: 5432, description: 'Database port' },
          { name: 'database', type: 'string', required: true, description: 'Database name' },
          { name: 'username', type: 'string', required: true, description: 'Username' },
          { name: 'password', type: 'password', required: true, description: 'Password' },
          { name: 'ssl', type: 'boolean', required: false, default: true, description: 'Use SSL connection' },
        ],
      },
      {
        type: 'cloud_mysql',
        name: 'Cloud MySQL',
        description: 'Connect to external MySQL instance',
        icon: 'cloud',
        features: ['Wide compatibility', 'Popular choice', 'Good performance'],
        limitations: ['Different SQL dialect', 'Limited advanced features'],
        status: 'coming_soon',
      },
      {
        type: 'cloud_mongodb',
        name: 'Cloud MongoDB',
        description: 'Connect to external MongoDB instance',
        icon: 'cloud',
        features: ['NoSQL flexibility', 'Document storage', 'Horizontal scaling'],
        limitations: ['Different query language', 'Schema-less'],
        status: 'coming_soon',
      },
    ];

    const response: ApiResponse = {
      success: true,
      data: { supported_types: supportedTypes },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Validate connection configuration based on database type
   * @param type - Database type
   * @param connection - Connection configuration
   */
  private validateConnectionConfig(type: string, connection: any): void {
    switch (type) {
      case 'local':
        // Local doesn't require additional configuration
        break;
      
      case 'cloud_postgres':
        if (!connection.host || !connection.database || !connection.username || !connection.password) {
          throw createError.validation('PostgreSQL connection requires host, database, username, and password', []);
        }
        if (connection.port && (connection.port < 1 || connection.port > 65535)) {
          throw createError.validation('Port must be between 1 and 65535', []);
        }
        break;
      
      case 'cloud_mysql':
      case 'cloud_mongodb':
        throw createError.validation(`Database type ${type} is not yet supported`, []);
      
      default:
        throw createError.validation(`Unsupported database type: ${type}`, []);
    }
  }

  /**
   * Get connection summary without sensitive details
   * @param type - Database type
   */
  private getConnectionSummary(type: string): string {
    switch (type) {
      case 'local':
        return 'Local PostgreSQL (shared instance)';
      case 'cloud_postgres':
        return 'External PostgreSQL';
      case 'cloud_mysql':
        return 'External MySQL';
      case 'cloud_mongodb':
        return 'External MongoDB';
      default:
        return 'Unknown';
    }
  }

  /**
   * Sanitize connection configuration for API responses
   * @param config - Raw connection configuration
   */
  private sanitizeConnectionConfig(config: any): any {
    if (!config) return null;

    const sanitized = { ...config };
    
    // Remove sensitive fields
    delete sanitized.password;
    delete sanitized.secret;
    delete sanitized.key;
    
    // Mask sensitive values
    if (sanitized.username) {
      sanitized.username = this.maskString(sanitized.username);
    }
    
    return sanitized;
  }

  /**
   * Mask string for security
   * @param str - String to mask
   */
  private maskString(str: string): string {
    if (str.length <= 3) return '*'.repeat(str.length);
    return str.substring(0, 2) + '*'.repeat(str.length - 4) + str.substring(str.length - 2);
  }
}

// Create controller instance
export const databaseController = new DatabaseController();

/**
 * Validation Rules
 */

// Create database validation
export const createDatabaseValidation = [
  body('name')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Database name must be between 1 and 255 characters'),
  body('type')
    .isIn(['local', 'cloud_postgres', 'cloud_mysql', 'cloud_mongodb'])
    .withMessage('Invalid database type'),
  body('connection')
    .isObject()
    .withMessage('Connection configuration is required')
    .custom((connection, { req }) => {
      const type = req.body.type;
      if (type === 'cloud_postgres') {
        if (!connection.host || !connection.database || !connection.username || !connection.password) {
          throw new Error('PostgreSQL requires host, database, username, and password');
        }
      }
      return true;
    }),
];

// Update database validation
export const updateDatabaseValidation = [
  param('databaseId')
    .isUUID()
    .withMessage('Database ID must be a valid UUID'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Database name must be between 1 and 255 characters'),
  body('connection')
    .optional()
    .isObject()
    .withMessage('Connection must be an object'),
  body('is_active')
    .optional()
    .isBoolean()
    .withMessage('is_active must be a boolean'),
];

// Test connection validation
export const testConnectionValidation = [
  body('type')
    .isIn(['local', 'cloud_postgres', 'cloud_mysql', 'cloud_mongodb'])
    .withMessage('Invalid database type'),
  body('connection')
    .isObject()
    .withMessage('Connection configuration is required'),
];

// Database ID param validation
export const databaseIdValidation = [
  param('databaseId')
    .isUUID()
    .withMessage('Database ID must be a valid UUID'),
];

// Backup validation
export const backupValidation = [
  param('databaseId')
    .isUUID()
    .withMessage('Database ID must be a valid UUID'),
  body('format')
    .optional()
    .isIn(['json', 'sql', 'csv'])
    .withMessage('Format must be json, sql, or csv'),
  body('include_schema')
    .optional()
    .isBoolean()
    .withMessage('include_schema must be a boolean'),
];