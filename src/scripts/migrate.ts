import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { config } from '../config/environment';
import { logger } from '../utils/logger';
import fs from 'fs';
import path from 'path';

/**
 * Database Migration Script
 * Handles both master and tenant database migrations
 */
class MigrationRunner {
  private masterConnection: postgres.Sql | null = null;

  async run(): Promise<void> {
    try {
      logger.info('Starting database migrations...');

      // Run master database migrations
      await this.runMasterMigrations();

      // Create default admin user if needed
      await this.createDefaultUser();

      // Run initial setup SQL
      await this.runInitialSetup();

      logger.info('All migrations completed successfully');
      process.exit(0);

    } catch (error) {
      logger.error('Migration failed:', error);
      process.exit(1);
    }
  }

  /**
   * Run master database migrations
   */
  private async runMasterMigrations(): Promise<void> {
    try {
      logger.info('Running master database migrations...');

      this.masterConnection = postgres(config.database.masterUrl, {
        max: 1,
        ssl: config.node.env === 'production' ? 'require' : false,
      });

      const db = drizzle(this.masterConnection);

      // Check if migrations folder exists
      const migrationsPath = path.join(__dirname, '../database/migrations');
      if (!fs.existsSync(migrationsPath)) {
        logger.warn('No migrations folder found, creating...');
        fs.mkdirSync(migrationsPath, { recursive: true });
      }

      // Run migrations
      await migrate(db, { migrationsFolder: migrationsPath });
      
      logger.info('Master database migrations completed');

    } catch (error) {
      logger.error('Master database migration failed:', error);
      throw error;
    }
  }

  /**
   * Create default admin user
   */
  private async createDefaultUser(): Promise<void> {
    try {
      if (!this.masterConnection) {
        throw new Error('Master connection not established');
      }

      logger.info('Creating default admin user...');

      // Check if default user already exists
      const existingUser = await this.masterConnection`
        SELECT id FROM users WHERE email = 'admin@localhost'
      `;

      if (existingUser.length > 0) {
        logger.info('Default admin user already exists');
        return;
      }

      // Create default admin user
      const bcrypt = require('bcryptjs');
      const defaultPassword = 'admin123'; // Change this in production!
      const passwordHash = await bcrypt.hash(defaultPassword, 12);

      await this.masterConnection`
        INSERT INTO users (email, password_hash, name, role, email_verified, is_active)
        VALUES ('admin@localhost', ${passwordHash}, 'Admin User', 'admin', true, true)
      `;

      logger.info('Default admin user created (email: admin@localhost, password: admin123)');
      logger.warn('⚠️  IMPORTANT: Change the default password in production!');

    } catch (error) {
      logger.error('Failed to create default user:', error);
      throw error;
    }
  }

  /**
   * Run initial setup SQL
   */
  private async runInitialSetup(): Promise<void> {
    try {
      if (!this.masterConnection) {
        throw new Error('Master connection not established');
      }

      logger.info('Running initial setup...');

      // Create extensions if needed
      await this.masterConnection`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`;
      await this.masterConnection`CREATE EXTENSION IF NOT EXISTS "pg_trgm"`;

      // Create indexes for better performance
      await this.createPerformanceIndexes();

      // Set up audit triggers
      await this.setupAuditTriggers();

      // Create system configuration entries
      await this.createSystemConfig();

      logger.info('Initial setup completed');

    } catch (error) {
      logger.error('Initial setup failed:', error);
      throw error;
    }
  }

  /**
   * Create performance indexes
   */
  private async createPerformanceIndexes(): Promise<void> {
    try {
      if (!this.masterConnection) return;

      logger.info('Creating performance indexes...');

      const indexes = [
        // User indexes
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = true',
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at ON users(created_at)',
        
        // Session indexes
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at) WHERE expires_at > NOW()',
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_active ON user_sessions(user_id, expires_at) WHERE expires_at > NOW()',
        
        // Database config indexes
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_databases_user_active ON user_databases(user_id) WHERE is_active = true',
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_databases_health ON user_databases(health_status, last_health_check)',
        
        // Audit logs indexes
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_date ON audit_logs(user_id, created_at)',
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id)',
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_date ON audit_logs(action, created_at)',
      ];

      for (const indexSql of indexes) {
        try {
          await this.masterConnection`${indexSql}`;
        } catch (error: any) {
          // Ignore if index already exists
          if (!error.message.includes('already exists')) {
            logger.warn(`Failed to create index: ${error.message}`);
          }
        }
      }

      logger.info('Performance indexes created');

    } catch (error) {
      logger.error('Failed to create performance indexes:', error);
      throw error;
    }
  }

  /**
   * Setup audit triggers
   */
  private async setupAuditTriggers(): Promise<void> {
    try {
      if (!this.masterConnection) return;

      logger.info('Setting up audit triggers...');

      // Create audit trigger function
      await this.masterConnection`
        CREATE OR REPLACE FUNCTION audit_trigger_function()
        RETURNS TRIGGER AS $
        BEGIN
          IF TG_OP = 'INSERT' THEN
            INSERT INTO audit_logs (action, resource_type, resource_id, details, created_at)
            VALUES ('create', TG_TABLE_NAME, NEW.id::text, row_to_json(NEW), NOW());
            RETURN NEW;
          ELSIF TG_OP = 'UPDATE' THEN
            INSERT INTO audit_logs (action, resource_type, resource_id, details, created_at)
            VALUES ('update', TG_TABLE_NAME, NEW.id::text, 
                   jsonb_build_object('old', row_to_json(OLD), 'new', row_to_json(NEW)), NOW());
            RETURN NEW;
          ELSIF TG_OP = 'DELETE' THEN
            INSERT INTO audit_logs (action, resource_type, resource_id, details, created_at)
            VALUES ('delete', TG_TABLE_NAME, OLD.id::text, row_to_json(OLD), NOW());
            RETURN OLD;
          END IF;
          RETURN NULL;
        END;
        $ LANGUAGE plpgsql;
      `;

      // Create triggers for important tables
      const tables = ['users', 'user_databases', 'export_jobs'];
      
      for (const table of tables) {
        await this.masterConnection`
          DROP TRIGGER IF EXISTS audit_trigger ON ${this.masterConnection(table)}
        `;
        
        await this.masterConnection`
          CREATE TRIGGER audit_trigger
          AFTER INSERT OR UPDATE OR DELETE ON ${this.masterConnection(table)}
          FOR EACH ROW EXECUTE FUNCTION audit_trigger_function()
        `;
      }

      logger.info('Audit triggers created');

    } catch (error) {
      logger.error('Failed to setup audit triggers:', error);
      throw error;
    }
  }

  /**
   * Create system configuration entries
   */
  private async createSystemConfig(): Promise<void> {
    try {
      if (!this.masterConnection) return;

      logger.info('Creating system configuration...');

      const configs = [
        {
          key: 'app_version',
          value: '1.0.0',
          description: 'Application version'
        },
        {
          key: 'maintenance_mode',
          value: false,
          description: 'Enable maintenance mode'
        },
        {
          key: 'max_connections_per_user',
          value: 5,
          description: 'Maximum WebSocket connections per user'
        },
        {
          key: 'export_retention_days',
          value: 7,
          description: 'How long to keep export files (days)'
        },
        {
          key: 'audit_retention_days',
          value: 90,
          description: 'How long to keep audit logs (days)'
        },
        {
          key: 'max_file_size',
          value: 10485760,
          description: 'Maximum file upload size in bytes (10MB)'
        },
      ];

      for (const config of configs) {
        await this.masterConnection`
          INSERT INTO system_config (config_key, config_value, description, is_active)
          VALUES (${config.key}, ${JSON.stringify(config.value)}, ${config.description}, true)
          ON CONFLICT (config_key) DO UPDATE SET
            config_value = EXCLUDED.config_value,
            updated_at = NOW()
        `;
      }

      logger.info('System configuration created');

    } catch (error) {
      logger.error('Failed to create system configuration:', error);
      throw error;
    }
  }

  /**
   * Create tenant database schema
   * @param userId - User ID
   */
  async createTenantSchema(userId: string): Promise<void> {
    try {
      if (!this.masterConnection) {
        throw new Error('Master connection not established');
      }

      logger.info(`Creating tenant schema for user: ${userId}`);

      const schemaName = `tenant_${userId.replace(/-/g, '_')}`;

      // Create schema
      await this.masterConnection`CREATE SCHEMA IF NOT EXISTS ${this.masterConnection(schemaName)}`;

      // Set search path and create tables
      await this.masterConnection`SET search_path TO ${this.masterConnection(schemaName)}, public`;

      // Create tenant tables (these would be the actual table creation SQL)
      await this.createTenantTables();

      // Reset search path
      await this.masterConnection`SET search_path TO public`;

      logger.info(`Tenant schema created: ${schemaName}`);

    } catch (error) {
      logger.error(`Failed to create tenant schema for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Create tenant tables
   */
  private async createTenantTables(): Promise<void> {
    if (!this.masterConnection) return;

    // Projects table
    await this.masterConnection`
      CREATE TABLE IF NOT EXISTS projects (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'active',
        priority VARCHAR(50) DEFAULT 'medium',
        color VARCHAR(7) DEFAULT '#3B82F6',
        icon VARCHAR(50),
        tags JSONB DEFAULT '[]',
        settings JSONB DEFAULT '{}',
        collaborators JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        archived_at TIMESTAMP,
        completed_at TIMESTAMP,
        deadline TIMESTAMP,
        metadata JSONB DEFAULT '{}'
      )
    `;

    // Conversations table
    await this.masterConnection`
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        summary TEXT,
        key_topics TEXT,
        importance_level INTEGER DEFAULT 3,
        status VARCHAR(50) DEFAULT 'active',
        conversation_type VARCHAR(50) DEFAULT 'chat',
        message_count INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0,
        estimated_cost DECIMAL(10,4) DEFAULT 0,
        tags JSONB DEFAULT '[]',
        participants JSONB DEFAULT '[]',
        settings JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        last_message_at TIMESTAMP,
        archived_at TIMESTAMP,
        template_data JSONB
      )
    `;

    // Messages table
    await this.masterConnection`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        parent_message_id UUID REFERENCES messages(id),
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        content_type VARCHAR(50) DEFAULT 'text',
        tokens_used INTEGER,
        model_used VARCHAR(100),
        processing_time_ms INTEGER,
        cost DECIMAL(10,6),
        status VARCHAR(50) DEFAULT 'completed',
        error_details TEXT,
        attachments JSONB DEFAULT '[]',
        reactions JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        edited_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        deleted_at TIMESTAMP
      )
    `;

    // Create indexes for better performance
    await this.masterConnection`CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status)`;
    await this.masterConnection`CREATE INDEX IF NOT EXISTS idx_conversations_project ON conversations(project_id)`;
    await this.masterConnection`CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status)`;
    await this.masterConnection`CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)`;
    await this.masterConnection`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`;
  }

  /**
   * Verify database setup
   */
  async verify(): Promise<void> {
    try {
      if (!this.masterConnection) {
        throw new Error('Master connection not established');
      }

      logger.info('Verifying database setup...');

      // Check if essential tables exist
      const tables = await this.masterConnection`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('users', 'user_sessions', 'user_databases', 'audit_logs', 'system_config')
      `;

      const expectedTables = ['users', 'user_sessions', 'user_databases', 'audit_logs', 'system_config'];
      const existingTables = tables.map(t => t.table_name);
      const missingTables = expectedTables.filter(t => !existingTables.includes(t));

      if (missingTables.length > 0) {
        throw new Error(`Missing tables: ${missingTables.join(', ')}`);
      }

      // Check if default user exists
      const userCount = await this.masterConnection`
        SELECT COUNT(*) as count FROM users WHERE role = 'admin'
      `;

      if (parseInt(userCount[0].count) === 0) {
        logger.warn('No admin users found');
      }

      logger.info('Database verification completed successfully');

    } catch (error) {
      logger.error('Database verification failed:', error);
      throw error;
    }
  }

  /**
   * Cleanup connections
   */
  async cleanup(): Promise<void> {
    if (this.masterConnection) {
      await this.masterConnection.end();
      this.masterConnection = null;
    }
  }
}

/**
 * Run migrations
 */
async function main() {
  const runner = new MigrationRunner();
  
  try {
    await runner.run();
    await runner.verify();
  } finally {
    await runner.cleanup();
  }
}

// Run migrations if this script is executed directly
if (require.main === module) {
  main().catch((error) => {
    console.error('Migration script failed:', error);
    process.exit(1);
  });
}

export { MigrationRunner };