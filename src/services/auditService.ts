import { databaseService } from '@/services/databaseService';
import { logger } from '@/utils/logger';
import * as masterSchema from '@/database/schemas/master.schema';
import type { AuditEvent, NewAuditLog } from '@/types/database.types';

/**
 * Audit Service
 * Handles audit logging for security, compliance, and debugging
 * Tracks all user actions and system events
 */
class AuditService {
  private batchSize = 100;
  private flushInterval = 30000; // 30 seconds
  private auditQueue: NewAuditLog[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private isEnabled = true;

  constructor() {
    this.startBatchProcessor();
  }

  /**
   * Log an audit event
   * @param event - Audit event data
   */
  async log(event: AuditEvent): Promise<void> {
    if (!this.isEnabled) {
      return;
    }

    try {
      const auditLog: NewAuditLog = {
        user_id: event.user_id || null,
        action: event.action,
        resource_type: event.resource_type,
        resource_id: event.resource_id || null,
        details: event.details || {},
        ip_address: event.ip_address || null,
        user_agent: event.user_agent || null,
        created_at: new Date(),
      };

      // Add to batch queue
      this.auditQueue.push(auditLog);

      // Force flush if queue is full
      if (this.auditQueue.length >= this.batchSize) {
        await this.flushBatch();
      }

      logger.debug('Audit event queued:', {
        action: event.action,
        resource: event.resource_type,
        user: event.user_id,
      });
    } catch (error) {
      logger.error('Failed to queue audit event:', error);
    }
  }

  /**
   * Log user authentication events
   */
  async logAuth(event: {
    user_id?: string;
    action: 'login' | 'logout' | 'register' | 'password_change' | 'token_refresh';
    success: boolean;
    ip_address?: string;
    user_agent?: string;
    details?: any;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `auth_${event.action}`,
      resource_type: 'user_session',
      details: {
        success: event.success,
        ...event.details,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });
  }

  /**
   * Log project-related events
   */
  async logProject(event: {
    user_id: string;
    action: 'create' | 'update' | 'delete' | 'archive' | 'restore';
    project_id: string;
    changes?: any;
    ip_address?: string;
    user_agent?: string;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `project_${event.action}`,
      resource_type: 'project',
      resource_id: event.project_id,
      details: {
        changes: event.changes,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });
  }

  /**
   * Log conversation events
   */
  async logConversation(event: {
    user_id: string;
    action: 'create' | 'update' | 'delete' | 'archive' | 'message_sent';
    conversation_id: string;
    project_id?: string;
    message_count?: number;
    tokens_used?: number;
    ip_address?: string;
    user_agent?: string;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `conversation_${event.action}`,
      resource_type: 'conversation',
      resource_id: event.conversation_id,
      details: {
        project_id: event.project_id,
        message_count: event.message_count,
        tokens_used: event.tokens_used,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });
  }

  /**
   * Log database operations
   */
  async logDatabase(event: {
    user_id: string;
    action: 'create' | 'update' | 'delete' | 'connect' | 'disconnect' | 'test';
    database_id?: string;
    database_type?: string;
    success: boolean;
    ip_address?: string;
    user_agent?: string;
    error?: string;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `database_${event.action}`,
      resource_type: 'user_database',
      resource_id: event.database_id,
      details: {
        database_type: event.database_type,
        success: event.success,
        error: event.error,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });
  }

  /**
   * Log export/import operations
   */
  async logExport(event: {
    user_id: string;
    action: 'export_create' | 'export_download' | 'import_create' | 'import_complete';
    job_id: string;
    format?: string;
    file_size?: number;
    records_count?: number;
    ip_address?: string;
    user_agent?: string;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: event.action,
      resource_type: 'export_job',
      resource_id: event.job_id,
      details: {
        format: event.format,
        file_size: event.file_size,
        records_count: event.records_count,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });
  }

  /**
   * Log security events
   */
  async logSecurity(event: {
    user_id?: string;
    action: 'suspicious_activity' | 'rate_limit_exceeded' | 'unauthorized_access' | 'data_breach_attempt';
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    ip_address?: string;
    user_agent?: string;
    details?: any;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `security_${event.action}`,
      resource_type: 'security_event',
      details: {
        severity: event.severity,
        description: event.description,
        ...event.details,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });

    // Log high severity events immediately
    if (event.severity === 'high' || event.severity === 'critical') {
      await this.flushBatch();
      logger.warn(`Security event [${event.severity}]:`, {
        action: event.action,
        user: event.user_id,
        description: event.description,
        ip: event.ip_address,
      });
    }
  }

  /**
   * Log admin operations
   */
  async logAdmin(event: {
    user_id: string;
    action: string;
    target_user_id?: string;
    resource_type: string;
    resource_id?: string;
    changes?: any;
    ip_address?: string;
    user_agent?: string;
  }): Promise<void> {
    await this.log({
      user_id: event.user_id,
      action: `admin_${event.action}`,
      resource_type: event.resource_type,
      resource_id: event.resource_id,
      details: {
        target_user_id: event.target_user_id,
        changes: event.changes,
        admin_operation: true,
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
    });

    // Always flush admin operations immediately
    await this.flushBatch();
  }

  /**
   * Get audit logs with filtering
   */
  async getAuditLogs(filters: {
    user_id?: string;
    action?: string;
    resource_type?: string;
    resource_id?: string;
    date_from?: Date;
    date_to?: Date;
    limit?: number;
    offset?: number;
  } = {}): Promise<{
    logs: any[];
    total: number;
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      
      let query = masterDb.select().from(masterSchema.auditLogs);
      let countQuery = masterDb.select({ count: masterSchema.auditLogs.id }).from(masterSchema.auditLogs);

      // Apply filters
      const conditions: any[] = [];

      if (filters.user_id) {
        conditions.push(`user_id = '${filters.user_id}'`);
      }

      if (filters.action) {
        conditions.push(`action = '${filters.action}'`);
      }

      if (filters.resource_type) {
        conditions.push(`resource_type = '${filters.resource_type}'`);
      }

      if (filters.resource_id) {
        conditions.push(`resource_id = '${filters.resource_id}'`);
      }

      if (filters.date_from) {
        conditions.push(`created_at >= '${filters.date_from.toISOString()}'`);
      }

      if (filters.date_to) {
        conditions.push(`created_at <= '${filters.date_to.toISOString()}'`);
      }

      // Build WHERE clause
      if (conditions.length > 0) {
        const whereClause = conditions.join(' AND ');
        query = query.where(whereClause as any);
        countQuery = countQuery.where(whereClause as any);
      }

      // Apply ordering
      query = query.orderBy(masterSchema.auditLogs.created_at, 'desc');

      // Apply pagination
      if (filters.limit) {
        query = query.limit(filters.limit);
      }
      if (filters.offset) {
        query = query.offset(filters.offset);
      }

      const [logs, [{ count }]] = await Promise.all([
        query,
        countQuery
      ]);

      return {
        logs,
        total: Array.isArray(count) ? count.length : Number(count) || 0,
      };
    } catch (error) {
      logger.error('Failed to get audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit statistics
   */
  async getAuditStats(period: '24h' | '7d' | '30d' = '24h'): Promise<{
    total_events: number;
    events_by_action: Record<string, number>;
    events_by_resource: Record<string, number>;
    unique_users: number;
    timeline: Array<{
      date: string;
      count: number;
    }>;
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      
      // Calculate date range
      const now = new Date();
      const periodHours = period === '24h' ? 24 : period === '7d' ? 168 : 720;
      const startDate = new Date(now.getTime() - (periodHours * 60 * 60 * 1000));

      // Get basic stats
      const [totalEvents] = await masterDb.execute(`
        SELECT COUNT(*) as total
        FROM audit_logs 
        WHERE created_at >= $1
      `, [startDate]);

      const [uniqueUsers] = await masterDb.execute(`
        SELECT COUNT(DISTINCT user_id) as unique_users
        FROM audit_logs 
        WHERE created_at >= $1 AND user_id IS NOT NULL
      `, [startDate]);

      // Get events by action
      const eventsByAction = await masterDb.execute(`
        SELECT action, COUNT(*) as count
        FROM audit_logs 
        WHERE created_at >= $1
        GROUP BY action
        ORDER BY count DESC
        LIMIT 20
      `, [startDate]);

      // Get events by resource type
      const eventsByResource = await masterDb.execute(`
        SELECT resource_type, COUNT(*) as count
        FROM audit_logs 
        WHERE created_at >= $1
        GROUP BY resource_type
        ORDER BY count DESC
        LIMIT 20
      `, [startDate]);

      // Get timeline
      const timelineInterval = period === '24h' ? 'hour' : 'day';
      const timeline = await masterDb.execute(`
        SELECT 
          DATE_TRUNC('${timelineInterval}', created_at) as date,
          COUNT(*) as count
        FROM audit_logs 
        WHERE created_at >= $1
        GROUP BY DATE_TRUNC('${timelineInterval}', created_at)
        ORDER BY date
      `, [startDate]);

      return {
        total_events: Number(totalEvents.rows[0]?.total || 0),
        unique_users: Number(uniqueUsers.rows[0]?.unique_users || 0),
        events_by_action: eventsByAction.rows.reduce((acc: any, row: any) => {
          acc[row.action] = Number(row.count);
          return acc;
        }, {}),
        events_by_resource: eventsByResource.rows.reduce((acc: any, row: any) => {
          acc[row.resource_type] = Number(row.count);
          return acc;
        }, {}),
        timeline: timeline.rows.map((row: any) => ({
          date: row.date,
          count: Number(row.count),
        })),
      };
    } catch (error) {
      logger.error('Failed to get audit stats:', error);
      throw error;
    }
  }

  /**
   * Search audit logs
   */
  async searchAuditLogs(searchTerm: string, filters: {
    user_id?: string;
    resource_type?: string;
    date_from?: Date;
    date_to?: Date;
    limit?: number;
  } = {}): Promise<any[]> {
    try {
      const masterDb = databaseService.getMasterDb();

      let query = `
        SELECT * FROM audit_logs 
        WHERE (
          action ILIKE $1 OR 
          resource_type ILIKE $1 OR 
          resource_id ILIKE $1 OR
          details::text ILIKE $1
        )
      `;
      
      const params: any[] = [`%${searchTerm}%`];
      let paramIndex = 2;

      if (filters.user_id) {
        query += ` AND user_id = $${paramIndex}`;
        params.push(filters.user_id);
        paramIndex++;
      }

      if (filters.resource_type) {
        query += ` AND resource_type = $${paramIndex}`;
        params.push(filters.resource_type);
        paramIndex++;
      }

      if (filters.date_from) {
        query += ` AND created_at >= $${paramIndex}`;
        params.push(filters.date_from);
        paramIndex++;
      }

      if (filters.date_to) {
        query += ` AND created_at <= $${paramIndex}`;
        params.push(filters.date_to);
        paramIndex++;
      }

      query += ` ORDER BY created_at DESC`;

      if (filters.limit) {
        query += ` LIMIT $${paramIndex}`;
        params.push(filters.limit);
      }

      const result = await masterDb.execute(query, params);
      return result.rows;
    } catch (error) {
      logger.error('Failed to search audit logs:', error);
      throw error;
    }
  }

  /**
   * Start batch processor
   */
  private startBatchProcessor(): void {
    this.flushTimer = setInterval(async () => {
      if (this.auditQueue.length > 0) {
        await this.flushBatch();
      }
    }, this.flushInterval);
  }

  /**
   * Flush current batch to database
   */
  private async flushBatch(): Promise<void> {
    if (this.auditQueue.length === 0) {
      return;
    }

    const batch = this.auditQueue.splice(0, this.batchSize);
    
    try {
      const masterDb = databaseService.getMasterDb();
      
      // Insert batch
      await masterDb
        .insert(masterSchema.auditLogs)
        .values(batch);

      logger.debug(`Flushed ${batch.length} audit events to database`);
    } catch (error) {
      logger.error('Failed to flush audit batch:', error);
      
      // Re-queue failed events (with limit to prevent memory issues)
      if (this.auditQueue.length < 1000) {
        this.auditQueue.unshift(...batch);
      }
    }
  }

  /**
   * Enable/disable audit logging
   */
  setEnabled(enabled: boolean): void {
    this.isEnabled = enabled;
    logger.info(`Audit logging ${enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Get audit service status
   */
  getStatus(): {
    enabled: boolean;
    queue_size: number;
    batch_size: number;
    flush_interval: number;
  } {
    return {
      enabled: this.isEnabled,
      queue_size: this.auditQueue.length,
      batch_size: this.batchSize,
      flush_interval: this.flushInterval,
    };
  }

  /**
   * Cleanup old audit logs
   */
  async cleanup(retentionDays: number = 90): Promise<number> {
    try {
      const masterDb = databaseService.getMasterDb();
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await masterDb.execute(`
        DELETE FROM audit_logs 
        WHERE created_at < $1
      `, [cutoffDate]);

      const deletedCount = result.rowCount || 0;
      
      logger.info(`Cleaned up ${deletedCount} old audit logs older than ${retentionDays} days`);
      return deletedCount;
    } catch (error) {
      logger.error('Failed to cleanup audit logs:', error);
      throw error;
    }
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down audit service...');
      
      // Stop the flush timer
      if (this.flushTimer) {
        clearInterval(this.flushTimer);
        this.flushTimer = null;
      }

      // Flush remaining events
      if (this.auditQueue.length > 0) {
        await this.flushBatch();
      }

      logger.info('Audit service shutdown completed');
    } catch (error) {
      logger.error('Error during audit service shutdown:', error);
    }
  }
}

// Export singleton instance
export const auditService = new AuditService();