import { eq, and, desc, gte, lte, like, sql } from 'drizzle-orm';
import { databaseService } from '@/services/databaseService';
import { logger, auditLogger } from '@/utils/logger';
import * as masterSchema from '@/database/schemas/master.schema';
import { config } from '@/config/environment';

/**
 * Audit Service
 * Handles comprehensive audit logging for security, compliance, and monitoring
 */

interface AuditEntry {
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'auth' | 'data' | 'system' | 'security' | 'api' | 'file';
}

interface AuthAuditEntry {
  user_id?: string;
  action: 'login' | 'logout' | 'register' | 'password_change' | 'password_reset' | 'token_refresh' | 'failed_login' | 'account_locked';
  ip_address?: string;
  user_agent?: string;
  details?: Record<string, any>;
}

interface ConversationAuditEntry {
  user_id: string;
  action: 'create' | 'update' | 'delete' | 'message_sent' | 'message_received' | 'export';
  conversation_id?: string;
  project_id?: string;
  message_id?: string;
  tokens_used?: number;
  ip_address?: string;
  user_agent?: string;
}

interface DataAuditEntry {
  user_id: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'export' | 'import' | 'backup' | 'restore';
  table_name: string;
  record_id?: string;
  field_changes?: Record<string, { old: any; new: any }>;
  ip_address?: string;
  user_agent?: string;
}

interface SystemAuditEntry {
  action: 'startup' | 'shutdown' | 'migration' | 'backup' | 'maintenance' | 'error' | 'performance_alert';
  component: string;
  details?: Record<string, any>;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

interface SecurityAuditEntry {
  user_id?: string;
  action: 'suspicious_activity' | 'rate_limit_exceeded' | 'unauthorized_access' | 'malicious_request' | 'security_scan';
  threat_type?: string;
  ip_address?: string;
  user_agent?: string;
  details?: Record<string, any>;
}

interface AuditQuery {
  user_id?: string;
  action?: string;
  resource_type?: string;
  category?: string;
  severity?: string;
  date_from?: string;
  date_to?: string;
  ip_address?: string;
  limit?: number;
  offset?: number;
}

class AuditService {
  private batchEntries: AuditEntry[] = [];
  private batchInterval: NodeJS.Timeout | null = null;
  private readonly BATCH_SIZE = 100;
  private readonly BATCH_INTERVAL = 5000; // 5 seconds

  constructor() {
    this.startBatchProcessor();
    logger.info('Audit service initialized');
  }

  /**
   * Start batch processing for audit entries
   */
  private startBatchProcessor(): void {
    this.batchInterval = setInterval(async () => {
      if (this.batchEntries.length > 0) {
        await this.flushBatch();
      }
    }, this.BATCH_INTERVAL);
  }

  /**
   * Generic audit logging
   */
  async logAudit(entry: AuditEntry): Promise<void> {
    try {
      const auditEntry = {
        ...entry,
        timestamp: new Date(),
        session_id: this.generateSessionId(),
      };

      // Add to batch
      this.batchEntries.push(auditEntry);

      // Log to file immediately for critical entries
      if (entry.severity === 'critical') {
        auditLogger.error('Critical audit event', auditEntry);
        await this.flushBatch(); // Immediate flush for critical events
      } else if (entry.severity === 'high') {
        auditLogger.warn('High severity audit event', auditEntry);
      }

      // Flush batch if it's full
      if (this.batchEntries.length >= this.BATCH_SIZE) {
        await this.flushBatch();
      }
    } catch (error) {
      logger.error('Failed to log audit entry:', error);
    }
  }

  /**
   * Authentication audit logging
   */
  async logAuth(entry: AuthAuditEntry): Promise<void> {
    const severity = this.getAuthSeverity(entry.action);
    
    await this.logAudit({
      user_id: entry.user_id,
      action: entry.action,
      resource_type: 'user',
      ip_address: entry.ip_address,
      user_agent: entry.user_agent,
      details: entry.details,
      severity,
      category: 'auth',
    });

    // Additional logging for security events
    if (['failed_login', 'account_locked'].includes(entry.action)) {
      await this.logSecurity({
        user_id: entry.user_id,
        action: 'suspicious_activity',
        threat_type: entry.action,
        ip_address: entry.ip_address,
        user_agent: entry.user_agent,
        details: entry.details,
      });
    }
  }

  /**
   * Conversation audit logging
   */
  async logConversation(entry: ConversationAuditEntry): Promise<void> {
    await this.logAudit({
      user_id: entry.user_id,
      action: entry.action,
      resource_type: 'conversation',
      resource_id: entry.conversation_id,
      ip_address: entry.ip_address,
      user_agent: entry.user_agent,
      details: {
        project_id: entry.project_id,
        message_id: entry.message_id,
        tokens_used: entry.tokens_used,
      },
      severity: 'low',
      category: 'data',
    });
  }

  /**
   * Data operation audit logging
   */
  async logData(entry: DataAuditEntry): Promise<void> {
    const severity = ['delete', 'export'].includes(entry.action) ? 'medium' : 'low';

    await this.logAudit({
      user_id: entry.user_id,
      action: entry.action,
      resource_type: entry.table_name,
      resource_id: entry.record_id,
      ip_address: entry.ip_address,
      user_agent: entry.user_agent,
      details: {
        field_changes: entry.field_changes,
      },
      severity,
      category: 'data',
    });
  }

  /**
   * System event audit logging
   */
  async logSystem(entry: SystemAuditEntry): Promise<void> {
    const severity = this.mapSystemSeverity(entry.severity);

    await this.logAudit({
      action: entry.action,
      resource_type: 'system',
      resource_id: entry.component,
      details: entry.details,
      severity,
      category: 'system',
    });
  }

  /**
   * Security event audit logging
   */
  async logSecurity(entry: SecurityAuditEntry): Promise<void> {
    await this.logAudit({
      user_id: entry.user_id,
      action: entry.action,
      resource_type: 'security',
      ip_address: entry.ip_address,
      user_agent: entry.user_agent,
      details: {
        threat_type: entry.threat_type,
        ...entry.details,
      },
      severity: 'high',
      category: 'security',
    });

    // Log to security logger
    logger.logSecurityEvent(entry.action, {
      user_id: entry.user_id,
      threat_type: entry.threat_type,
      ip_address: entry.ip_address,
      details: entry.details,
    });
  }

  /**
   * File operation audit logging
   */
  async logFile(
    user_id: string,
    action: 'upload' | 'download' | 'delete',
    filename: string,
    size?: number,
    ip_address?: string
  ): Promise<void> {
    await this.logAudit({
      user_id,
      action,
      resource_type: 'file',
      resource_id: filename,
      ip_address,
      details: { size },
      severity: 'low',
      category: 'file',
    });
  }

  /**
   * API request audit logging
   */
  async logApi(
    user_id: string | undefined,
    method: string,
    endpoint: string,
    status_code: number,
    ip_address?: string,
    user_agent?: string,
    response_time?: number
  ): Promise<void> {
    const severity = status_code >= 500 ? 'high' : status_code >= 400 ? 'medium' : 'low';

    await this.logAudit({
      user_id,
      action: `${method} ${endpoint}`,
      resource_type: 'api',
      ip_address,
      user_agent,
      details: {
        method,
        endpoint,
        status_code,
        response_time,
      },
      severity,
      category: 'api',
    });
  }

  /**
   * Query audit logs
   */
  async queryAuditLogs(query: AuditQuery): Promise<{
    logs: any[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      const limit = Math.min(query.limit || 50, 1000);
      const offset = query.offset || 0;

      // Build where conditions
      const conditions = [];

      if (query.user_id) {
        conditions.push(eq(masterSchema.auditLogs.user_id, query.user_id));
      }
      if (query.action) {
        conditions.push(like(masterSchema.auditLogs.action, `%${query.action}%`));
      }
      if (query.resource_type) {
        conditions.push(eq(masterSchema.auditLogs.resource_type, query.resource_type));
      }
      if (query.category) {
        conditions.push(eq(masterSchema.auditLogs.category, query.category));
      }
      if (query.severity) {
        conditions.push(eq(masterSchema.auditLogs.severity, query.severity));
      }
      if (query.ip_address) {
        conditions.push(eq(masterSchema.auditLogs.ip_address, query.ip_address));
      }
      if (query.date_from) {
        conditions.push(gte(masterSchema.auditLogs.timestamp, new Date(query.date_from)));
      }
      if (query.date_to) {
        conditions.push(lte(masterSchema.auditLogs.timestamp, new Date(query.date_to)));
      }

      // Get total count
      const [{ count }] = await masterDb
        .select({ count: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      // Get logs with pagination
      const logs = await masterDb
        .select()
        .from(masterSchema.auditLogs)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(masterSchema.auditLogs.timestamp))
        .limit(limit)
        .offset(offset);

      const totalPages = Math.ceil(count / limit);
      const page = Math.floor(offset / limit) + 1;

      return {
        logs,
        total: count,
        page,
        totalPages,
      };
    } catch (error) {
      logger.error('Failed to query audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit statistics
   */
  async getStatistics(timeframe: 'day' | 'week' | 'month' = 'day'): Promise<{
    totalEvents: number;
    eventsByCategory: Record<string, number>;
    eventsBySeverity: Record<string, number>;
    topUsers: Array<{ user_id: string; count: number }>;
    topActions: Array<{ action: string; count: number }>;
    timeline: Array<{ date: string; count: number }>;
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      const timeframeHours = { day: 24, week: 168, month: 720 }[timeframe];
      const since = new Date(Date.now() - timeframeHours * 60 * 60 * 1000);

      // Total events
      const [{ totalEvents }] = await masterDb
        .select({ totalEvents: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(gte(masterSchema.auditLogs.timestamp, since));

      // Events by category
      const categoryStats = await masterDb
        .select({
          category: masterSchema.auditLogs.category,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(gte(masterSchema.auditLogs.timestamp, since))
        .groupBy(masterSchema.auditLogs.category);

      const eventsByCategory = categoryStats.reduce((acc, { category, count }) => {
        acc[category] = count;
        return acc;
      }, {} as Record<string, number>);

      // Events by severity
      const severityStats = await masterDb
        .select({
          severity: masterSchema.auditLogs.severity,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(gte(masterSchema.auditLogs.timestamp, since))
        .groupBy(masterSchema.auditLogs.severity);

      const eventsBySeverity = severityStats.reduce((acc, { severity, count }) => {
        acc[severity] = count;
        return acc;
      }, {} as Record<string, number>);

      // Top users
      const topUsers = await masterDb
        .select({
          user_id: masterSchema.auditLogs.user_id,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, since),
            sql`user_id IS NOT NULL`
          )
        )
        .groupBy(masterSchema.auditLogs.user_id)
        .orderBy(desc(sql`count(*)`))
        .limit(10);

      // Top actions
      const topActions = await masterDb
        .select({
          action: masterSchema.auditLogs.action,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(gte(masterSchema.auditLogs.timestamp, since))
        .groupBy(masterSchema.auditLogs.action)
        .orderBy(desc(sql`count(*)`))
        .limit(10);

      // Timeline
      const timelineQuery = timeframe === 'day' 
        ? sql`DATE_TRUNC('hour', timestamp)` 
        : sql`DATE_TRUNC('day', timestamp)`;

      const timelineStats = await masterDb
        .select({
          date: timelineQuery,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(gte(masterSchema.auditLogs.timestamp, since))
        .groupBy(timelineQuery)
        .orderBy(timelineQuery);

      const timeline = timelineStats.map(({ date, count }) => ({
        date: date.toISOString(),
        count,
      }));

      return {
        totalEvents,
        eventsByCategory,
        eventsBySeverity,
        topUsers: topUsers.map(u => ({ user_id: u.user_id!, count: u.count })),
        topActions,
        timeline,
      };
    } catch (error) {
      logger.error('Failed to get audit statistics:', error);
      throw error;
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    startDate: string,
    endDate: string
  ): Promise<{
    period: { start: string; end: string };
    summary: {
      totalEvents: number;
      securityEvents: number;
      dataAccessEvents: number;
      authenticationEvents: number;
    };
    violations: any[];
    recommendations: string[];
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      const start = new Date(startDate);
      const end = new Date(endDate);

      // Get summary statistics
      const [{ totalEvents }] = await masterDb
        .select({ totalEvents: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, start),
            lte(masterSchema.auditLogs.timestamp, end)
          )
        );

      // Security events
      const [{ securityEvents }] = await masterDb
        .select({ securityEvents: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, start),
            lte(masterSchema.auditLogs.timestamp, end),
            eq(masterSchema.auditLogs.category, 'security')
          )
        );

      // Data access events
      const [{ dataAccessEvents }] = await masterDb
        .select({ dataAccessEvents: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, start),
            lte(masterSchema.auditLogs.timestamp, end),
            eq(masterSchema.auditLogs.category, 'data')
          )
        );

      // Authentication events
      const [{ authenticationEvents }] = await masterDb
        .select({ authenticationEvents: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, start),
            lte(masterSchema.auditLogs.timestamp, end),
            eq(masterSchema.auditLogs.category, 'auth')
          )
        );

      // Find potential violations (high/critical severity events)
      const violations = await masterDb
        .select()
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, start),
            lte(masterSchema.auditLogs.timestamp, end),
            sql`severity IN ('high', 'critical')`
          )
        )
        .orderBy(desc(masterSchema.auditLogs.timestamp));

      // Generate recommendations
      const recommendations = this.generateRecommendations(violations, {
        totalEvents,
        securityEvents,
        dataAccessEvents,
        authenticationEvents,
      });

      return {
        period: { start: startDate, end: endDate },
        summary: {
          totalEvents,
          securityEvents,
          dataAccessEvents,
          authenticationEvents,
        },
        violations,
        recommendations,
      };
    } catch (error) {
      logger.error('Failed to generate compliance report:', error);
      throw error;
    }
  }

  /**
   * Flush batch entries to database
   */
  private async flushBatch(): Promise<void> {
    if (this.batchEntries.length === 0) return;

    try {
      const masterDb = databaseService.getMasterDb();
      const entries = [...this.batchEntries];
      this.batchEntries = [];

      await masterDb
        .insert(masterSchema.auditLogs)
        .values(
          entries.map(entry => ({
            user_id: entry.user_id,
            action: entry.action,
            resource_type: entry.resource_type,
            resource_id: entry.resource_id,
            ip_address: entry.ip_address,
            user_agent: entry.user_agent,
            details: entry.details,
            severity: entry.severity,
            category: entry.category,
            timestamp: new Date(),
          }))
        );

      logger.debug(`Flushed ${entries.length} audit entries to database`);
    } catch (error) {
      logger.error('Failed to flush audit batch:', error);
      // Re-add entries to batch for retry
      this.batchEntries.unshift(...this.batchEntries);
    }
  }

  /**
   * Helper methods
   */
  private getAuthSeverity(action: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (action) {
      case 'failed_login':
      case 'account_locked':
        return 'high';
      case 'password_change':
      case 'password_reset':
        return 'medium';
      default:
        return 'low';
    }
  }

  private mapSystemSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity) {
      case 'critical':
        return 'critical';
      case 'error':
        return 'high';
      case 'warning':
        return 'medium';
      default:
        return 'low';
    }
  }

  private generateSessionId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateRecommendations(violations: any[], summary: any): string[] {
    const recommendations: string[] = [];

    // Check for high number of security events
    if (summary.securityEvents > 50) {
      recommendations.push('High number of security events detected. Review security policies and implement additional monitoring.');
    }

    // Check for failed login patterns
    const failedLogins = violations.filter(v => v.action === 'failed_login');
    if (failedLogins.length > 10) {
      recommendations.push('Multiple failed login attempts detected. Consider implementing account lockout policies.');
    }

    // Check for suspicious IP patterns
    const suspiciousIPs = violations
      .filter(v => v.ip_address)
      .reduce((acc, v) => {
        acc[v.ip_address] = (acc[v.ip_address] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

    const highActivityIPs = Object.entries(suspiciousIPs)
      .filter(([, count]) => count > 5)
      .map(([ip]) => ip);

    if (highActivityIPs.length > 0) {
      recommendations.push(`High activity from IPs: ${highActivityIPs.join(', ')}. Consider IP-based restrictions.`);
    }

    // Check for data export activities
    const dataExports = violations.filter(v => v.action.includes('export'));
    if (dataExports.length > 0) {
      recommendations.push('Data export activities detected. Ensure proper authorization and data protection compliance.');
    }

    return recommendations;
  }

  /**
   * Archive old audit logs
   */
  async archiveOldLogs(retentionDays: number = 365): Promise<number> {
    try {
      const masterDb = databaseService.getMasterDb();
      const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

      // Get count of logs to be archived
      const [{ count }] = await masterDb
        .select({ count: sql<number>`cast(count(*) as int)` })
        .from(masterSchema.auditLogs)
        .where(lte(masterSchema.auditLogs.timestamp, cutoffDate));

      // In production, you would move these to an archive table or external storage
      // For now, we'll just log the operation
      logger.info(`Would archive ${count} audit logs older than ${retentionDays} days`);

      return count;
    } catch (error) {
      logger.error('Failed to archive old logs:', error);
      throw error;
    }
  }

  /**
   * Export audit logs
   */
  async exportLogs(
    query: AuditQuery,
    format: 'json' | 'csv' = 'json'
  ): Promise<string> {
    try {
      const { logs } = await this.queryAuditLogs({ ...query, limit: 10000 });

      if (format === 'csv') {
        const headers = [
          'timestamp',
          'user_id',
          'action',
          'resource_type',
          'resource_id',
          'ip_address',
          'severity',
          'category',
        ];

        const csvData = [
          headers.join(','),
          ...logs.map(log => [
            log.timestamp,
            log.user_id || '',
            log.action,
            log.resource_type,
            log.resource_id || '',
            log.ip_address || '',
            log.severity,
            log.category,
          ].map(field => `"${field}"`).join(',')),
        ].join('\n');

        return csvData;
      }

      return JSON.stringify(logs, null, 2);
    } catch (error) {
      logger.error('Failed to export audit logs:', error);
      throw error;
    }
  }

  /**
   * Real-time monitoring alerts
   */
  async checkSecurityAlerts(): Promise<{
    alerts: Array<{
      type: string;
      severity: 'medium' | 'high' | 'critical';
      message: string;
      count: number;
      details: any;
    }>;
  }> {
    try {
      const masterDb = databaseService.getMasterDb();
      const lastHour = new Date(Date.now() - 60 * 60 * 1000);
      const alerts = [];

      // Check for multiple failed logins from same IP
      const failedLoginsByIP = await masterDb
        .select({
          ip_address: masterSchema.auditLogs.ip_address,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, lastHour),
            eq(masterSchema.auditLogs.action, 'failed_login'),
            sql`ip_address IS NOT NULL`
          )
        )
        .groupBy(masterSchema.auditLogs.ip_address)
        .having(sql`count(*) >= 5`);

      failedLoginsByIP.forEach(({ ip_address, count }) => {
        alerts.push({
          type: 'brute_force_attempt',
          severity: count >= 10 ? 'critical' : 'high',
          message: `Multiple failed login attempts from IP: ${ip_address}`,
          count,
          details: { ip_address },
        });
      });

      // Check for unusual data access patterns
      const highVolumeUsers = await masterDb
        .select({
          user_id: masterSchema.auditLogs.user_id,
          count: sql<number>`cast(count(*) as int)`,
        })
        .from(masterSchema.auditLogs)
        .where(
          and(
            gte(masterSchema.auditLogs.timestamp, lastHour),
            eq(masterSchema.auditLogs.category, 'data'),
            sql`user_id IS NOT NULL`
          )
        )
        .groupBy(masterSchema.auditLogs.user_id)
        .having(sql`count(*) >= 100`);

      highVolumeUsers.forEach(({ user_id, count }) => {
        alerts.push({
          type: 'unusual_data_access',
          severity: 'medium',
          message: `High volume data access by user: ${user_id}`,
          count,
          details: { user_id },
        });
      });

      return { alerts };
    } catch (error) {
      logger.error('Failed to check security alerts:', error);
      return { alerts: [] };
    }
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    try {
      if (this.batchInterval) {
        clearInterval(this.batchInterval);
      }

      // Flush remaining entries
      await this.flushBatch();

      logger.info('Audit service shutdown completed');
    } catch (error) {
      logger.error('Error during audit service shutdown:', error);
    }
  }

  /**
   * Get service status
   */
  getStatus(): {
    batchSize: number;
    pendingEntries: number;
    isProcessing: boolean;
  } {
    return {
      batchSize: this.BATCH_SIZE,
      pendingEntries: this.batchEntries.length,
      isProcessing: !!this.batchInterval,
    };
  }
}

// Export singleton instance
export const auditService = new AuditService();

export default auditService;