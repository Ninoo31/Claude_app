import { Request, Response } from 'express';
import { databaseService } from '@/services/databaseService';
import { claudeService } from '@/services/claudeService';
import { webhookService } from '@/services/webhookService';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import { config } from '@/config/environment';
import { asyncHandler } from '@/middleware/errorHandler';

/**
 * Health Controller
 * Provides health check endpoints for monitoring and status
 */
class HealthController {
  /**
   * Basic health check
   * GET /api/v1/health
   */
  basicHealth = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.node.env,
      version: process.env.npm_package_version || '1.0.0',
      response_time: Date.now() - startTime,
    };

    res.status(200).json(health);
  });

  /**
   * Detailed health check with dependencies
   * GET /api/v1/health/detailed
   */
  detailedHealth = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const checks: any[] = [];
    let overallStatus = 'healthy';

    try {
      // Database health check
      const dbHealth = await databaseService.getHealthStatus();
      checks.push({
        name: 'database',
        status: dbHealth.status === 'healthy' ? 'pass' : 'fail',
        details: dbHealth,
      });

      if (dbHealth.status !== 'healthy') {
        overallStatus = 'degraded';
      }

      // Claude service health check
      try {
        const claudeHealth = await claudeService.testConnection();
        checks.push({
          name: 'claude_service',
          status: claudeHealth.success ? 'pass' : 'fail',
          response_time: claudeHealth.response_time,
          details: claudeHealth,
        });

        if (!claudeHealth.success) {
          overallStatus = 'degraded';
        }
      } catch (error: any) {
        checks.push({
          name: 'claude_service',
          status: 'fail',
          error: error.message,
        });
        overallStatus = 'degraded';
      }

      // Memory usage check
      const memoryUsage = process.memoryUsage();
      const memoryThreshold = 1024 * 1024 * 1024; // 1GB
      const memoryStatus = memoryUsage.heapUsed < memoryThreshold ? 'pass' : 'warn';
      
      checks.push({
        name: 'memory',
        status: memoryStatus,
        details: {
          heap_used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
          heap_total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
          external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`,
          rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
        },
      });

      // Disk space check (basic)
      try {
        const fs = require('fs');
        const stats = fs.statSync('.');
        checks.push({
          name: 'disk_space',
          status: 'pass',
          details: {
            available: 'check not implemented',
          },
        });
      } catch (error) {
        checks.push({
          name: 'disk_space',
          status: 'warn',
          error: 'Unable to check disk space',
        });
      }

      // Service-specific health checks
      const webhookStatus = webhookService.getStatus();
      checks.push({
        name: 'webhook_service',
        status: 'pass',
        details: webhookStatus,
      });

      const auditStatus = auditService.getStatus();
      checks.push({
        name: 'audit_service',
        status: auditStatus.enabled ? 'pass' : 'warn',
        details: auditStatus,
      });

      // API endpoints health (sample check)
      checks.push({
        name: 'api_endpoints',
        status: 'pass',
        details: {
          total_routes: 'available',
          middleware_loaded: true,
        },
      });

    } catch (error: any) {
      logger.error('Health check failed:', error);
      overallStatus = 'unhealthy';
      checks.push({
        name: 'health_check_system',
        status: 'fail',
        error: error.message,
      });
    }

    const response = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      response_time: Date.now() - startTime,
      checks,
      system: {
        uptime: process.uptime(),
        environment: config.node.env,
        node_version: process.version,
        platform: process.platform,
        arch: process.arch,
        memory_usage: process.memoryUsage(),
        cpu_usage: process.cpuUsage(),
      },
      service_info: {
        name: 'claude-memory-backend',
        version: process.env.npm_package_version || '1.0.0',
        build: process.env.BUILD_ID || 'development',
        git_commit: process.env.GIT_COMMIT || 'unknown',
      },
    };

    const statusCode = overallStatus === 'healthy' ? 200 : 
                      overallStatus === 'degraded' ? 200 : 503;

    res.status(statusCode).json(response);
  });

  /**
   * Readiness probe for Kubernetes
   * GET /api/v1/health/readiness
   */
  readinessCheck = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    
    try {
      // Check if essential services are ready
      const dbHealth = await databaseService.getHealthStatus();
      
      if (dbHealth.status === 'unhealthy') {
        throw new Error('Database not ready');
      }

      // Check if we can handle requests
      const response = {
        status: 'ready',
        timestamp: new Date().toISOString(),
        response_time: Date.now() - startTime,
        checks: {
          database: dbHealth.status === 'healthy' ? 'ready' : 'not_ready',
          services: 'ready',
        },
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.warn('Readiness check failed:', error);
      
      const response = {
        status: 'not_ready',
        timestamp: new Date().toISOString(),
        response_time: Date.now() - startTime,
        error: error.message,
      };

      res.status(503).json(response);
    }
  });

  /**
   * Liveness probe for Kubernetes
   * GET /api/v1/health/liveness
   */
  livenessCheck = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();

    // Basic liveness check - just ensure the application is running
    try {
      const response = {
        status: 'alive',
        timestamp: new Date().toISOString(),
        response_time: Date.now() - startTime,
        uptime: process.uptime(),
        pid: process.pid,
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Liveness check failed:', error);
      
      const response = {
        status: 'dead',
        timestamp: new Date().toISOString(),
        response_time: Date.now() - startTime,
        error: error.message,
      };

      res.status(503).json(response);
    }
  });

  /**
   * Get application metrics
   * GET /api/v1/health/metrics
   */
  getMetrics = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    try {
      const memoryUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();

      // Get service-specific metrics
      const claudeMetrics = claudeService.getServiceMetrics();
      const webhookMetrics = webhookService.getStatus();
      const auditMetrics = auditService.getStatus();
      const dbStats = databaseService.getConnectionStats();

      const metrics = {
        timestamp: new Date().toISOString(),
        system: {
          uptime_seconds: process.uptime(),
          memory: {
            heap_used_bytes: memoryUsage.heapUsed,
            heap_total_bytes: memoryUsage.heapTotal,
            external_bytes: memoryUsage.external,
            rss_bytes: memoryUsage.rss,
          },
          cpu: {
            user_microseconds: cpuUsage.user,
            system_microseconds: cpuUsage.system,
          },
          process: {
            pid: process.pid,
            version: process.version,
            platform: process.platform,
          },
        },
        services: {
          claude: {
            active_requests: claudeMetrics.active_requests,
            rate_limited_users: claudeMetrics.rate_limited_users,
            total_tracked_users: claudeMetrics.total_tracked_users,
          },
          webhooks: {
            queued_deliveries: webhookMetrics.queued_deliveries,
            active_retries: webhookMetrics.active_retries,
            processing: webhookMetrics.processing,
          },
          audit: {
            enabled: auditMetrics.enabled,
            queue_size: auditMetrics.queue_size,
            batch_size: auditMetrics.batch_size,
          },
          database: {
            master_connected: dbStats.master_connected,
            tenant_connections: dbStats.tenant_connections,
            total_pools: dbStats.total_pools,
            active_users_count: dbStats.active_users.length,
          },
        },
        environment: {
          node_env: config.node.env,
          port: config.server.port,
          log_level: config.logging.level,
        },
      };

      res.status(200).json(metrics);
    } catch (error: any) {
      logger.error('Failed to get metrics:', error);
      
      const response = {
        error: 'Failed to collect metrics',
        timestamp: new Date().toISOString(),
        details: error.message,
      };

      res.status(500).json(response);
    }
  });

  /**
   * Get application info
   * GET /api/v1/health/info
   */
  getInfo = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const info = {
      application: {
        name: 'Claude Memory Backend',
        description: 'Multi-tenant AI conversation platform with per-user database isolation',
        version: process.env.npm_package_version || '1.0.0',
        build: process.env.BUILD_ID || 'development',
        git_commit: process.env.GIT_COMMIT || 'unknown',
        build_date: process.env.BUILD_DATE || 'unknown',
      },
      environment: {
        node_version: process.version,
        platform: process.platform,
        arch: process.arch,
        env: config.node.env,
        timezone: process.env.TZ || Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      features: {
        multi_tenant: true,
        claude_integration: true,
        webhook_support: true,
        audit_logging: true,
        real_time_websockets: true,
        export_import: true,
        database_management: true,
        project_management: true,
      },
      api: {
        version: 'v1',
        base_url: `/api/v1`,
        documentation: config.node.env === 'development' ? '/api/docs' : null,
        rate_limit: {
          window_ms: config.rateLimit.windowMs,
          max_requests: config.rateLimit.max,
        },
      },
      dependencies: {
        database: 'PostgreSQL',
        ai_service: 'Claude (via n8n)',
        websockets: 'ws',
        authentication: 'JWT',
        logging: 'Winston',
      },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(info);
  });

  /**
   * Test all external dependencies
   * GET /api/v1/health/dependencies
   */
  testDependencies = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const results: any[] = [];
    let overallStatus = 'healthy';

    // Test database
    try {
      const dbHealth = await databaseService.getHealthStatus();
      results.push({
        name: 'master_database',
        type: 'database',
        status: dbHealth.status === 'healthy' ? 'available' : 'unavailable',
        details: dbHealth,
      });

      if (dbHealth.status !== 'healthy') {
        overallStatus = 'degraded';
      }
    } catch (error: any) {
      results.push({
        name: 'master_database',
        type: 'database',
        status: 'unavailable',
        error: error.message,
      });
      overallStatus = 'degraded';
    }

    // Test Claude service (n8n webhook)
    try {
      const claudeTest = await claudeService.testConnection();
      results.push({
        name: 'claude_n8n_webhook',
        type: 'external_api',
        status: claudeTest.success ? 'available' : 'unavailable',
        response_time: claudeTest.response_time,
        details: claudeTest.details,
        error: claudeTest.error,
      });

      if (!claudeTest.success) {
        overallStatus = 'degraded';
      }
    } catch (error: any) {
      results.push({
        name: 'claude_n8n_webhook',
        type: 'external_api',
        status: 'unavailable',
        error: error.message,
      });
      overallStatus = 'degraded';
    }

    // Test Redis (if configured)
    if (config.redis.url) {
      try {
        // Redis test would go here
        results.push({
          name: 'redis',
          type: 'cache',
          status: 'not_implemented',
          note: 'Redis testing not implemented yet',
        });
      } catch (error: any) {
        results.push({
          name: 'redis',
          type: 'cache',
          status: 'unavailable',
          error: error.message,
        });
      }
    }

    // Test file system access
    try {
      const fs = require('fs');
      const testFile = `${config.storage.path}/health_check_${Date.now()}.tmp`;
      
      // Ensure directory exists
      require('fs').mkdirSync(config.storage.path, { recursive: true });
      
      // Write test file
      fs.writeFileSync(testFile, 'health check test');
      
      // Read and delete test file
      const content = fs.readFileSync(testFile, 'utf8');
      fs.unlinkSync(testFile);
      
      results.push({
        name: 'file_system',
        type: 'storage',
        status: content === 'health check test' ? 'available' : 'unavailable',
        path: config.storage.path,
      });
    } catch (error: any) {
      results.push({
        name: 'file_system',
        type: 'storage',
        status: 'unavailable',
        error: error.message,
        path: config.storage.path,
      });
      overallStatus = 'degraded';
    }

    // Test environment variables
    const requiredEnvVars = [
      'JWT_SECRET',
      'MASTER_DATABASE_URL',
      'N8N_WEBHOOK_URL',
      'ANTHROPIC_API_KEY',
    ];

    const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
    
    results.push({
      name: 'environment_variables',
      type: 'configuration',
      status: missingEnvVars.length === 0 ? 'available' : 'unavailable',
      missing_variables: missingEnvVars,
      total_required: requiredEnvVars.length,
      total_present: requiredEnvVars.length - missingEnvVars.length,
    });

    if (missingEnvVars.length > 0) {
      overallStatus = 'degraded';
    }

    const response = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      total_dependencies: results.length,
      available: results.filter(r => r.status === 'available').length,
      unavailable: results.filter(r => r.status === 'unavailable').length,
      dependencies: results,
    };

    const statusCode = overallStatus === 'healthy' ? 200 : 
                      overallStatus === 'degraded' ? 200 : 503;

    res.status(statusCode).json(response);
  });

  /**
   * Get recent application logs
   * GET /api/v1/health/logs
   */
  getRecentLogs = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    try {
      const level = (req.query.level as string) || 'info';
      const limit = parseInt(req.query.limit as string) || 100;

      // This would typically read from log files or a log aggregation service
      // For now, return a placeholder response
      const logs = [
        {
          timestamp: new Date().toISOString(),
          level: 'info',
          message: 'Health check endpoint accessed',
          service: 'health-controller',
        },
        {
          timestamp: new Date(Date.now() - 60000).toISOString(),
          level: 'info',
          message: 'Database connection pool status checked',
          service: 'database-service',
        },
        {
          timestamp: new Date(Date.now() - 120000).toISOString(),
          level: 'debug',
          message: 'Claude service metrics updated',
          service: 'claude-service',
        },
      ].filter(log => this.shouldIncludeLog(log.level, level))
       .slice(0, limit);

      const response = {
        status: 'success',
        timestamp: new Date().toISOString(),
        filter: {
          level,
          limit,
        },
        total_logs: logs.length,
        logs,
        note: 'This is a placeholder implementation. In production, integrate with your logging system.',
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get recent logs:', error);
      
      const response = {
        status: 'error',
        timestamp: new Date().toISOString(),
        error: 'Failed to retrieve logs',
        details: error.message,
      };

      res.status(500).json(response);
    }
  });

  /**
   * Trigger garbage collection (development only)
   * POST /api/v1/health/gc
   */
  triggerGarbageCollection = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    if (config.node.env === 'production') {
      res.status(403).json({
        error: 'Garbage collection trigger not available in production',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      const beforeMemory = process.memoryUsage();
      
      // Trigger garbage collection if available
      if (global.gc) {
        global.gc();
      } else {
        throw new Error('Garbage collection not available. Start with --expose-gc flag.');
      }

      const afterMemory = process.memoryUsage();

      const response = {
        status: 'completed',
        timestamp: new Date().toISOString(),
        memory_before: {
          heap_used: `${Math.round(beforeMemory.heapUsed / 1024 / 1024)}MB`,
          heap_total: `${Math.round(beforeMemory.heapTotal / 1024 / 1024)}MB`,
          external: `${Math.round(beforeMemory.external / 1024 / 1024)}MB`,
          rss: `${Math.round(beforeMemory.rss / 1024 / 1024)}MB`,
        },
        memory_after: {
          heap_used: `${Math.round(afterMemory.heapUsed / 1024 / 1024)}MB`,
          heap_total: `${Math.round(afterMemory.heapTotal / 1024 / 1024)}MB`,
          external: `${Math.round(afterMemory.external / 1024 / 1024)}MB`,
          rss: `${Math.round(afterMemory.rss / 1024 / 1024)}MB`,
        },
        memory_freed: {
          heap: `${Math.round((beforeMemory.heapUsed - afterMemory.heapUsed) / 1024 / 1024)}MB`,
          rss: `${Math.round((beforeMemory.rss - afterMemory.rss) / 1024 / 1024)}MB`,
        },
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to trigger garbage collection:', error);
      
      const response = {
        status: 'failed',
        timestamp: new Date().toISOString(),
        error: error.message,
      };

      res.status(500).json(response);
    }
  });

  /**
   * Helper method to determine if log should be included based on level
   * @param logLevel - Level of the log entry
   * @param filterLevel - Minimum level to include
   */
  private shouldIncludeLog(logLevel: string, filterLevel: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    const logLevelIndex = levels.indexOf(logLevel);
    const filterLevelIndex = levels.indexOf(filterLevel);
    
    return logLevelIndex >= filterLevelIndex;
  }

  /**
   * Get system resource usage
   * GET /api/v1/health/resources
   */
  getResourceUsage = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    try {
      const memoryUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();

      // Get more detailed system info
      const response = {
        timestamp: new Date().toISOString(),
        process: {
          pid: process.pid,
          uptime: process.uptime(),
          version: process.version,
          platform: process.platform,
          arch: process.arch,
        },
        memory: {
          heap_used: memoryUsage.heapUsed,
          heap_total: memoryUsage.heapTotal,
          heap_used_mb: Math.round(memoryUsage.heapUsed / 1024 / 1024),
          heap_total_mb: Math.round(memoryUsage.heapTotal / 1024 / 1024),
          external: memoryUsage.external,
          external_mb: Math.round(memoryUsage.external / 1024 / 1024),
          rss: memoryUsage.rss,
          rss_mb: Math.round(memoryUsage.rss / 1024 / 1024),
          array_buffers: memoryUsage.arrayBuffers,
          heap_usage_percentage: Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100),
        },
        cpu: {
          user: cpuUsage.user,
          system: cpuUsage.system,
          user_ms: Math.round(cpuUsage.user / 1000),
          system_ms: Math.round(cpuUsage.system / 1000),
        },
        load_average: require('os').loadavg(),
        free_memory: require('os').freemem(),
        total_memory: require('os').totalmem(),
        cpu_count: require('os').cpus().length,
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get resource usage:', error);
      
      const response = {
        error: 'Failed to get resource usage',
        timestamp: new Date().toISOString(),
        details: error.message,
      };

      res.status(500).json(response);
    }
  });
}

// Create controller instance
export const healthController = new HealthController();