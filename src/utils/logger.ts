import winston from 'winston';
import path from 'path';
import { config, loggingConfig } from '@/config/environment';

/**
 * Logger Utility
 * Centralized logging configuration using Winston
 */

// Custom log levels
const customLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
  },
  colors: {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'blue',
  },
};

// Add colors to winston
winston.addColors(customLevels.colors);

/**
 * Custom log format for development
 */
const developmentFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      log += '\n' + JSON.stringify(meta, null, 2);
    }
    
    return log;
  })
);

/**
 * Custom log format for production
 */
const productionFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    return JSON.stringify({
      timestamp,
      level,
      message,
      ...meta,
      environment: config.NODE_ENV,
      service: 'claude-memory-backend',
    });
  })
);

/**
 * Console transport configuration
 */
const consoleTransport = new winston.transports.Console({
  level: loggingConfig.level,
  format: config.NODE_ENV === 'production' ? productionFormat : developmentFormat,
  handleExceptions: true,
  handleRejections: true,
});

/**
 * File transport for combined logs
 */
const combinedFileTransport = new winston.transports.File({
  filename: path.join('logs', 'combined.log'),
  level: 'info',
  format: productionFormat,
  maxsize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  tailable: true,
});

/**
 * File transport for error logs
 */
const errorFileTransport = new winston.transports.File({
  filename: path.join('logs', 'error.log'),
  level: 'error',
  format: productionFormat,
  maxsize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  tailable: true,
});

/**
 * File transport for audit logs
 */
const auditFileTransport = new winston.transports.File({
  filename: path.join('logs', 'audit.log'),
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      // Only log audit-related entries
      if (meta.audit || meta.userId || meta.action) {
        return JSON.stringify({
          timestamp,
          level,
          message,
          ...meta,
          type: 'audit',
        });
      }
      return '';
    })
  ),
  maxsize: 50 * 1024 * 1024, // 50MB
  maxFiles: 10,
  tailable: true,
});

/**
 * HTTP access logs transport
 */
const accessFileTransport = new winston.transports.File({
  filename: path.join('logs', 'access.log'),
  level: 'http',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        message,
        ...meta,
        type: 'access',
      });
    })
  ),
  maxsize: 100 * 1024 * 1024, // 100MB
  maxFiles: 7,
  tailable: true,
});

/**
 * Create logger instance
 */
const createLogger = (): winston.Logger => {
  const transports: winston.transport[] = [];

  // Always include console transport
  if (loggingConfig.transports.console) {
    transports.push(consoleTransport);
  }

  // Add file transports in production or when explicitly enabled
  if (loggingConfig.transports.file || config.NODE_ENV === 'production') {
    transports.push(
      combinedFileTransport,
      errorFileTransport,
      accessFileTransport
    );

    // Add audit transport if audit logging is enabled
    if (loggingConfig.auditEnabled) {
      transports.push(auditFileTransport);
    }
  }

  return winston.createLogger({
    levels: customLevels.levels,
    level: loggingConfig.level,
    transports,
    exitOnError: false,
    silent: config.NODE_ENV === 'test',
  });
};

// Create the main logger instance
export const logger = createLogger();

/**
 * Specialized loggers for different purposes
 */

// Audit logger for security and compliance
export const auditLogger = winston.createLogger({
  levels: customLevels.levels,
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        message,
        ...meta,
        type: 'audit',
        service: 'claude-memory-backend',
      });
    })
  ),
  transports: [
    auditFileTransport,
    ...(config.NODE_ENV === 'development' ? [consoleTransport] : []),
  ],
});

// Performance logger for monitoring
export const performanceLogger = winston.createLogger({
  levels: customLevels.levels,
  level: 'info',
  format: productionFormat,
  transports: [
    new winston.transports.File({
      filename: path.join('logs', 'performance.log'),
      maxsize: 50 * 1024 * 1024,
      maxFiles: 5,
    }),
  ],
});

// Security logger for security events
export const securityLogger = winston.createLogger({
  levels: customLevels.levels,
  level: 'warn',
  format: productionFormat,
  transports: [
    new winston.transports.File({
      filename: path.join('logs', 'security.log'),
      maxsize: 50 * 1024 * 1024,
      maxFiles: 10,
    }),
    ...(config.NODE_ENV === 'development' ? [consoleTransport] : []),
  ],
});

/**
 * Logger wrapper with enhanced functionality
 */
class LoggerWrapper {
  private winston: winston.Logger;

  constructor(winstonLogger: winston.Logger) {
    this.winston = winstonLogger;
  }

  // Standard log methods
  error(message: string, meta?: any): void {
    this.winston.error(message, meta);
  }

  warn(message: string, meta?: any): void {
    this.winston.warn(message, meta);
  }

  info(message: string, meta?: any): void {
    this.winston.info(message, meta);
  }

  http(message: string, meta?: any): void {
    this.winston.http(message, meta);
  }

  debug(message: string, meta?: any): void {
    this.winston.debug(message, meta);
  }

  // Enhanced methods with context
  logWithContext(level: string, message: string, context: any, meta?: any): void {
    this.winston.log(level, message, {
      ...context,
      ...meta,
    });
  }

  // User action logging
  logUserAction(userId: string, action: string, details?: any): void {
    auditLogger.info('User action', {
      userId,
      action,
      details,
      timestamp: new Date().toISOString(),
      audit: true,
    });
  }

  // Security event logging
  logSecurityEvent(event: string, details: any): void {
    securityLogger.warn('Security event', {
      event,
      details,
      timestamp: new Date().toISOString(),
      security: true,
    });
  }

  // Performance logging
  logPerformance(operation: string, duration: number, details?: any): void {
    performanceLogger.info('Performance metric', {
      operation,
      duration,
      details,
      timestamp: new Date().toISOString(),
      performance: true,
    });
  }

  // Database operation logging
  logDatabaseOperation(operation: string, userId?: string, details?: any): void {
    this.winston.info('Database operation', {
      operation,
      userId,
      details,
      timestamp: new Date().toISOString(),
      category: 'database',
    });
  }

  // API request logging
  logApiRequest(method: string, url: string, statusCode: number, duration: number, userId?: string): void {
    this.winston.http('API request', {
      method,
      url,
      statusCode,
      duration,
      userId,
      timestamp: new Date().toISOString(),
      category: 'api',
    });
  }

  // External service logging
  logExternalService(service: string, operation: string, success: boolean, duration?: number, error?: any): void {
    this.winston.info('External service call', {
      service,
      operation,
      success,
      duration,
      error: error?.message,
      timestamp: new Date().toISOString(),
      category: 'external',
    });
  }

  // File operation logging
  logFileOperation(operation: string, filename: string, userId?: string, size?: number): void {
    this.winston.info('File operation', {
      operation,
      filename,
      userId,
      size,
      timestamp: new Date().toISOString(),
      category: 'file',
    });
  }

  // Create child logger with default context
  child(defaultContext: any): LoggerWrapper {
    const childLogger = winston.createLogger({
      levels: customLevels.levels,
      level: this.winston.level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            level,
            message,
            ...defaultContext,
            ...meta,
          });
        })
      ),
      transports: this.winston.transports,
    });

    return new LoggerWrapper(childLogger);
  }
}

// Create enhanced logger instance
const enhancedLogger = new LoggerWrapper(logger);

// Export both the winston logger and enhanced wrapper
export { logger as winstonLogger };
export default enhancedLogger;

/**
 * Utility functions for logging
 */

// Log levels check
export const isLogLevel = (level: string): boolean => {
  return Object.keys(customLevels.levels).includes(level);
};

// Get current log level
export const getLogLevel = (): string => {
  return logger.level;
};

// Set log level dynamically
export const setLogLevel = (level: string): void => {
  if (isLogLevel(level)) {
    logger.level = level;
  }
};

// Create request logger with context
export const createRequestLogger = (requestId: string, userId?: string) => {
  return enhancedLogger.child({
    requestId,
    userId,
    category: 'request',
  });
};

// Log application startup
export const logStartup = (port: number, environment: string): void => {
  logger.info('Application starting', {
    port,
    environment,
    nodeVersion: process.version,
    platform: process.platform,
    pid: process.pid,
    timestamp: new Date().toISOString(),
    category: 'startup',
  });
};

// Log application shutdown
export const logShutdown = (reason: string): void => {
  logger.info('Application shutting down', {
    reason,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    category: 'shutdown',
  });
};

// Ensure log directory exists
import fs from 'fs';
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}