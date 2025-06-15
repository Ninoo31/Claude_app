import { Request, Response, NextFunction } from 'express';
import { logger } from '@/utils/logger';
import { config } from '@/config/environment';
import crypto from 'crypto';

/**
 * Logging Middleware
 * Comprehensive request/response logging with performance monitoring
 */

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      requestId?: string;
      startTime?: number;
      requestSize?: number;
    }
  }
}

/**
 * Request ID middleware
 * Generates unique ID for each request
 */
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  req.requestId = req.headers['x-request-id'] as string || generateRequestId();
  req.startTime = Date.now();
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', req.requestId);
  
  next();
};

/**
 * Basic request logging middleware
 */
export const requestLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  req.startTime = startTime;

  // Calculate request size
  req.requestSize = Buffer.byteLength(JSON.stringify(req.body || {}), 'utf8');

  // Log incoming request
  logger.info('Incoming request', {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer'),
    userId: req.user?.id,
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length'),
    requestSize: req.requestSize,
    timestamp: new Date().toISOString(),
  });

  // Response finished handler
  const onFinished = () => {
    const duration = Date.now() - startTime;
    const responseSize = res.get('Content-Length') || 0;

    logger.info('Request completed', {
      requestId: req.requestId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      responseSize: `${responseSize} bytes`,
      userId: req.user?.id,
      timestamp: new Date().toISOString(),
    });

    // Log slow requests
    if (duration > 5000) {
      logger.warn('Slow request detected', {
        requestId: req.requestId,
        method: req.method,
        url: req.originalUrl,
        duration: `${duration}ms`,
        statusCode: res.statusCode,
        userId: req.user?.id,
      });
    }

    // Log error responses
    if (res.statusCode >= 400) {
      const logLevel = res.statusCode >= 500 ? 'error' : 'warn';
      logger[logLevel]('Error response', {
        requestId: req.requestId,
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });
    }
  };

  // Listen for response finish
  res.on('finish', onFinished);
  res.on('close', onFinished);

  next();
};

/**
 * Detailed request logging (includes body for debugging)
 */
export const detailedRequestLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (config.NODE_ENV !== 'development') {
    return next(); // Only in development
  }

  const sensitiveFields = ['password', 'token', 'secret', 'authorization'];
  const sanitizedBody = sanitizeObject(req.body, sensitiveFields);
  const sanitizedHeaders = sanitizeObject(req.headers, sensitiveFields);

  logger.debug('Detailed request', {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    headers: sanitizedHeaders,
    body: sanitizedBody,
    query: req.query,
    params: req.params,
    cookies: req.cookies,
    ip: req.ip,
    protocol: req.protocol,
    secure: req.secure,
    timestamp: new Date().toISOString(),
  });

  next();
};

/**
 * Performance monitoring middleware
 */
export const performanceLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = process.hrtime.bigint();
  const startMemory = process.memoryUsage();

  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const endMemory = process.memoryUsage();
    
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    const memoryDelta = {
      rss: endMemory.rss - startMemory.rss,
      heapUsed: endMemory.heapUsed - startMemory.heapUsed,
      heapTotal: endMemory.heapTotal - startMemory.heapTotal,
      external: endMemory.external - startMemory.external,
    };

    logger.debug('Performance metrics', {
      requestId: req.requestId,
      method: req.method,
      url: req.originalUrl,
      duration: `${duration.toFixed(2)}ms`,
      statusCode: res.statusCode,
      memoryDelta,
      timestamp: new Date().toISOString(),
    });

    // Alert on high memory usage
    if (memoryDelta.heapUsed > 50 * 1024 * 1024) { // 50MB
      logger.warn('High memory usage detected', {
        requestId: req.requestId,
        url: req.originalUrl,
        memoryDelta,
      });
    }
  });

  next();
};

/**
 * Error logging middleware
 */
export const errorLoggingMiddleware = (
  error: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errorInfo = {
    requestId: req.requestId,
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code,
      statusCode: error.statusCode,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      headers: sanitizeObject(req.headers, ['authorization', 'cookie']),
      body: sanitizeObject(req.body, ['password', 'token', 'secret']),
      query: req.query,
      params: req.params,
      userId: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    },
    timestamp: new Date().toISOString(),
  };

  // Log based on error severity
  if (error.statusCode >= 500 || !error.statusCode) {
    logger.error('Server error occurred', errorInfo);
  } else if (error.statusCode >= 400) {
    logger.warn('Client error occurred', errorInfo);
  } else {
    logger.info('Error handled', errorInfo);
  }

  next(error);
};

/**
 * Audit logging middleware for sensitive operations
 */
export const auditLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const sensitiveOperations = [
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
  ];

  const sensitiveEndpoints = [
    '/auth',
    '/users',
    '/admin',
    '/database',
    '/export',
  ];

  const isSensitiveOperation = sensitiveOperations.includes(req.method);
  const isSensitiveEndpoint = sensitiveEndpoints.some(endpoint => 
    req.originalUrl.toLowerCase().includes(endpoint)
  );

  if (isSensitiveOperation || isSensitiveEndpoint) {
    res.on('finish', () => {
      logger.info('Audit log', {
        requestId: req.requestId,
        userId: req.user?.id,
        userEmail: req.user?.email,
        action: `${req.method} ${req.originalUrl}`,
        statusCode: res.statusCode,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        success: res.statusCode < 400,
      });
    });
  }

  next();
};

/**
 * Security event logging middleware
 */
export const securityLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  // Log potential security events
  const suspiciousPatterns = [
    /(\bunion\b.*\bselect\b)/i,
    /(\bscript\b)/i,
    /(javascript:)/i,
    /(\.\./),
    /(\beval\b)/i,
    /(\balert\b)/i,
  ];

  const requestString = JSON.stringify({
    url: req.originalUrl,
    body: req.body,
    query: req.query,
  }).toLowerCase();

  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(requestString)
  );

  if (isSuspicious) {
    logger.warn('Suspicious request detected', {
      requestId: req.requestId,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      patterns: suspiciousPatterns.filter(pattern => pattern.test(requestString)),
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * API key logging middleware
 */
export const apiKeyLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'];
  
  if (apiKey) {
    logger.info('API key usage', {
      requestId: req.requestId,
      apiKeyHash: crypto.createHash('sha256').update(apiKey as string).digest('hex').substring(0, 8),
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * Rate limit logging middleware
 */
export const rateLimitLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  res.on('finish', () => {
    if (res.statusCode === 429) {
      logger.warn('Rate limit exceeded', {
        requestId: req.requestId,
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userId: req.user?.id,
        userAgent: req.get('User-Agent'),
        rateLimitHeaders: {
          limit: res.get('X-RateLimit-Limit'),
          remaining: res.get('X-RateLimit-Remaining'),
          reset: res.get('X-RateLimit-Reset'),
        },
        timestamp: new Date().toISOString(),
      });
    }
  });

  next();
};

/**
 * Health check logging (minimal)
 */
export const healthCheckLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (req.originalUrl.includes('/health')) {
    // Minimal logging for health checks
    logger.debug('Health check', {
      statusCode: res.statusCode,
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * File upload logging middleware
 */
export const fileUploadLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (req.file || req.files) {
    const files = req.files as any;
    const fileInfo = req.file ? [req.file] : (files ? Object.values(files).flat() : []);

    logger.info('File upload', {
      requestId: req.requestId,
      userId: req.user?.id,
      fileCount: fileInfo.length,
      files: fileInfo.map((file: any) => ({
        originalName: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
      })),
      totalSize: fileInfo.reduce((sum: number, file: any) => sum + file.size, 0),
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * WebSocket connection logging
 */
export const websocketLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (req.headers.upgrade === 'websocket') {
    logger.info('WebSocket connection attempt', {
      requestId: req.requestId,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      origin: req.get('Origin'),
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

/**
 * Combined logging middleware for production
 */
export const productionLoggingMiddleware = [
  requestIdMiddleware,
  requestLoggingMiddleware,
  auditLoggingMiddleware,
  securityLoggingMiddleware,
  rateLimitLoggingMiddleware,
  errorLoggingMiddleware,
];

/**
 * Combined logging middleware for development
 */
export const developmentLoggingMiddleware = [
  requestIdMiddleware,
  requestLoggingMiddleware,
  detailedRequestLoggingMiddleware,
  performanceLoggingMiddleware,
  auditLoggingMiddleware,
  errorLoggingMiddleware,
];

/**
 * Utility functions
 */

function generateRequestId(): string {
  return `req_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function sanitizeObject(obj: any, sensitiveFields: string[]): any {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const sanitized = { ...obj };
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
}

/**
 * Environment-specific logging middleware
 */
export const environmentLoggingMiddleware = config.NODE_ENV === 'production' 
  ? productionLoggingMiddleware 
  : developmentLoggingMiddleware;

export default {
  requestIdMiddleware,
  requestLoggingMiddleware,
  detailedRequestLoggingMiddleware,
  performanceLoggingMiddleware,
  errorLoggingMiddleware,
  auditLoggingMiddleware,
  securityLoggingMiddleware,
  apiKeyLoggingMiddleware,
  rateLimitLoggingMiddleware,
  healthCheckLoggingMiddleware,
  fileUploadLoggingMiddleware,
  websocketLoggingMiddleware,
  productionLoggingMiddleware,
  developmentLoggingMiddleware,
  environmentLoggingMiddleware,
};