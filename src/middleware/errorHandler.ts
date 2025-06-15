import { Request, Response, NextFunction } from 'express';
import { logger } from '@/utils/logger';
import { config } from '@/config/environment';
import type { ApiResponse, ValidationError } from '@/types/database.type';

/**
 * Custom Error Classes
 */
export class AppError extends Error {
  public statusCode: number;
  public code: string;
  public isOperational: boolean;
  public details?: any;
  public timestamp: Date;

  constructor(
    message: string,
    statusCode: number = 500,
    code: string = 'INTERNAL_ERROR',
    details?: any
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
    this.details = details;
    this.timestamp = new Date();

    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationAppError extends AppError {
  public validationErrors: ValidationError[];

  constructor(message: string, validationErrors: ValidationError[]) {
    super(message, 400, 'VALIDATION_ERROR', validationErrors);
    this.validationErrors = validationErrors;
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND');
  }
}

export class ConflictError extends AppError {
  constructor(message: string = 'Resource already exists') {
    super(message, 409, 'CONFLICT');
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Too many requests') {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
  }
}

export class DatabaseError extends AppError {
  constructor(message: string = 'Database operation failed', details?: any) {
    super(message, 500, 'DATABASE_ERROR', details);
  }
}

export class ExternalServiceError extends AppError {
  constructor(service: string, message: string = 'External service error') {
    super(`${service}: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR', { service });
  }
}

export class FileUploadError extends AppError {
  constructor(message: string = 'File upload failed') {
    super(message, 400, 'FILE_UPLOAD_ERROR');
  }
}

/**
 * Error Handler Middleware
 * Centralized error handling for the application
 */
export const errorHandler = (
  error: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Generate request ID for tracking
  const requestId = req.requestId || generateRequestId();
  
  // Default error response
  let statusCode = 500;
  let code = 'INTERNAL_ERROR';
  let message = 'Internal server error';
  let details: any = undefined;

  // Handle different error types
  if (error instanceof AppError) {
    statusCode = error.statusCode;
    code = error.code;
    message = error.message;
    details = error.details;
  } else if (error.name === 'ValidationError') {
    statusCode = 400;
    code = 'VALIDATION_ERROR';
    message = 'Validation failed';
    details = parseValidationError(error);
  } else if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    code = 'INVALID_TOKEN';
    message = 'Invalid authentication token';
  } else if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    code = 'TOKEN_EXPIRED';
    message = 'Authentication token expired';
  } else if (error.name === 'CastError') {
    statusCode = 400;
    code = 'INVALID_ID';
    message = 'Invalid resource ID format';
  } else if (error.name === 'MongoError' || error.name === 'PostgresError') {
    const dbError = parseDatabaseError(error);
    statusCode = dbError.statusCode;
    code = dbError.code;
    message = dbError.message;
    details = dbError.details;
  } else if (error.message.includes('ECONNRESET') || error.message.includes('ENOTFOUND')) {
    statusCode = 502;
    code = 'EXTERNAL_SERVICE_ERROR';
    message = 'External service unavailable';
  }

  // Log error with appropriate level
  const errorLog = {
    requestId,
    error: {
      name: error.name,
      message: error.message,
      code,
      statusCode,
      stack: error.stack,
      details,
    },
    request: {
      method: req.method,
      url: req.url,
      headers: sanitizeHeaders(req.headers),
      body: sanitizeBody(req.body),
      user: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    },
    timestamp: new Date().toISOString(),
  };

  if (statusCode >= 500) {
    logger.error('Server error:', errorLog);
  } else if (statusCode >= 400) {
    logger.warn('Client error:', errorLog);
  } else {
    logger.info('Request error:', errorLog);
  }

  // Prepare response
  const response: ApiResponse = {
    success: false,
    error: message,
    timestamp: new Date().toISOString(),
    ...(details && { details }),
    ...(config.node.env === 'development' && {
      debug: {
        requestId,
        stack: error.stack,
        originalError: error.message,
      },
    }),
  };

  // Handle specific error codes for client guidance
  if (code === 'VALIDATION_ERROR' && details) {
    response.validation_errors = details;
  }

  if (code === 'RATE_LIMIT_EXCEEDED') {
    res.setHeader('Retry-After', '60'); // Suggest retry after 60 seconds
  }

  // Send error response
  res.status(statusCode).json(response);
};

/**
 * Async Error Handler Wrapper
 * Wraps async route handlers to catch and forward errors
 */
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Not Found Handler
 * Handles requests to undefined routes
 */
export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
  const error = new NotFoundError(`Route ${req.method} ${req.url}`);
  next(error);
};

/**
 * Parse database errors
 */
function parseDatabaseError(error: any): {
  statusCode: number;
  code: string;
  message: string;
  details?: any;
} {
  // PostgreSQL errors
  if (error.code) {
    switch (error.code) {
      case '23505': // Unique violation
        return {
          statusCode: 409,
          code: 'DUPLICATE_ENTRY',
          message: 'Resource already exists',
          details: { constraint: error.constraint },
        };
      case '23503': // Foreign key violation
        return {
          statusCode: 400,
          code: 'FOREIGN_KEY_VIOLATION',
          message: 'Invalid reference to related resource',
          details: { constraint: error.constraint },
        };
      case '23502': // Not null violation
        return {
          statusCode: 400,
          code: 'REQUIRED_FIELD_MISSING',
          message: 'Required field is missing',
          details: { column: error.column },
        };
      case '42P01': // Table does not exist
        return {
          statusCode: 500,
          code: 'SCHEMA_ERROR',
          message: 'Database schema error',
        };
      default:
        return {
          statusCode: 500,
          code: 'DATABASE_ERROR',
          message: 'Database operation failed',
          details: config.node.env === 'development' ? { code: error.code } : undefined,
        };
    }
  }

  // MongoDB errors
  if (error.name === 'MongoError') {
    switch (error.code) {
      case 11000: // Duplicate key
        return {
          statusCode: 409,
          code: 'DUPLICATE_ENTRY',
          message: 'Resource already exists',
        };
      default:
        return {
          statusCode: 500,
          code: 'DATABASE_ERROR',
          message: 'Database operation failed',
        };
    }
  }

  return {
    statusCode: 500,
    code: 'DATABASE_ERROR',
    message: 'Database operation failed',
  };
}

/**
 * Parse validation errors
 */
function parseValidationError(error: any): ValidationError[] {
  const validationErrors: ValidationError[] = [];

  if (error.errors) {
    Object.keys(error.errors).forEach(field => {
      const fieldError = error.errors[field];
      validationErrors.push({
        field,
        message: fieldError.message || 'Invalid value',
        value: fieldError.value,
        code: fieldError.kind || 'INVALID',
      });
    });
  }

  return validationErrors;
}

/**
 * Sanitize request headers for logging
 */
function sanitizeHeaders(headers: any): any {
  const sanitized = { ...headers };
  
  // Remove sensitive headers
  delete sanitized.authorization;
  delete sanitized.cookie;
  delete sanitized['x-api-key'];
  
  return sanitized;
}

/**
 * Sanitize request body for logging
 */
function sanitizeBody(body: any): any {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };
  
  // Remove sensitive fields
  const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
}

/**
 * Generate unique request ID
 */
function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Request ID Middleware
 * Adds unique request ID to each request
 */
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  req.requestId = generateRequestId();
  req.startTime = Date.now();
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', req.requestId);
  
  next();
};

/**
 * Response Time Middleware
 * Logs request processing time
 */
export const responseTimeMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    
    logger.info('Request completed', {
      requestId: req.requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id,
    });

    // Warn on slow requests
    if (duration > 5000) {
      logger.warn('Slow request detected', {
        requestId: req.requestId,
        duration: `${duration}ms`,
        url: req.url,
      });
    }
  });

  next();
};

/**
 * Error factories for common scenarios
 */
export const createError = {
  validation: (message: string, errors: ValidationError[]) => 
    new ValidationAppError(message, errors),
  
  notFound: (resource: string = 'Resource') => 
    new NotFoundError(resource),
  
  unauthorized: (message?: string) => 
    new AuthenticationError(message),
  
  forbidden: (message?: string) => 
    new AuthorizationError(message),
  
  conflict: (message?: string) => 
    new ConflictError(message),
  
  rateLimit: (message?: string) => 
    new RateLimitError(message),
  
  database: (message?: string, details?: any) => 
    new DatabaseError(message, details),
  
  externalService: (service: string, message?: string) => 
    new ExternalServiceError(service, message),
  
  fileUpload: (message?: string) => 
    new FileUploadError(message),
  
  custom: (message: string, statusCode: number, code: string, details?: any) => 
    new AppError(message, statusCode, code, details),
};

/**
 * Health Check Error Handler
 * Special handler for health check endpoints
 */
export const healthCheckErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  logger.error('Health check failed:', error);
  
  res.status(503).json({
    success: false,
    error: 'Service unavailable',
    code: 'HEALTH_CHECK_FAILED',
    timestamp: new Date().toISOString(),
    details: config.node.env === 'development' ? {
      error: error.message,
      stack: error.stack,
    } : undefined,
  });
};

/**
 * Graceful Shutdown Error Handler
 * Handles errors during graceful shutdown
 */
export const shutdownErrorHandler = (error: Error): void => {
  logger.error('Graceful shutdown error:', {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString(),
  });
  
  // Force exit after timeout
  setTimeout(() => {
    logger.error('Forced shutdown due to hanging processes');
    process.exit(1);
  }, 10000);
};

/**
 * Unhandled Rejection Handler
 */
export const unhandledRejectionHandler = (reason: any, promise: Promise<any>): void => {
  logger.error('Unhandled promise rejection:', {
    reason: reason?.message || reason,
    stack: reason?.stack,
    promise: promise.toString(),
    timestamp: new Date().toISOString(),
  });
  
  // Exit gracefully
  process.exit(1);
};

/**
 * Uncaught Exception Handler
 */
export const uncaughtExceptionHandler = (error: Error): void => {
  logger.error('Uncaught exception:', {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString(),
  });
  
  // Exit immediately
  process.exit(1);
};

/**
 * Express Error Boundary
 * Catches all remaining errors
 */
export const globalErrorBoundary = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // If response already sent, delegate to default Express error handler
  if (res.headersSent) {
    return next(error);
  }

  // Log the error
  logger.error('Global error boundary caught:', {
    error: error.message,
    stack: error.stack,
    requestId: req.requestId,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  // Send generic error response
  res.status(500).json({
    success: false,
    error: 'An unexpected error occurred',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    ...(config.node.env === 'development' && {
      debug: {
        message: error.message,
        stack: error.stack,
      },
    }),
  });
};

/**
 * Setup Global Error Handlers
 * Call this function to setup all global error handlers
 */
export const setupGlobalErrorHandlers = (): void => {
  process.on('unhandledRejection', unhandledRejectionHandler);
  process.on('uncaughtException', uncaughtExceptionHandler);
  
  // Handle graceful shutdown signals
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received, starting graceful shutdown');
    // Graceful shutdown logic will be handled in server.ts
  });
  
  process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    // Graceful shutdown logic will be handled in server.ts
  });
};

/**
 * Error Code Constants
 */
export const ERROR_CODES = {
  // Authentication & Authorization
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  
  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  REQUIRED_FIELD_MISSING: 'REQUIRED_FIELD_MISSING',
  INVALID_FORMAT: 'INVALID_FORMAT',
  INVALID_ID: 'INVALID_ID',
  
  // Resources
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  
  // Database
  DATABASE_ERROR: 'DATABASE_ERROR',
  FOREIGN_KEY_VIOLATION: 'FOREIGN_KEY_VIOLATION',
  SCHEMA_ERROR: 'SCHEMA_ERROR',
  CONNECTION_ERROR: 'CONNECTION_ERROR',
  
  // External Services
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  CLAUDE_SERVICE_ERROR: 'CLAUDE_SERVICE_ERROR',
  N8N_WEBHOOK_ERROR: 'N8N_WEBHOOK_ERROR',
  
  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',
  
  // File Operations
  FILE_UPLOAD_ERROR: 'FILE_UPLOAD_ERROR',
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  INVALID_FILE_TYPE: 'INVALID_FILE_TYPE',
  
  // Export/Import
  EXPORT_ERROR: 'EXPORT_ERROR',
  IMPORT_ERROR: 'IMPORT_ERROR',
  BACKUP_ERROR: 'BACKUP_ERROR',
  
  // General
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  MAINTENANCE_MODE: 'MAINTENANCE_MODE',
} as const;

/**
 * HTTP Status Code Constants
 */
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
} as const;

/**
 * Utility function to check if error is operational
 */
export const isOperationalError = (error: Error): boolean => {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  return false;
};

/**
 * Error reporting to external services (placeholder)
 */
export const reportError = async (error: Error, context?: any): Promise<void> => {
  // In production, you might want to report to services like:
  // - Sentry
  // - Bugsnag
  // - Custom error tracking service
  
  if (config.node.env === 'production') {
    try {
      // Example: await sentryClient.captureException(error, context);
      logger.info('Error reported to external service', {
        error: error.message,
        context,
      });
    } catch (reportingError) {
      logger.error('Failed to report error to external service:', reportingError);
    }
  }
};