import { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import { config, corsConfig } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * CORS Middleware Configuration
 * Handles Cross-Origin Resource Sharing policies
 */

/**
 * Default CORS configuration
 */
const defaultCorsOptions: CorsOptions = {
  origin: corsConfig.origin,
  credentials: corsConfig.credentials,
  methods: corsConfig.methods,
  allowedHeaders: corsConfig.allowedHeaders,
  exposedHeaders: [
    'X-Total-Count',
    'X-Page-Count',
    'X-Current-Page',
    'X-Rate-Limit-Limit',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset',
    'X-Request-ID',
  ],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

/**
 * Dynamic CORS configuration based on request
 */
const dynamicCorsOptions: CorsOptions = {
  ...defaultCorsOptions,
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }

    // Check if origin is allowed
    const allowedOrigins = Array.isArray(corsConfig.origin) 
      ? corsConfig.origin 
      : [corsConfig.origin];

    // Allow localhost in development
    if (config.NODE_ENV === 'development') {
      const localhostRegex = /^https?:\/\/localhost(:\d+)?$/;
      const ip127Regex = /^https?:\/\/127\.0\.0\.1(:\d+)?$/;
      
      if (localhostRegex.test(origin) || ip127Regex.test(origin)) {
        return callback(null, true);
      }
    }

    // Check against allowed origins
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Check wildcard patterns
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp(
          allowedOrigin.replace(/\*/g, '.*').replace(/\./g, '\\.')
        );
        return regex.test(origin);
      }
      return false;
    });

    if (isAllowed) {
      return callback(null, true);
    }

    logger.warn('CORS request blocked:', {
      origin,
      allowedOrigins,
      userAgent: 'Not available in origin callback',
    });

    callback(new Error('Not allowed by CORS'));
  },
};

/**
 * Standard CORS middleware
 */
export const corsMiddleware = cors(dynamicCorsOptions);

/**
 * Permissive CORS for development
 */
export const devCorsMiddleware = cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['*'],
  exposedHeaders: ['*'],
  maxAge: 86400,
});

/**
 * Strict CORS for production
 */
export const strictCorsMiddleware = cors({
  ...defaultCorsOptions,
  origin: (origin, callback) => {
    if (!origin) {
      return callback(new Error('Origin header required'));
    }

    const allowedOrigins = Array.isArray(corsConfig.origin) 
      ? corsConfig.origin 
      : [corsConfig.origin];

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error('Not allowed by CORS'));
  },
});

/**
 * API-specific CORS (more restrictive)
 */
export const apiCorsMiddleware = cors({
  origin: corsConfig.origin,
  credentials: false, // No credentials for API
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Requested-With',
  ],
  exposedHeaders: [
    'X-Rate-Limit-Limit',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset',
  ],
  maxAge: 3600, // 1 hour
});

/**
 * WebSocket CORS configuration
 */
export const webSocketCorsMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const origin = req.headers.origin;

  if (!origin) {
    return next();
  }

  const allowedOrigins = Array.isArray(corsConfig.origin) 
    ? corsConfig.origin 
    : [corsConfig.origin];

  if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
  } else {
    logger.warn('WebSocket CORS request blocked:', { origin });
    res.status(403).json({
      success: false,
      error: 'WebSocket connection not allowed from this origin',
      code: 'WEBSOCKET_CORS_DENIED',
    });
  }
};

/**
 * Conditional CORS based on environment
 */
export const conditionalCorsMiddleware = config.NODE_ENV === 'production' 
  ? strictCorsMiddleware 
  : devCorsMiddleware;

/**
 * Custom CORS middleware with logging
 */
export const customCorsMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const origin = req.headers.origin;
  const method = req.method;

  // Log CORS requests
  if (origin && method === 'OPTIONS') {
    logger.debug('CORS preflight request:', {
      origin,
      method: req.headers['access-control-request-method'],
      headers: req.headers['access-control-request-headers'],
      userAgent: req.headers['user-agent'],
    });
  }

  // Apply CORS
  corsMiddleware(req, res, (err) => {
    if (err) {
      logger.warn('CORS error:', {
        error: err.message,
        origin,
        method,
        path: req.path,
      });
      
      return res.status(403).json({
        success: false,
        error: 'CORS policy violation',
        code: 'CORS_ERROR',
        details: config.NODE_ENV === 'development' ? err.message : undefined,
      });
    }
    
    next();
  });
};

/**
 * CORS for file uploads
 */
export const uploadCorsMiddleware = cors({
  ...defaultCorsOptions,
  allowedHeaders: [
    ...corsConfig.allowedHeaders,
    'Content-Length',
    'Content-Range',
    'Content-Disposition',
  ],
  exposedHeaders: [
    'X-Upload-Progress',
    'X-File-ID',
    'X-File-URL',
  ],
});

/**
 * CORS for webhooks (more permissive)
 */
export const webhookCorsMiddleware = cors({
  origin: '*',
  credentials: false,
  methods: ['POST', 'PUT'],
  allowedHeaders: [
    'Content-Type',
    'X-Webhook-Signature',
    'X-Event-Type',
  ],
  maxAge: 0, // No caching for webhooks
});

/**
 * Mobile app CORS (allows any origin but requires specific headers)
 */
export const mobileCorsMiddleware = cors({
  origin: (origin, callback) => {
    // Mobile apps might not send origin header
    if (!origin) {
      return callback(null, true);
    }
    
    // Check for mobile app user agents
    const userAgent = 'Not available in origin callback';
    // In actual implementation, you'd need to pass userAgent through request context
    
    callback(null, true);
  },
  credentials: true,
  methods: corsConfig.methods,
  allowedHeaders: [
    ...corsConfig.allowedHeaders,
    'X-App-Version',
    'X-Device-ID',
    'X-Platform',
  ],
});

/**
 * Admin panel CORS (very strict)
 */
export const adminCorsMiddleware = cors({
  origin: (origin, callback) => {
    if (!origin) {
      return callback(new Error('Admin panel requires origin header'));
    }

    // Only allow specific admin origins
    const adminOrigins = process.env.ADMIN_ORIGINS?.split(',') || [];
    
    if (adminOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Admin access not allowed from this origin'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Admin-Token',
  ],
});

/**
 * Health check CORS (minimal)
 */
export const healthCorsMiddleware = cors({
  origin: '*',
  credentials: false,
  methods: ['GET'],
  allowedHeaders: ['Content-Type'],
  maxAge: 300, // 5 minutes
});

/**
 * Documentation CORS (read-only)
 */
export const docsCorsMiddleware = cors({
  origin: '*',
  credentials: false,
  methods: ['GET'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400, // 24 hours
});

/**
 * CORS middleware factory
 */
export const createCorsMiddleware = (options: Partial<CorsOptions> = {}) => {
  return cors({
    ...defaultCorsOptions,
    ...options,
  });
};

/**
 * CORS error handler
 */
export const corsErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (err && err.message.includes('CORS')) {
    logger.warn('CORS error occurred:', {
      error: err.message,
      origin: req.headers.origin,
      method: req.method,
      path: req.path,
      userAgent: req.headers['user-agent'],
    });

    res.status(403).json({
      success: false,
      error: 'Cross-origin request not allowed',
      code: 'CORS_POLICY_VIOLATION',
      timestamp: new Date().toISOString(),
    });
  } else {
    next(err);
  }
};

/**
 * CORS preflight cache control
 */
export const corsPreflightCacheMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (req.method === 'OPTIONS') {
    // Set aggressive caching for preflight requests
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    res.setHeader('Cache-Control', 'public, max-age=86400');
  }
  next();
};

/**
 * Security headers for CORS
 */
export const corsSecurityMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Add security headers for cross-origin requests
  if (req.headers.origin) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
  next();
};

export default {
  corsMiddleware,
  devCorsMiddleware,
  strictCorsMiddleware,
  apiCorsMiddleware,
  webSocketCorsMiddleware,
  conditionalCorsMiddleware,
  customCorsMiddleware,
  uploadCorsMiddleware,
  webhookCorsMiddleware,
  mobileCorsMiddleware,
  adminCorsMiddleware,
  healthCorsMiddleware,
  docsCorsMiddleware,
  createCorsMiddleware,
  corsErrorHandler,
  corsPreflightCacheMiddleware,
  corsSecurityMiddleware,
};