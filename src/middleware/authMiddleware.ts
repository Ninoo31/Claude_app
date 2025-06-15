import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '@/config/environment';
import { authService } from '@/services/authService';
import { logger } from '@/utils/logger';
import { createError } from '@/middleware/errorHandler';
import type { AuthUser, JWTPayload } from '@/types/auth.types';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
      sessionId?: string;
      requestId?: string;
      startTime?: number;
    }
  }
}

/**
 * Authentication Middleware
 * Validates JWT tokens and sets user context
 */
export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      throw createError.unauthorized('Authentication token required');
    }

    // Verify and decode token
    const user = await authService.verifyToken(token);
    
    // Set user context
    req.user = user;
    
    // Extract session ID from token for audit logging
    const decoded = jwt.decode(token) as JWTPayload;
    req.sessionId = decoded?.sessionId;

    next();
  } catch (error: any) {
    logger.warn('Authentication failed:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      error: error.message,
    });

    if (error.name === 'JsonWebTokenError') {
      next(createError.unauthorized('Invalid authentication token'));
    } else if (error.name === 'TokenExpiredError') {
      next(createError.unauthorized('Authentication token expired'));
    } else {
      next(createError.unauthorized(error.message || 'Authentication failed'));
    }
  }
};

/**
 * Optional Authentication Middleware
 * Sets user context if token is valid, but doesn't require authentication
 */
export const optionalAuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractToken(req);
    
    if (token) {
      try {
        const user = await authService.verifyToken(token);
        req.user = user;
        
        const decoded = jwt.decode(token) as JWTPayload;
        req.sessionId = decoded?.sessionId;
      } catch (error) {
        // Ignore authentication errors for optional auth
        logger.debug('Optional auth failed:', error);
      }
    }

    next();
  } catch (error) {
    // Never throw errors in optional auth
    next();
  }
};

/**
 * Role-based authorization middleware
 */
export const requireRole = (roles: string | string[]) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];
  
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(createError.unauthorized('Authentication required'));
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn('Authorization failed:', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path,
      });
      
      return next(createError.forbidden('Insufficient permissions'));
    }

    next();
  };
};

/**
 * Admin-only middleware
 */
export const requireAdmin = requireRole('admin');

/**
 * User or Admin middleware
 */
export const requireUserOrAdmin = requireRole(['user', 'admin']);

/**
 * Self or Admin middleware
 * Allows access if the user is accessing their own resources or is an admin
 */
export const requireSelfOrAdmin = (userIdParam: string = 'userId') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(createError.unauthorized('Authentication required'));
    }

    const targetUserId = req.params[userIdParam];
    const isSelf = req.user.id === targetUserId;
    const isAdmin = req.user.role === 'admin';

    if (!isSelf && !isAdmin) {
      logger.warn('Self-or-admin authorization failed:', {
        userId: req.user.id,
        targetUserId,
        userRole: req.user.role,
        path: req.path,
      });
      
      return next(createError.forbidden('Can only access your own resources'));
    }

    next();
  };
};

/**
 * API Key authentication middleware
 * For service-to-service communication
 */
export const apiKeyMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'] as string;
  
  if (!apiKey) {
    return next(createError.unauthorized('API key required'));
  }

  // In production, validate against a secure store
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
  
  if (!validApiKeys.includes(apiKey)) {
    logger.warn('Invalid API key used:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
    });
    
    return next(createError.unauthorized('Invalid API key'));
  }

  // Set API context
  req.user = {
    id: 'system',
    email: 'system@api',
    name: 'System API',
    role: 'system',
    avatar_url: null,
    preferences: {},
  };

  next();
};

/**
 * Rate limiting per user
 */
export const userRateLimit = (
  maxRequests: number = 100,
  windowMs: number = 15 * 60 * 1000 // 15 minutes
) => {
  const requestCounts = new Map<string, { count: number; resetTime: number }>();

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(createError.unauthorized('Authentication required'));
    }

    const userId = req.user.id;
    const now = Date.now();
    const userLimit = requestCounts.get(userId);

    if (!userLimit || now > userLimit.resetTime) {
      // Reset or initialize counter
      requestCounts.set(userId, {
        count: 1,
        resetTime: now + windowMs,
      });
      return next();
    }

    if (userLimit.count >= maxRequests) {
      logger.warn('User rate limit exceeded:', {
        userId,
        count: userLimit.count,
        limit: maxRequests,
      });
      
      return next(createError.rateLimit('Too many requests, please try again later'));
    }

    // Increment counter
    userLimit.count++;
    next();
  };
};

/**
 * Session validation middleware
 * Ensures the session is still valid and updates last used time
 */
export const validateSession = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !req.sessionId) {
      return next(createError.unauthorized('Valid session required'));
    }

    // This would typically check the session in the database
    // and update the last_used_at timestamp
    const isValidSession = await authService.validateSession(req.user.id, req.sessionId);
    
    if (!isValidSession) {
      return next(createError.unauthorized('Session expired or invalid'));
    }

    next();
  } catch (error) {
    next(createError.unauthorized('Session validation failed'));
  }
};

/**
 * Extract token from request
 * Supports Bearer token in Authorization header and cookies
 */
function extractToken(req: Request): string | null {
  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check cookies
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }

  // Check query parameter (for WebSocket upgrades)
  if (req.query && req.query.token) {
    return req.query.token as string;
  }

  return null;
}

/**
 * Middleware to log authentication events
 */
export const authLoggingMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (req.user) {
    logger.debug('Authenticated request:', {
      userId: req.user.id,
      email: req.user.email,
      role: req.user.role,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });
  }

  next();
};

/**
 * Development-only middleware to bypass authentication
 * Only active in development mode with specific environment variable
 */
export const devBypassAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (config.NODE_ENV === 'development' && process.env.BYPASS_AUTH === 'true') {
    req.user = {
      id: 'dev-user',
      email: 'dev@localhost',
      name: 'Development User',
      role: 'admin',
      avatar_url: null,
      preferences: {},
    };
    
    logger.warn('Authentication bypassed for development');
  }

  next();
};

export default authMiddleware;