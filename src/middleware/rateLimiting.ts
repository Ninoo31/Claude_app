import { Request, Response, NextFunction } from 'express';
import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { createError } from '@/middleware/errorHandler';

/**
 * Rate Limiting Middleware
 * Provides various rate limiting strategies for different endpoints
 */

// Redis client for distributed rate limiting
let redisClient: Redis | null = null;

if (config.REDIS_URL || config.REDIS_HOST) {
  try {
    redisClient = new Redis({
      host: config.REDIS_HOST,
      port: config.REDIS_PORT,
      password: config.REDIS_PASSWORD,
      db: config.REDIS_DB + 1, // Use separate DB for rate limiting
      retryDelayOnFailover: 100,
      enableReadyCheck: false,
      lazyConnect: true,
    });

    redisClient.on('error', (error) => {
      logger.error('Redis rate limiting error:', error);
    });

    logger.info('Redis rate limiting store configured');
  } catch (error) {
    logger.warn('Failed to configure Redis for rate limiting, falling back to memory store:', error);
    redisClient = null;
  }
}

/**
 * Create rate limiter with optional Redis store
 */
const createRateLimiter = (options: {
  windowMs: number;
  max: number;
  message?: string;
  keyGenerator?: (req: Request) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  standardHeaders?: boolean;
  legacyHeaders?: boolean;
}): RateLimitRequestHandler => {
  const baseOptions = {
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests, please try again later.',
    ...options,
  };

  // Use Redis store if available, otherwise fall back to memory store
  if (redisClient) {
    return rateLimit({
      ...baseOptions,
      store: new RedisStore({
        sendCommand: (...args: string[]) => redisClient!.call(...args),
        prefix: 'rl:',
      }),
    });
  }

  return rateLimit(baseOptions);
};

/**
 * General API rate limiting
 * Applied to all API routes
 */
export const generalRateLimit = createRateLimiter({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS,
  message: 'Too many requests from this IP, please try again later.',
  keyGenerator: (req: Request) => {
    // Use user ID if authenticated, otherwise IP
    return req.user?.id || req.ip;
  },
});

/**
 * Strict rate limiting for authentication endpoints
 * Prevents brute force attacks
 */
export const authRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true, // Don't count successful logins
  keyGenerator: (req: Request) => {
    // Combine IP and email for more granular limiting
    const email = req.body?.email || 'unknown';
    return `auth:${req.ip}:${email}`;
  },
});

/**
 * Registration rate limiting
 * Prevents spam registrations
 */
export const registrationRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per hour per IP
  message: 'Too many registration attempts, please try again later.',
  keyGenerator: (req: Request) => `register:${req.ip}`,
});

/**
 * Password reset rate limiting
 */
export const passwordResetRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 reset attempts per hour
  message: 'Too many password reset attempts, please try again later.',
  keyGenerator: (req: Request) => {
    const email = req.body?.email || 'unknown';
    return `reset:${req.ip}:${email}`;
  },
});

/**
 * Message sending rate limiting
 * Prevents spam and controls API usage
 */
export const messageRateLimit = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 messages per minute
  message: 'Too many messages sent, please slow down.',
  keyGenerator: (req: Request) => `message:${req.user?.id || req.ip}`,
});

/**
 * Claude AI API rate limiting
 * Based on user's subscription plan
 */
export const claudeApiRateLimit = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    return next(createError.unauthorized('Authentication required'));
  }

  // Different limits based on user role/plan
  const limits = {
    admin: { windowMs: 60 * 1000, max: 100 },
    premium: { windowMs: 60 * 1000, max: 60 },
    user: { windowMs: 60 * 1000, max: 20 },
  };

  const userLimit = limits[req.user.role as keyof typeof limits] || limits.user;

  const limiter = createRateLimiter({
    ...userLimit,
    message: 'Claude API rate limit exceeded for your plan.',
    keyGenerator: (req: Request) => `claude:${req.user!.id}`,
  });

  limiter(req, res, next);
};

/**
 * File upload rate limiting
 */
export const uploadRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 uploads per 15 minutes
  message: 'Too many file uploads, please try again later.',
  keyGenerator: (req: Request) => `upload:${req.user?.id || req.ip}`,
});

/**
 * Export/download rate limiting
 */
export const exportRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 exports per hour
  message: 'Too many export requests, please try again later.',
  keyGenerator: (req: Request) => `export:${req.user?.id || req.ip}`,
});

/**
 * Search rate limiting
 */
export const searchRateLimit = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 searches per minute
  message: 'Too many search requests, please slow down.',
  keyGenerator: (req: Request) => `search:${req.user?.id || req.ip}`,
});

/**
 * Webhook rate limiting
 */
export const webhookRateLimit = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 webhooks per minute
  message: 'Webhook rate limit exceeded.',
  keyGenerator: (req: Request) => `webhook:${req.ip}`,
});

/**
 * Admin operations rate limiting
 */
export const adminRateLimit = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 50, // 50 admin operations per minute
  message: 'Admin rate limit exceeded.',
  keyGenerator: (req: Request) => `admin:${req.user?.id || req.ip}`,
});

/**
 * Database operation rate limiting
 */
export const databaseRateLimit = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 database operations per minute
  message: 'Database operation rate limit exceeded.',
  keyGenerator: (req: Request) => `db:${req.user?.id || req.ip}`,
});

/**
 * Dynamic rate limiting based on user subscription
 */
export const dynamicUserRateLimit = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    return next(createError.unauthorized('Authentication required'));
  }

  // Get user's subscription info (this would come from database)
  const subscription = {
    plan: req.user.role === 'admin' ? 'enterprise' : 'free',
    requestsPerMinute: req.user.role === 'admin' ? 1000 : 60,
  };

  const limiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: subscription.requestsPerMinute,
    message: `Rate limit exceeded for ${subscription.plan} plan.`,
    keyGenerator: (req: Request) => `dynamic:${req.user!.id}`,
  });

  limiter(req, res, next);
};

/**
 * Token bucket rate limiter for burst handling
 */
class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per second

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  consume(tokens: number = 1): boolean {
    this.refill();
    
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsed * this.refillRate;
    
    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  getTokens(): number {
    this.refill();
    return Math.floor(this.tokens);
  }
}

// In-memory token buckets (in production, use Redis)
const tokenBuckets = new Map<string, TokenBucket>();

/**
 * Token bucket rate limiting middleware
 */
export const tokenBucketRateLimit = (
  capacity: number = 10,
  refillRate: number = 1, // tokens per second
  tokensPerRequest: number = 1
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.user?.id || req.ip;
    
    if (!tokenBuckets.has(key)) {
      tokenBuckets.set(key, new TokenBucket(capacity, refillRate));
    }
    
    const bucket = tokenBuckets.get(key)!;
    
    if (bucket.consume(tokensPerRequest)) {
      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': capacity.toString(),
        'X-RateLimit-Remaining': bucket.getTokens().toString(),
        'X-RateLimit-Reset': new Date(Date.now() + (capacity / refillRate) * 1000).toISOString(),
      });
      
      next();
    } else {
      logger.warn('Token bucket rate limit exceeded:', {
        key,
        tokensRequested: tokensPerRequest,
        tokensAvailable: bucket.getTokens(),
      });
      
      res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((tokensPerRequest - bucket.getTokens()) / refillRate),
        timestamp: new Date().toISOString(),
      });
    }
  };
};

/**
 * Smart rate limiting based on request cost
 * Different endpoints have different "costs"
 */
export const smartRateLimit = (requestCost: number = 1) => {
  const costLimits = {
    admin: 1000,
    premium: 500,
    user: 100,
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(createError.unauthorized('Authentication required'));
    }

    const userLimit = costLimits[req.user.role as keyof typeof costLimits] || costLimits.user;
    const key = `smart:${req.user.id}`;

    // Use token bucket with user's limit as capacity
    if (!tokenBuckets.has(key)) {
      tokenBuckets.set(key, new TokenBucket(userLimit, userLimit / 60)); // Refill over 1 minute
    }

    const bucket = tokenBuckets.get(key)!;

    if (bucket.consume(requestCost)) {
      res.set({
        'X-RateLimit-Cost': requestCost.toString(),
        'X-RateLimit-Remaining': bucket.getTokens().toString(),
      });
      next();
    } else {
      logger.warn('Smart rate limit exceeded:', {
        userId: req.user.id,
        requestCost,
        availableTokens: bucket.getTokens(),
      });

      res.status(429).json({
        success: false,
        error: 'Request cost exceeds available rate limit',
        code: 'SMART_RATE_LIMIT_EXCEEDED',
        details: {
          requestCost,
          availableTokens: bucket.getTokens(),
          userLimit,
        },
        timestamp: new Date().toISOString(),
      });
    }
  };
};

/**
 * Cleanup expired token buckets (call periodically)
 */
export const cleanupTokenBuckets = (): void => {
  const now = Date.now();
  const maxAge = 60 * 60 * 1000; // 1 hour

  for (const [key, bucket] of tokenBuckets.entries()) {
    if (now - bucket['lastRefill'] > maxAge) {
      tokenBuckets.delete(key);
    }
  }

  logger.debug(`Token bucket cleanup completed. Active buckets: ${tokenBuckets.size}`);
};

// Cleanup token buckets every 30 minutes
setInterval(cleanupTokenBuckets, 30 * 60 * 1000);

/**
 * Rate limit bypass for specific conditions
 */
export const bypassRateLimit = (condition: (req: Request) => boolean) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (condition(req)) {
      return next();
    }
    
    // Continue to next middleware (which should be the rate limiter)
    next();
  };
};

// Common bypass conditions
export const bypassForAdmin = bypassRateLimit((req) => req.user?.role === 'admin');
export const bypassForLocalhost = bypassRateLimit((req) => req.ip === '127.0.0.1' || req.ip === '::1');
export const bypassForApiKey = bypassRateLimit((req) => !!req.headers['x-api-key']);

/**
 * Get rate limit status for a user
 */
export const getRateLimitStatus = (userId: string): any => {
  const userBuckets = Array.from(tokenBuckets.entries())
    .filter(([key]) => key.includes(userId))
    .map(([key, bucket]) => ({
      key,
      tokens: bucket.getTokens(),
      capacity: bucket['capacity'],
    }));

  return {
    userId,
    buckets: userBuckets,
    timestamp: new Date().toISOString(),
  };
};

export default {
  generalRateLimit,
  authRateLimit,
  registrationRateLimit,
  passwordResetRateLimit,
  messageRateLimit,
  claudeApiRateLimit,
  uploadRateLimit,
  exportRateLimit,
  searchRateLimit,
  webhookRateLimit,
  adminRateLimit,
  databaseRateLimit,
  dynamicUserRateLimit,
  tokenBucketRateLimit,
  smartRateLimit,
  bypassForAdmin,
  bypassForLocalhost,
  bypassForApiKey,
  cleanupTokenBuckets,
  getRateLimitStatus,
};