import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { createError } from '@/middleware/errorHandler';
import crypto from 'crypto';

/**
 * Security Middleware
 * Provides comprehensive security headers and protections
 */

/**
 * Basic security headers using Helmet
 */
export const basicSecurityMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "wss:", "ws:"],
      mediaSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "unsafe-none" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true,
});

/**
 * Production security headers (stricter)
 */
export const productionSecurityMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      mediaSrc: ["'none'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: { policy: "require-corp" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  hsts: {
    maxAge: 63072000, // 2 years
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: "no-referrer" },
});

/**
 * Development security headers (relaxed)
 */
export const developmentSecurityMiddleware = helmet({
  contentSecurityPolicy: false, // Disable CSP in development
  hsts: false, // Disable HSTS in development
});

/**
 * API security headers
 */
export const apiSecurityMiddleware = helmet({
  contentSecurityPolicy: false, // APIs don't need CSP
  crossOriginResourcePolicy: { policy: "cross-origin" },
  frameguard: false, // APIs don't need frame protection
  hsts: config.NODE_ENV === 'production' ? {
    maxAge: 31536000,
    includeSubDomains: true,
  } : false,
});

/**
 * Request size limiting
 */
export const requestSizeMiddleware = (maxSize: string = '10mb') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = req.headers['content-length'];
    const maxSizeBytes = parseSize(maxSize);

    if (contentLength && parseInt(contentLength, 10) > maxSizeBytes) {
      logger.warn('Request size exceeded:', {
        contentLength: parseInt(contentLength, 10),
        maxSize: maxSizeBytes,
        path: req.path,
        ip: req.ip,
      });

      return next(createError.custom(
        'Request size too large',
        413,
        'REQUEST_TOO_LARGE'
      ));
    }

    next();
  };
};

/**
 * Request timeout middleware
 */
export const requestTimeoutMiddleware = (timeout: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const timeoutId = setTimeout(() => {
      if (!res.headersSent) {
        logger.warn('Request timeout:', {
          path: req.path,
          method: req.method,
          timeout,
          ip: req.ip,
        });

        res.status(408).json({
          success: false,
          error: 'Request timeout',
          code: 'REQUEST_TIMEOUT',
          timestamp: new Date().toISOString(),
        });
      }
    }, timeout);

    // Clear timeout when response finishes
    res.on('finish', () => clearTimeout(timeoutId));
    res.on('close', () => clearTimeout(timeoutId));

    next();
  };
};

/**
 * IP allowlist middleware
 */
export const ipAllowlistMiddleware = (allowedIPs: string[] = []) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIP = req.ip;

    if (allowedIPs.length === 0) {
      return next(); // No restrictions if no IPs specified
    }

    const isAllowed = allowedIPs.some(allowedIP => {
      if (allowedIP.includes('/')) {
        // CIDR notation
        return isIPInCIDR(clientIP, allowedIP);
      }
      return clientIP === allowedIP;
    });

    if (!isAllowed) {
      logger.warn('IP access denied:', {
        clientIP,
        allowedIPs,
        path: req.path,
        userAgent: req.headers['user-agent'],
      });

      return next(createError.forbidden('Access denied from this IP address'));
    }

    next();
  };
};

/**
 * User agent validation
 */
export const userAgentValidationMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const userAgent = req.headers['user-agent'];

  // Block requests without user agent
  if (!userAgent) {
    logger.warn('Request without user agent blocked:', {
      ip: req.ip,
      path: req.path,
    });

    return next(createError.custom(
      'User agent required',
      400,
      'USER_AGENT_REQUIRED'
    ));
  }

  // Block known malicious user agents
  const blockedPatterns = [
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /masscan/i,
    /zap/i,
    /gobuster/i,
    /dirb/i,
  ];

  const isBlocked = blockedPatterns.some(pattern => pattern.test(userAgent));

  if (isBlocked) {
    logger.warn('Malicious user agent blocked:', {
      userAgent,
      ip: req.ip,
      path: req.path,
    });

    return next(createError.forbidden('Access denied'));
  }

  next();
};

/**
 * Content type validation
 */
export const contentTypeValidationMiddleware = (allowedTypes: string[] = ['application/json']) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (['GET', 'DELETE', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next(); // Skip validation for methods without body
    }

    const contentType = req.headers['content-type'];

    if (!contentType) {
      return next(createError.custom(
        'Content-Type header required',
        400,
        'CONTENT_TYPE_REQUIRED'
      ));
    }

    const isAllowed = allowedTypes.some(type => 
      contentType.toLowerCase().startsWith(type.toLowerCase())
    );

    if (!isAllowed) {
      logger.warn('Invalid content type:', {
        contentType,
        allowedTypes,
        path: req.path,
        ip: req.ip,
      });

      return next(createError.custom(
        `Content-Type must be one of: ${allowedTypes.join(', ')}`,
        415,
        'UNSUPPORTED_MEDIA_TYPE'
      ));
    }

    next();
  };
};

/**
 * Request method validation
 */
export const methodValidationMiddleware = (allowedMethods: string[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!allowedMethods.includes(req.method)) {
      return next(createError.custom(
        `Method ${req.method} not allowed`,
        405,
        'METHOD_NOT_ALLOWED'
      ));
    }

    // Set Allow header
    res.setHeader('Allow', allowedMethods.join(', '));
    next();
  };
};

/**
 * HTTPS redirect middleware
 */
export const httpsRedirectMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (config.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
    logger.info('Redirecting HTTP to HTTPS:', {
      originalUrl: req.originalUrl,
      ip: req.ip,
    });

    return res.redirect(301, `https://${req.get('host')}${req.originalUrl}`);
  }

  next();
};

/**
 * No cache middleware
 */
export const noCacheMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
};

/**
 * Security headers for sensitive endpoints
 */
export const sensitiveEndpointSecurityMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  // Additional security headers for sensitive endpoints
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Prevent caching
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  
  next();
};

/**
 * Request fingerprinting prevention
 */
export const antiFingerprinting = (req: Request, res: Response, next: NextFunction): void => {
  // Remove/modify headers that can be used for fingerprinting
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  
  // Add randomized headers to make fingerprinting harder
  const randomValue = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-ID', randomValue);
  
  next();
};

/**
 * SQL injection protection
 */
export const sqlInjectionProtection = (req: Request, res: Response, next: NextFunction): void => {
  const sqlPatterns = [
    /(\bUNION\b.*\bSELECT\b)/i,
    /(\bSELECT\b.*\bFROM\b)/i,
    /(\bINSERT\b.*\bINTO\b)/i,
    /(\bUPDATE\b.*\bSET\b)/i,
    /(\bDELETE\b.*\bFROM\b)/i,
    /(\bDROP\b.*\bTABLE\b)/i,
    /(\bCREATE\b.*\bTABLE\b)/i,
    /(\bALTER\b.*\bTABLE\b)/i,
    /(--|\#|\/\*|\*\/)/,
    /(\bxp_cmdshell\b)/i,
    /(\bsp_executesql\b)/i,
  ];

  const checkForSQLInjection = (value: any): boolean => {
    if (typeof value === 'string') {
      return sqlPatterns.some(pattern => pattern.test(value));
    }
    if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(checkForSQLInjection);
    }
    return false;
  };

  const suspicious = [
    req.query,
    req.body,
    req.params,
  ].some(checkForSQLInjection);

  if (suspicious) {
    logger.warn('Potential SQL injection attempt:', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      path: req.path,
      method: req.method,
      query: req.query,
      body: typeof req.body === 'object' ? '[OBJECT]' : req.body,
    });

    return next(createError.custom(
      'Malicious request detected',
      400,
      'MALICIOUS_REQUEST'
    ));
  }

  next();
};

/**
 * XSS protection
 */
export const xssProtection = (req: Request, res: Response, next: NextFunction): void => {
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<img[^>]+src[=\s]*["\']?[^"\'>\s]*["\']?[^>]*>/gi,
  ];

  const checkForXSS = (value: any): boolean => {
    if (typeof value === 'string') {
      return xssPatterns.some(pattern => pattern.test(value));
    }
    if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(checkForXSS);
    }
    return false;
  };

  const suspicious = [
    req.query,
    req.body,
    req.params,
  ].some(checkForXSS);

  if (suspicious) {
    logger.warn('Potential XSS attempt:', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      path: req.path,
      method: req.method,
    });

    return next(createError.custom(
      'Malicious content detected',
      400,
      'XSS_DETECTED'
    ));
  }

  next();
};

/**
 * Path traversal protection
 */
export const pathTraversalProtection = (req: Request, res: Response, next: NextFunction): void => {
  const pathTraversalPatterns = [
    /\.\./,
    /\0/,
    /%2e%2e/i,
    /%252e%252e/i,
    /%c0%ae/i,
    /%c1%9c/i,
  ];

  const checkForPathTraversal = (value: any): boolean => {
    if (typeof value === 'string') {
      return pathTraversalPatterns.some(pattern => pattern.test(value));
    }
    if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(checkForPathTraversal);
    }
    return false;
  };

  const suspicious = [
    req.query,
    req.body,
    req.params,
    req.path,
  ].some(checkForPathTraversal);

  if (suspicious) {
    logger.warn('Potential path traversal attempt:', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      path: req.path,
      method: req.method,
    });

    return next(createError.custom(
      'Invalid path detected',
      400,
      'PATH_TRAVERSAL_DETECTED'
    ));
  }

  next();
};

/**
 * Combined security middleware
 */
export const combinedSecurityMiddleware = [
  antiFingerprinting,
  sqlInjectionProtection,
  xssProtection,
  pathTraversalProtection,
  userAgentValidationMiddleware,
];

/**
 * Utility functions
 */

function parseSize(size: string): number {
  const units: { [key: string]: number } = {
    b: 1,
    kb: 1024,
    mb: 1024 * 1024,
    gb: 1024 * 1024 * 1024,
  };

  const match = size.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*([a-z]+)?$/);
  if (!match) return 0;

  const [, value, unit = 'b'] = match;
  return parseFloat(value) * (units[unit] || 1);
}

function isIPInCIDR(ip: string, cidr: string): boolean {
  // Simple CIDR check implementation
  // In production, use a proper IP library like 'ip' or 'netmask'
  try {
    const [network, prefixLength] = cidr.split('/');
    const ipParts = ip.split('.').map(Number);
    const networkParts = network.split('.').map(Number);
    const mask = parseInt(prefixLength, 10);

    if (ipParts.length !== 4 || networkParts.length !== 4 || mask < 0 || mask > 32) {
      return false;
    }

    const ipBinary = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const networkBinary = (networkParts[0] << 24) + (networkParts[1] << 16) + (networkParts[2] << 8) + networkParts[3];
    const maskBinary = (-1 << (32 - mask)) >>> 0;

    return (ipBinary & maskBinary) === (networkBinary & maskBinary);
  } catch {
    return false;
  }
}

/**
 * Environment-specific security middleware
 */
export const environmentSecurityMiddleware = config.NODE_ENV === 'production' 
  ? productionSecurityMiddleware 
  : developmentSecurityMiddleware;

export default {
  basicSecurityMiddleware,
  productionSecurityMiddleware,
  developmentSecurityMiddleware,
  apiSecurityMiddleware,
  environmentSecurityMiddleware,
  requestSizeMiddleware,
  requestTimeoutMiddleware,
  ipAllowlistMiddleware,
  userAgentValidationMiddleware,
  contentTypeValidationMiddleware,
  methodValidationMiddleware,
  httpsRedirectMiddleware,
  noCacheMiddleware,
  sensitiveEndpointSecurityMiddleware,
  antiFingerprinting,
  sqlInjectionProtection,
  xssProtection,
  pathTraversalProtection,
  combinedSecurityMiddleware,
};