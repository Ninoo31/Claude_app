import { Router } from 'express';
import { authMiddleware, requireRole } from '@/middleware/authMiddleware';
import { rateLimitingMiddleware } from '@/middleware/rateLimiting';
import { validationMiddleware } from '@/middleware/validation';
import { loggingMiddleware } from '@/middleware/logging';

// Import route modules
import authRoutes from './auth.routes';
import userRoutes from './user.routes';
import projectRoutes from './project.routes';
import conversationRoutes from './conversation.routes';
import databaseRoutes from './database.routes';
import exportRoutes from './export.routes';
import healthRoutes from './health.routes';
import webhookRoutes from './webhook.routes';

/**
 * Main Routes Index
 * Centralizes all API route definitions and middleware application
 */

const router = Router();

/**
 * API Version Information
 */
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Claude Memory Backend API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    documentation: '/api/docs',
    endpoints: {
      auth: '/api/v1/auth',
      users: '/api/v1/users',
      projects: '/api/v1/projects', 
      conversations: '/api/v1/conversations',
      database: '/api/v1/database',
      export: '/api/v1/export',
      health: '/api/v1/health',
      webhooks: '/api/v1/webhooks',
    },
  });
});

/**
 * Health Check Routes (No authentication required)
 */
router.use('/health', healthRoutes);

/**
 * Authentication Routes (No authentication required)
 */
router.use('/auth', [
  rateLimitingMiddleware.authRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], authRoutes);

/**
 * Webhook Routes (Special authentication)
 */
router.use('/webhooks', [
  rateLimitingMiddleware.webhookRateLimit,
  loggingMiddleware.webhookLoggingMiddleware,
], webhookRoutes);

/**
 * Protected Routes (Authentication required)
 */

// User management routes
router.use('/users', [
  authMiddleware,
  rateLimitingMiddleware.generalRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], userRoutes);

// Project management routes
router.use('/projects', [
  authMiddleware,
  rateLimitingMiddleware.generalRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], projectRoutes);

// Conversation management routes
router.use('/conversations', [
  authMiddleware,
  rateLimitingMiddleware.messageRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], conversationRoutes);

// Database management routes (Admin only)
router.use('/database', [
  authMiddleware,
  requireRole('admin'),
  rateLimitingMiddleware.databaseRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], databaseRoutes);

// Export/Import routes
router.use('/export', [
  authMiddleware,
  rateLimitingMiddleware.exportRateLimit,
  loggingMiddleware.auditLoggingMiddleware,
], exportRoutes);

/**
 * API Status endpoint
 */
router.get('/status', authMiddleware, (req, res) => {
  res.json({
    success: true,
    status: 'operational',
    user: {
      id: req.user?.id,
      email: req.user?.email,
      role: req.user?.role,
    },
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.version,
    },
    timestamp: new Date().toISOString(),
  });
});

/**
 * API Documentation redirect
 */
router.get('/docs', (req, res) => {
  if (process.env.NODE_ENV === 'development') {
    res.redirect('/api/docs');
  } else {
    res.status(404).json({
      success: false,
      error: 'Documentation not available in production',
      code: 'DOCS_NOT_AVAILABLE',
    });
  }
});

/**
 * Catch-all for undefined API routes
 */
router.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'API endpoint not found',
    code: 'ENDPOINT_NOT_FOUND',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      'GET /api/v1/',
      'GET /api/v1/health',
      'POST /api/v1/auth/login',
      'POST /api/v1/auth/register',
      'GET /api/v1/users/profile',
      'GET /api/v1/projects',
      'GET /api/v1/conversations',
      'GET /api/v1/status',
    ],
  });
});

export default router;