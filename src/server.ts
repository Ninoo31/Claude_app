import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';

import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { errorHandler } from '@/middleware/errorHandler';
import { authMiddleware } from '@/middleware/authMiddleware';
import { databaseService } from '@/services/databaseService';
import { webSocketService } from '@/services/webSocketService';

// Import routes
import authRoutes from '@/routes/auth.routes';
import userRoutes from '@/routes/user.routes';
import projectRoutes from '@/routes/project.routes';
import conversationRoutes from '@/routes/conversation.routes';
import databaseRoutes from '@/routes/database.routes';
import exportRoutes from '@/routes/export.routes';
import healthRoutes from '@/routes/health.routes';

/**
 * Claude Memory Backend Server
 * Multi-tenant AI conversation platform with per-user database isolation
 */
class Server {
  private app: express.Application;
  private httpServer: any;
  private wss: WebSocketServer | null = null;

  constructor() {
    this.app = express();
    this.httpServer = createServer(this.app);
    
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeWebSocket();
    this.initializeErrorHandling();
  }

  /**
   * Initialize middleware stack
   * Security, parsing, logging, and rate limiting
   */
  private initializeMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration
    this.app.use(cors({
      origin: config.cors.origin,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // General middleware
    this.app.use(compression());
    this.app.use(cookieParser());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Logging
    this.app.use(morgan('combined', {
      stream: { write: (message) => logger.info(message.trim()) }
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use('/api/', limiter);
  }

  /**
   * Initialize API routes
   * All routes are prefixed with /api/v1
   */
  private initializeRoutes(): void {
    const apiPrefix = '/api/v1';

    // Health check (no auth required)
    this.app.use(`${apiPrefix}/health`, healthRoutes);

    // Authentication routes (no auth required)
    this.app.use(`${apiPrefix}/auth`, authRoutes);

    // Protected routes (require authentication)
    this.app.use(`${apiPrefix}/users`, authMiddleware, userRoutes);
    this.app.use(`${apiPrefix}/projects`, authMiddleware, projectRoutes);
    this.app.use(`${apiPrefix}/conversations`, authMiddleware, conversationRoutes);
    this.app.use(`${apiPrefix}/database`, authMiddleware, databaseRoutes);
    this.app.use(`${apiPrefix}/export`, authMiddleware, exportRoutes);

    // API documentation
    if (config.node.env === 'development') {
      const swaggerUi = require('swagger-ui-express');
      const swaggerSpec = require('@/config/swagger');
      this.app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
    }

    // Catch-all for undefined routes
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        message: 'Route not found',
        path: req.originalUrl
      });
    });
  }

  /**
   * Initialize WebSocket server for real-time chat
   */
  private initializeWebSocket(): void {
    this.wss = new WebSocketServer({ 
      server: this.httpServer,
      path: '/ws'
    });

    webSocketService.initialize(this.wss);
    logger.info('WebSocket server initialized');
  }

  /**
   * Initialize error handling middleware
   */
  private initializeErrorHandling(): void {
    this.app.use(errorHandler);
  }

  /**
   * Start the server
   */
  public async start(): Promise<void> {
    try {
      // Initialize database connections
      await databaseService.initialize();
      
      // Start HTTP server
      this.httpServer.listen(config.server.port, () => {
        logger.info(`🚀 Server running on port ${config.server.port}`);
        logger.info(`📚 API Documentation: http://localhost:${config.server.port}/api/docs`);
        logger.info(`🌐 Environment: ${config.node.env}`);
      });

      // Graceful shutdown handling
      process.on('SIGTERM', () => this.gracefulShutdown());
      process.on('SIGINT', () => this.gracefulShutdown());
      
    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  /**
   * Graceful shutdown procedure
   */
  private async gracefulShutdown(): Promise<void> {
    logger.info('Initiating graceful shutdown...');
    
    // Close WebSocket server
    if (this.wss) {
      this.wss.close();
    }

    // Close HTTP server
    this.httpServer.close(() => {
      logger.info('HTTP server closed');
    });

    // Close database connections
    await databaseService.closeAll();
    
    logger.info('Graceful shutdown completed');
    process.exit(0);
  }
}

// Start server
const server = new Server();
server.start().catch((error) => {
  logger.error('Server startup failed:', error);
  process.exit(1);
});