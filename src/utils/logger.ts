import winston from 'winston';
import { config } from '@/config/environment';

/**
 * Enhanced logging configuration
 * Provides structured logging with different transports for different environments
 */
const createLogger = () => {
  const logFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
  );

  const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      let logMessage = `${timestamp} [${level}]: ${message}`;
      if (Object.keys(meta).length > 0) {
        logMessage += ' ' + JSON.stringify(meta, null, 2);
      }
      return logMessage;
    })
  );

  const transports: winston.transport[] = [
    new winston.transports.Console({
      format: config.node.env === 'development' ? consoleFormat : logFormat,
      level: config.logging.level,
    }),
  ];

  // Add file transports in production
  if (config.node.env === 'production') {
    transports.push(
      new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        format: logFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
      new winston.transports.File({
        filename: 'logs/combined.log',
        format: logFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      })
    );
  }

  return winston.createLogger({
    level: config.logging.level,
    format: logFormat,
    transports,
    exceptionHandlers: [
      new winston.transports.File({ filename: 'logs/exceptions.log' })
    ],
    rejectionHandlers: [
      new winston.transports.File({ filename: 'logs/rejections.log' })
    ],
  });
};

export const logger = createLogger();

// Cleanup rate limits periodically
setInterval(() => {
  claudeService.cleanupRateLimits();
}, 300000); // Every 5 minutes import type { Conversation, NewConversation, Message, NewMessage } from '@/types/database.types';

