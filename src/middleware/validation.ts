import { Request, Response, NextFunction } from 'express';
import { body, param, query, validationResult, ValidationChain } from 'express-validator';
import { createError } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';

/**
 * Validation Middleware
 * Provides common validation rules and middleware for request validation
 */

/**
 * Handle validation results
 * Collects and formats validation errors
 */
export const handleValidationErrors = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(error => ({
      field: error.type === 'field' ? error.path : 'unknown',
      message: error.msg,
      value: error.type === 'field' ? error.value : undefined,
      location: error.location || 'body',
    }));

    logger.warn('Validation failed:', {
      path: req.path,
      method: req.method,
      errors: formattedErrors,
      body: req.body,
    });

    throw createError.validation('Validation failed', formattedErrors);
  }

  next();
};

/**
 * Create validation middleware chain
 */
export const validate = (validations: ValidationChain[]) => {
  return [...validations, handleValidationErrors];
};

/**
 * Common validation rules
 */

// UUID validation
export const uuidValidation = (field: string, location: 'param' | 'body' | 'query' = 'param') => {
  const validator = location === 'param' ? param(field) : 
                   location === 'query' ? query(field) : 
                   body(field);
  
  return validator
    .isUUID()
    .withMessage(`${field} must be a valid UUID`);
};

// Email validation
export const emailValidation = (field: string = 'email', required: boolean = true) => {
  const validator = body(field);
  
  if (required) {
    return validator
      .notEmpty()
      .withMessage(`${field} is required`)
      .isEmail()
      .normalizeEmail()
      .withMessage(`${field} must be a valid email address`);
  }
  
  return validator
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage(`${field} must be a valid email address`);
};

// Password validation
export const passwordValidation = (field: string = 'password', minLength: number = 8) => {
  return body(field)
    .isLength({ min: minLength })
    .withMessage(`${field} must be at least ${minLength} characters long`)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage(`${field} must contain at least one lowercase letter, one uppercase letter, and one number`);
};

// String validation with length constraints
export const stringValidation = (
  field: string,
  options: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    location?: 'body' | 'query' | 'param';
    trim?: boolean;
  } = {}
) => {
  const {
    required = true,
    minLength = 1,
    maxLength = 1000,
    location = 'body',
    trim = true,
  } = options;

  const validator = location === 'query' ? query(field) :
                   location === 'param' ? param(field) :
                   body(field);

  let chain = validator;

  if (trim) {
    chain = chain.trim();
  }

  if (required) {
    chain = chain
      .notEmpty()
      .withMessage(`${field} is required`);
  } else {
    chain = chain.optional();
  }

  return chain
    .isLength({ min: minLength, max: maxLength })
    .withMessage(`${field} must be between ${minLength} and ${maxLength} characters`);
};

// Integer validation
export const integerValidation = (
  field: string,
  options: {
    required?: boolean;
    min?: number;
    max?: number;
    location?: 'body' | 'query' | 'param';
  } = {}
) => {
  const {
    required = true,
    min = Number.MIN_SAFE_INTEGER,
    max = Number.MAX_SAFE_INTEGER,
    location = 'body',
  } = options;

  const validator = location === 'query' ? query(field) :
                   location === 'param' ? param(field) :
                   body(field);

  let chain = validator;

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .isInt({ min, max })
    .withMessage(`${field} must be an integer between ${min} and ${max}`)
    .toInt();
};

// Boolean validation
export const booleanValidation = (
  field: string,
  options: {
    required?: boolean;
    location?: 'body' | 'query' | 'param';
  } = {}
) => {
  const {
    required = true,
    location = 'body',
  } = options;

  const validator = location === 'query' ? query(field) :
                   location === 'param' ? param(field) :
                   body(field);

  let chain = validator;

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .isBoolean()
    .withMessage(`${field} must be a boolean value`)
    .toBoolean();
};

// Array validation
export const arrayValidation = (
  field: string,
  options: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    itemType?: 'string' | 'number' | 'boolean';
    location?: 'body' | 'query';
  } = {}
) => {
  const {
    required = true,
    minLength = 0,
    maxLength = 100,
    itemType,
    location = 'body',
  } = options;

  const validator = location === 'query' ? query(field) : body(field);

  let chain = validator;

  if (!required) {
    chain = chain.optional();
  }

  chain = chain
    .isArray({ min: minLength, max: maxLength })
    .withMessage(`${field} must be an array with ${minLength}-${maxLength} items`);

  if (itemType) {
    chain = chain.custom((arr: any[]) => {
      if (!Array.isArray(arr)) return false;
      
      return arr.every(item => {
        switch (itemType) {
          case 'string':
            return typeof item === 'string';
          case 'number':
            return typeof item === 'number' && !isNaN(item);
          case 'boolean':
            return typeof item === 'boolean';
          default:
            return true;
        }
      });
    }).withMessage(`All items in ${field} must be of type ${itemType}`);
  }

  return chain;
};

// Date validation
export const dateValidation = (
  field: string,
  options: {
    required?: boolean;
    format?: 'ISO' | 'timestamp';
    future?: boolean;
    past?: boolean;
    location?: 'body' | 'query' | 'param';
  } = {}
) => {
  const {
    required = true,
    format = 'ISO',
    future,
    past,
    location = 'body',
  } = options;

  const validator = location === 'query' ? query(field) :
                   location === 'param' ? param(field) :
                   body(field);

  let chain = validator;

  if (!required) {
    chain = chain.optional();
  }

  if (format === 'ISO') {
    chain = chain
      .isISO8601({ strict: true })
      .withMessage(`${field} must be a valid ISO 8601 date`);
  } else {
    chain = chain
      .isInt()
      .withMessage(`${field} must be a valid timestamp`)
      .custom((value: number) => {
        const date = new Date(value);
        return !isNaN(date.getTime());
      })
      .withMessage(`${field} must be a valid timestamp`);
  }

  if (future) {
    chain = chain.custom((value: string | number) => {
      const date = new Date(value);
      return date > new Date();
    }).withMessage(`${field} must be a future date`);
  }

  if (past) {
    chain = chain.custom((value: string | number) => {
      const date = new Date(value);
      return date < new Date();
    }).withMessage(`${field} must be a past date`);
  }

  return chain;
};

// URL validation
export const urlValidation = (
  field: string,
  options: {
    required?: boolean;
    protocols?: string[];
    location?: 'body' | 'query';
  } = {}
) => {
  const {
    required = true,
    protocols = ['http', 'https'],
    location = 'body',
  } = options;

  const validator = location === 'query' ? query(field) : body(field);

  let chain = validator;

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .isURL({ protocols })
    .withMessage(`${field} must be a valid URL with protocol: ${protocols.join(', ')}`);
};

// JSON validation
export const jsonValidation = (field: string, required: boolean = true) => {
  let chain = body(field);

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .custom((value: any) => {
      if (typeof value === 'object') {
        return true; // Already parsed by express.json()
      }
      try {
        JSON.parse(value);
        return true;
      } catch {
        return false;
      }
    })
    .withMessage(`${field} must be valid JSON`);
};

// Pagination validation
export const paginationValidation = () => [
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('limit must be between 1 and 100')
    .toInt(),
  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('offset must be 0 or greater')
    .toInt(),
  query('sortBy')
    .optional()
    .isString()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('sortBy must be between 1 and 50 characters'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('sortOrder must be either "asc" or "desc"'),
];

// File upload validation
export const fileValidation = (
  field: string,
  options: {
    required?: boolean;
    maxSize?: number; // in bytes
    allowedTypes?: string[];
    maxFiles?: number;
  } = {}
) => {
  const {
    required = true,
    maxSize = 10 * 1024 * 1024, // 10MB default
    allowedTypes = [],
    maxFiles = 1,
  } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    const files = req.files as any;
    const file = req.file;
    
    if (required && !file && (!files || !files[field])) {
      throw createError.validation(`${field} file is required`, []);
    }

    if (!required && !file && (!files || !files[field])) {
      return next();
    }

    const filesToCheck = file ? [file] : (files ? files[field] : []);
    
    if (!Array.isArray(filesToCheck)) {
      throw createError.validation(`Invalid file upload for ${field}`, []);
    }

    if (filesToCheck.length > maxFiles) {
      throw createError.validation(`Maximum ${maxFiles} files allowed for ${field}`, []);
    }

    for (const uploadedFile of filesToCheck) {
      // Check file size
      if (uploadedFile.size > maxSize) {
        throw createError.validation(
          `File ${uploadedFile.originalname} exceeds maximum size of ${maxSize} bytes`,
          []
        );
      }

      // Check file type
      if (allowedTypes.length > 0 && !allowedTypes.includes(uploadedFile.mimetype)) {
        throw createError.validation(
          `File type ${uploadedFile.mimetype} not allowed. Allowed types: ${allowedTypes.join(', ')}`,
          []
        );
      }
    }

    next();
  };
};

// Custom validation for conversation status
export const conversationStatusValidation = (field: string = 'status') => {
  return body(field)
    .optional()
    .isIn(['active', 'archived', 'pinned', 'deleted'])
    .withMessage(`${field} must be one of: active, archived, pinned, deleted`);
};

// Custom validation for importance level
export const importanceLevelValidation = (field: string = 'importance_level') => {
  return body(field)
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage(`${field} must be between 1 and 10`)
    .toInt();
};

// Tags validation
export const tagsValidation = (field: string = 'tags') => {
  return body(field)
    .optional()
    .isArray({ max: 20 })
    .withMessage(`${field} must be an array with maximum 20 items`)
    .custom((tags: string[]) => {
      if (!Array.isArray(tags)) return false;
      
      return tags.every(tag => 
        typeof tag === 'string' && 
        tag.trim().length > 0 && 
        tag.length <= 50
      );
    })
    .withMessage(`Each tag must be a non-empty string with maximum 50 characters`);
};

// Message type validation
export const messageTypeValidation = (field: string = 'message_type') => {
  return body(field)
    .optional()
    .isIn(['text', 'image', 'file', 'code', 'system'])
    .withMessage(`${field} must be one of: text, image, file, code, system`);
};

// Project type validation
export const projectTypeValidation = (field: string = 'project_type') => {
  return body(field)
    .optional()
    .isIn(['personal', 'team', 'public'])
    .withMessage(`${field} must be one of: personal, team, public`);
};

// Database provider validation
export const databaseProviderValidation = (field: string = 'provider') => {
  return body(field)
    .isIn(['postgresql', 'mysql', 'sqlite'])
    .withMessage(`${field} must be one of: postgresql, mysql, sqlite`);
};

// Color validation (hex color)
export const colorValidation = (field: string, required: boolean = false) => {
  let chain = body(field);

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/)
    .withMessage(`${field} must be a valid hex color (e.g., #FF0000 or #F00)`);
};

// Phone number validation
export const phoneValidation = (field: string = 'phone', required: boolean = false) => {
  let chain = body(field);

  if (!required) {
    chain = chain.optional();
  }

  return chain
    .isMobilePhone('any')
    .withMessage(`${field} must be a valid phone number`);
};

// Language code validation
export const languageValidation = (field: string = 'language') => {
  return body(field)
    .optional()
    .isLength({ min: 2, max: 5 })
    .matches(/^[a-z]{2}(-[A-Z]{2})?$/)
    .withMessage(`${field} must be a valid language code (e.g., 'en', 'en-US')`);
};

// Timezone validation
export const timezoneValidation = (field: string = 'timezone') => {
  return body(field)
    .optional()
    .custom((value: string) => {
      try {
        Intl.DateTimeFormat(undefined, { timeZone: value });
        return true;
      } catch {
        return false;
      }
    })
    .withMessage(`${field} must be a valid timezone (e.g., 'America/New_York')`);
};

// IP address validation
export const ipValidation = (field: string, version?: 4 | 6) => {
  let chain = body(field);

  if (version === 4) {
    return chain
      .isIP(4)
      .withMessage(`${field} must be a valid IPv4 address`);
  } else if (version === 6) {
    return chain
      .isIP(6)
      .withMessage(`${field} must be a valid IPv6 address`);
  }

  return chain
    .isIP()
    .withMessage(`${field} must be a valid IP address`);
};

// Custom validation for Claude model names
export const claudeModelValidation = (field: string = 'model') => {
  const validModels = [
    'claude-3-opus-20240229',
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307',
    'claude-2.1',
    'claude-2.0',
    'claude-instant-1.2'
  ];

  return body(field)
    .optional()
    .isIn(validModels)
    .withMessage(`${field} must be one of: ${validModels.join(', ')}`);
};

// Export format validation
export const exportFormatValidation = (field: string = 'format') => {
  return body(field)
    .optional()
    .isIn(['json', 'csv', 'markdown', 'txt', 'sql'])
    .withMessage(`${field} must be one of: json, csv, markdown, txt, sql`);
};

// Webhook event validation
export const webhookEventValidation = (field: string = 'events') => {
  const validEvents = [
    'conversation.created',
    'conversation.updated',
    'conversation.deleted',
    'message.sent',
    'message.received',
    'project.created',
    'project.updated',
    'project.deleted',
    'user.registered',
    'user.updated'
  ];

  return body(field)
    .isArray({ min: 1 })
    .withMessage(`${field} must be a non-empty array`)
    .custom((events: string[]) => {
      return events.every(event => validEvents.includes(event));
    })
    .withMessage(`${field} contains invalid events. Valid events: ${validEvents.join(', ')}`);
};

// Batch operation validation
export const batchValidation = (field: string = 'ids', maxBatchSize: number = 100) => {
  return body(field)
    .isArray({ min: 1, max: maxBatchSize })
    .withMessage(`${field} must be an array with 1-${maxBatchSize} items`)
    .custom((ids: string[]) => {
      return ids.every(id => typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id));
    })
    .withMessage(`All items in ${field} must be valid UUIDs`);
};

// Search query validation
export const searchValidation = () => [
  query('q')
    .optional()
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Search query must be between 1 and 500 characters'),
  query('type')
    .optional()
    .isIn(['all', 'conversations', 'messages', 'projects'])
    .withMessage('Search type must be one of: all, conversations, messages, projects'),
  query('date_from')
    .optional()
    .isISO8601()
    .withMessage('date_from must be a valid ISO 8601 date'),
  query('date_to')
    .optional()
    .isISO8601()
    .withMessage('date_to must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (req.query.date_from && value) {
        return new Date(value) >= new Date(req.query.date_from as string);
      }
      return true;
    })
    .withMessage('date_to must be after date_from'),
];

// Sanitization helpers
export const sanitizeHtml = (field: string) => {
  return body(field)
    .customSanitizer((value: string) => {
      // Remove potentially dangerous HTML tags
      return value
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '');
    });
};

export const sanitizeFilename = (field: string) => {
  return body(field)
    .customSanitizer((value: string) => {
      // Remove or replace dangerous characters in filenames
      return value
        .replace(/[<>:"/\\|?*]/g, '_')
        .replace(/\.\./g, '__')
        .trim();
    });
};

// Composite validations for common use cases
export const userRegistrationValidation = () => [
  emailValidation('email'),
  passwordValidation('password'),
  stringValidation('name', { minLength: 2, maxLength: 100 }),
  phoneValidation('phone', false),
  languageValidation('preferred_language'),
  timezoneValidation('timezone'),
];

export const projectCreationValidation = () => [
  stringValidation('name', { minLength: 1, maxLength: 200 }),
  stringValidation('description', { required: false, maxLength: 1000 }),
  projectTypeValidation('type'),
  colorValidation('color', false),
  tagsValidation('tags'),
];

export const conversationCreationValidation = () => [
  stringValidation('title', { minLength: 1, maxLength: 500 }),
  stringValidation('description', { required: false, maxLength: 2000 }),
  uuidValidation('project_id', 'body'),
  importanceLevelValidation('importance_level'),
  tagsValidation('tags'),
];

export const messageCreationValidation = () => [
  stringValidation('content', { minLength: 1, maxLength: 50000 }),
  messageTypeValidation('message_type'),
  jsonValidation('metadata', false),
];

export default {
  validate,
  handleValidationErrors,
  // Basic validations
  uuidValidation,
  emailValidation,
  passwordValidation,
  stringValidation,
  integerValidation,
  booleanValidation,
  arrayValidation,
  dateValidation,
  urlValidation,
  jsonValidation,
  paginationValidation,
  fileValidation,
  // Application-specific validations
  conversationStatusValidation,
  importanceLevelValidation,
  tagsValidation,
  messageTypeValidation,
  projectTypeValidation,
  databaseProviderValidation,
  colorValidation,
  phoneValidation,
  languageValidation,
  timezoneValidation,
  ipValidation,
  claudeModelValidation,
  exportFormatValidation,
  webhookEventValidation,
  batchValidation,
  searchValidation,
  // Sanitization
  sanitizeHtml,
  sanitizeFilename,
  // Composite validations
  userRegistrationValidation,
  projectCreationValidation,
  conversationCreationValidation,
  messageCreationValidation,
};