import swaggerJsdoc from 'swagger-jsdoc';
import { config } from './environment';

/**
 * Swagger/OpenAPI Configuration
 * API documentation setup for Claude Memory Backend
 */

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Claude Memory Backend API',
    version: '1.0.0',
    description: 'Multi-tenant AI conversation platform with per-user database isolation',
    contact: {
      name: 'API Support',
      email: 'support@claude-memory.com',
      url: 'https://claude-memory.com/support',
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
  },
  servers: [
    {
      url: `http://localhost:${config.PORT}/api/v1`,
      description: 'Development server',
    },
    {
      url: 'https://api.claude-memory.com/v1',
      description: 'Production server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token for authentication',
      },
      apiKey: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'API key for service-to-service communication',
      },
      cookieAuth: {
        type: 'apiKey',
        in: 'cookie',
        name: 'accessToken',
        description: 'JWT token in HTTP-only cookie',
      },
    },
    schemas: {
      // User schemas
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          name: { type: 'string' },
          role: { type: 'string', enum: ['user', 'admin'] },
          avatar_url: { type: 'string', format: 'uri', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
          preferences: { type: 'object' },
        },
      },
      UserRegistration: {
        type: 'object',
        required: ['email', 'password', 'name'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
          name: { type: 'string', minLength: 2, maxLength: 100 },
          phone: { type: 'string', nullable: true },
          preferred_language: { type: 'string', default: 'en' },
          timezone: { type: 'string', default: 'UTC' },
        },
      },
      UserLogin: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' },
          remember_me: { type: 'boolean', default: false },
        },
      },
      
      // Project schemas
      Project: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          description: { type: 'string', nullable: true },
          type: { type: 'string', enum: ['personal', 'team', 'public'] },
          color: { type: 'string', pattern: '^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', nullable: true },
          tags: { type: 'array', items: { type: 'string' } },
          settings: { type: 'object' },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      ProjectCreate: {
        type: 'object',
        required: ['name'],
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 200 },
          description: { type: 'string', maxLength: 1000, nullable: true },
          type: { type: 'string', enum: ['personal', 'team', 'public'], default: 'personal' },
          color: { type: 'string', pattern: '^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', nullable: true },
          tags: { type: 'array', items: { type: 'string' }, maxItems: 20 },
        },
      },

      // Conversation schemas
      Conversation: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          project_id: { type: 'string', format: 'uuid', nullable: true },
          title: { type: 'string' },
          description: { type: 'string', nullable: true },
          status: { type: 'string', enum: ['active', 'archived', 'pinned', 'deleted'] },
          importance_level: { type: 'integer', minimum: 1, maximum: 10 },
          tags: { type: 'array', items: { type: 'string' } },
          message_count: { type: 'integer' },
          last_message_at: { type: 'string', format: 'date-time', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      ConversationCreate: {
        type: 'object',
        required: ['title'],
        properties: {
          title: { type: 'string', minLength: 1, maxLength: 500 },
          description: { type: 'string', maxLength: 2000, nullable: true },
          project_id: { type: 'string', format: 'uuid', nullable: true },
          importance_level: { type: 'integer', minimum: 1, maximum: 10, default: 3 },
          tags: { type: 'array', items: { type: 'string' }, maxItems: 20 },
        },
      },

      // Message schemas
      Message: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          conversation_id: { type: 'string', format: 'uuid' },
          role: { type: 'string', enum: ['user', 'assistant', 'system'] },
          content: { type: 'string' },
          message_type: { type: 'string', enum: ['text', 'image', 'file', 'code', 'system'] },
          tokens_used: { type: 'integer', nullable: true },
          model_used: { type: 'string', nullable: true },
          processing_time_ms: { type: 'integer', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          metadata: { type: 'object', nullable: true },
        },
      },
      MessageCreate: {
        type: 'object',
        required: ['content'],
        properties: {
          content: { type: 'string', minLength: 1, maxLength: 50000 },
          message_type: { type: 'string', enum: ['text', 'image', 'file', 'code'], default: 'text' },
          metadata: { type: 'object', nullable: true },
        },
      },

      // Database schemas
      DatabaseConfig: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          user_id: { type: 'string', format: 'uuid' },
          database_name: { type: 'string' },
          database_host: { type: 'string' },
          database_port: { type: 'integer' },
          status: { type: 'string', enum: ['active', 'inactive', 'deleted'] },
          created_at: { type: 'string', format: 'date-time' },
          last_backup_at: { type: 'string', format: 'date-time', nullable: true },
        },
      },

      // Export schemas
      ExportJob: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          user_id: { type: 'string', format: 'uuid' },
          status: { type: 'string', enum: ['pending', 'processing', 'completed', 'failed'] },
          format: { type: 'string', enum: ['json', 'csv', 'markdown', 'txt', 'sql'] },
          file_path: { type: 'string', nullable: true },
          file_size: { type: 'integer', nullable: true },
          progress: { type: 'integer', minimum: 0, maximum: 100 },
          created_at: { type: 'string', format: 'date-time' },
          completed_at: { type: 'string', format: 'date-time', nullable: true },
          error_message: { type: 'string', nullable: true },
        },
      },

      // Response schemas
      ApiResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          data: { type: 'object', nullable: true },
          message: { type: 'string', nullable: true },
          error: { type: 'string', nullable: true },
          code: { type: 'string', nullable: true },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      PaginatedResponse: {
        allOf: [
          { $ref: '#/components/schemas/ApiResponse' },
          {
            type: 'object',
            properties: {
              pagination: {
                type: 'object',
                properties: {
                  total: { type: 'integer' },
                  page: { type: 'integer' },
                  limit: { type: 'integer' },
                  totalPages: { type: 'integer' },
                  hasNext: { type: 'boolean' },
                  hasPrev: { type: 'boolean' },
                },
              },
            },
          },
        ],
      },
      ValidationError: {
        type: 'object',
        properties: {
          field: { type: 'string' },
          message: { type: 'string' },
          value: { type: 'string', nullable: true },
          code: { type: 'string' },
        },
      },
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          error: { type: 'string' },
          code: { type: 'string' },
          details: { 
            type: 'array', 
            items: { $ref: '#/components/schemas/ValidationError' },
            nullable: true 
          },
          timestamp: { type: 'string', format: 'date-time' },
          requestId: { type: 'string', nullable: true },
        },
      },
    },
    parameters: {
      limitParam: {
        name: 'limit',
        in: 'query',
        description: 'Number of items to return (max 100)',
        schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
      },
      offsetParam: {
        name: 'offset',
        in: 'query',
        description: 'Number of items to skip',
        schema: { type: 'integer', minimum: 0, default: 0 },
      },
      sortByParam: {
        name: 'sortBy',
        in: 'query',
        description: 'Field to sort by',
        schema: { type: 'string' },
      },
      sortOrderParam: {
        name: 'sortOrder',
        in: 'query',
        description: 'Sort order',
        schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
      },
      searchParam: {
        name: 'search',
        in: 'query',
        description: 'Search query',
        schema: { type: 'string', maxLength: 500 },
      },
    },
    responses: {
      Success: {
        description: 'Successful operation',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ApiResponse' },
          },
        },
      },
      ValidationError: {
        description: 'Validation error',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Validation failed',
              code: 'VALIDATION_ERROR',
              details: [
                {
                  field: 'email',
                  message: 'Valid email is required',
                  value: 'invalid-email',
                  code: 'INVALID_FORMAT',
                },
              ],
              timestamp: '2024-01-01T00:00:00.000Z',
            },
          },
        },
      },
      Unauthorized: {
        description: 'Authentication required',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Authentication token required',
              code: 'AUTHENTICATION_ERROR',
              timestamp: '2024-01-01T00:00:00.000Z',
            },
          },
        },
      },
      Forbidden: {
        description: 'Insufficient permissions',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Insufficient permissions',
              code: 'AUTHORIZATION_ERROR',
              timestamp: '2024-01-01T00:00:00.000Z',
            },
          },
        },
      },
      NotFound: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Resource not found',
              code: 'NOT_FOUND',
              timestamp: '2024-01-01T00:00:00.000Z',
            },
          },
        },
      },
      RateLimit: {
        description: 'Too many requests',
        headers: {
          'X-RateLimit-Limit': {
            schema: { type: 'integer' },
            description: 'Request limit per window',
          },
          'X-RateLimit-Remaining': {
            schema: { type: 'integer' },
            description: 'Remaining requests in current window',
          },
          'X-RateLimit-Reset': {
            schema: { type: 'string', format: 'date-time' },
            description: 'Time when the rate limit resets',
          },
        },
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Too many requests, please try again later',
              code: 'RATE_LIMIT_EXCEEDED',
              timestamp: '2024-01-01T00:00:00.000Z',
            },
          },
        },
      },
      ServerError: {
        description: 'Internal server error',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            example: {
              success: false,
              error: 'Internal server error',
              code: 'INTERNAL_ERROR',
              timestamp: '2024-01-01T00:00:00.000Z',
              requestId: 'req_123456789',
            },
          },
        },
      },
    },
  },
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and session management',
    },
    {
      name: 'Users',
      description: 'User profile and account management',
    },
    {
      name: 'Projects',
      description: 'Project management and organization',
    },
    {
      name: 'Conversations',
      description: 'AI conversation management',
    },
    {
      name: 'Messages',
      description: 'Message handling within conversations',
    },
    {
      name: 'Database',
      description: 'Database configuration and management',
    },
    {
      name: 'Export',
      description: 'Data export and import operations',
    },
    {
      name: 'Health',
      description: 'System health and monitoring',
    },
    {
      name: 'Webhooks',
      description: 'Webhook configuration and events',
    },
  ],
  security: [
    {
      bearerAuth: [],
    },
  ],
};

const options = {
  definition: swaggerDefinition,
  apis: [
    './src/routes/*.ts',
    './src/controllers/*.ts',
    './src/middleware/*.ts',
  ],
};

// Generate swagger specification
export const swaggerSpec = swaggerJsdoc(options);

// Swagger UI options
export const swaggerUiOptions = {
  explorer: true,
  swaggerOptions: {
    docExpansion: 'none',
    filter: true,
    showRequestDuration: true,
    tryItOutEnabled: true,
    requestInterceptor: (req: any) => {
      // Add any request interceptors here
      return req;
    },
  },
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info .title { color: #2c3e50 }
    .swagger-ui .scheme-container { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
  `,
  customSiteTitle: 'Claude Memory Backend API Documentation',
  customfavIcon: '/favicon.ico',
};

export default swaggerSpec;