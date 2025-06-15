import swaggerJSDoc from 'swagger-jsdoc';
import { config } from './environment';

/**
 * Swagger/OpenAPI Configuration
 * Generates comprehensive API documentation
 */

const swaggerDefinition = {
  openapi: '3.0.3',
  info: {
    title: 'Claude Memory Backend API',
    version: '1.0.0',
    description: `
# Claude Memory Backend API

Multi-tenant AI conversation platform with per-user database isolation.

## Features
- 🤖 **Claude AI Integration** - Seamless conversations with Claude
- 🏢 **Multi-tenant Architecture** - Isolated data per user
- 📊 **Project Management** - Organize conversations into projects
- 🔄 **Real-time Communication** - WebSocket support
- 📤 **Data Export/Import** - Comprehensive data portability
- 🔐 **Security First** - JWT authentication and audit logging

## Authentication
Most endpoints require JWT authentication. Include the token in the Authorization header:
\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Rate Limiting
API requests are rate limited to prevent abuse:
- **100 requests per 15 minutes** per IP address
- **50 requests per minute** per authenticated user

## Error Handling
All endpoints return consistent error responses:
\`\`\`json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "details": {}
}
\`\`\`
    `,
    contact: {
      name: 'Claude Memory Team',
      email: 'support@claude-memory.com',
      url: 'https://claude-memory.com/support',
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
    termsOfService: 'https://claude-memory.com/terms',
  },
  servers: [
    {
      url: config.node.env === 'development' 
        ? `http://localhost:${config.server.port}/api/v1`
        : 'https://api.claude-memory.com/v1',
      description: config.node.env === 'development' ? 'Development server' : 'Production server',
    },
    {
      url: 'https://staging-api.claude-memory.com/v1',
      description: 'Staging server',
    },
  ],
  paths: {},
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token obtained from login endpoint',
      },
      cookieAuth: {
        type: 'apiKey',
        in: 'cookie',
        name: 'accessToken',
        description: 'JWT token stored in HTTP-only cookie',
      },
    },
    schemas: {
      // Common response schemas
      ApiResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            description: 'Indicates if the request was successful',
          },
          message: {
            type: 'string',
            description: 'Human-readable message',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Response timestamp',
          },
        },
        required: ['success', 'timestamp'],
      },
      SuccessResponse: {
        allOf: [
          { $ref: '#/components/schemas/ApiResponse' },
          {
            type: 'object',
            properties: {
              data: {
                type: 'object',
                description: 'Response data',
              },
            },
          },
        ],
      },
      ErrorResponse: {
        allOf: [
          { $ref: '#/components/schemas/ApiResponse' },
          {
            type: 'object',
            properties: {
              error: {
                type: 'string',
                description: 'Error message',
              },
              code: {
                type: 'string',
                description: 'Error code',
              },
              details: {
                type: 'object',
                description: 'Additional error details',
              },
            },
            required: ['error'],
          },
        ],
      },
      PaginatedResponse: {
        allOf: [
          { $ref: '#/components/schemas/SuccessResponse' },
          {
            type: 'object',
            properties: {
              pagination: {
                type: 'object',
                properties: {
                  page: {
                    type: 'integer',
                    minimum: 1,
                    description: 'Current page number',
                  },
                  limit: {
                    type: 'integer',
                    minimum: 1,
                    maximum: 100,
                    description: 'Items per page',
                  },
                  total: {
                    type: 'integer',
                    minimum: 0,
                    description: 'Total number of items',
                  },
                  totalPages: {
                    type: 'integer',
                    minimum: 0,
                    description: 'Total number of pages',
                  },
                  hasNext: {
                    type: 'boolean',
                    description: 'Whether there are more pages',
                  },
                  hasPrev: {
                    type: 'boolean',
                    description: 'Whether there are previous pages',
                  },
                },
                required: ['page', 'limit', 'total', 'totalPages', 'hasNext', 'hasPrev'],
              },
            },
          },
        ],
      },

      // User & Authentication schemas
      User: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uuid',
            description: 'User unique identifier',
          },
          email: {
            type: 'string',
            format: 'email',
            description: 'User email address',
          },
          name: {
            type: 'string',
            description: 'User display name',
          },
          role: {
            type: 'string',
            enum: ['user', 'admin', 'super_admin'],
            description: 'User role',
          },
          avatar_url: {
            type: 'string',
            format: 'uri',
            nullable: true,
            description: 'User avatar URL',
          },
          preferences: {
            type: 'object',
            description: 'User preferences',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Account creation date',
          },
        },
        required: ['id', 'email', 'name', 'role'],
      },
      LoginRequest: {
        type: 'object',
        properties: {
          email: {
            type: 'string',
            format: 'email',
            description: 'User email address',
          },
          password: {
            type: 'string',
            minLength: 8,
            description: 'User password',
          },
        },
        required: ['email', 'password'],
      },
      RegisterRequest: {
        type: 'object',
        properties: {
          email: {
            type: 'string',
            format: 'email',
            description: 'User email address',
          },
          password: {
            type: 'string',
            minLength: 8,
            pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]',
            description: 'Strong password with uppercase, lowercase, number, and special character',
          },
          name: {
            type: 'string',
            minLength: 2,
            maxLength: 100,
            description: 'User display name',
          },
        },
        required: ['email', 'password', 'name'],
      },
      AuthTokens: {
        type: 'object',
        properties: {
          accessToken: {
            type: 'string',
            description: 'JWT access token',
          },
          refreshToken: {
            type: 'string',
            description: 'JWT refresh token',
          },
        },
        required: ['accessToken', 'refreshToken'],
      },

      // Project schemas
      Project: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uuid',
            description: 'Project unique identifier',
          },
          name: {
            type: 'string',
            maxLength: 255,
            description: 'Project name',
          },
          description: {
            type: 'string',
            nullable: true,
            description: 'Project description',
          },
          status: {
            type: 'string',
            enum: ['active', 'archived', 'completed', 'paused'],
            description: 'Project status',
          },
          priority: {
            type: 'string',
            enum: ['low', 'medium', 'high', 'critical'],
            description: 'Project priority',
          },
          color: {
            type: 'string',
            pattern: '^#[0-9A-F]{6}$',
            description: 'Project color (hex code)',
          },
          icon: {
            type: 'string',
            nullable: true,
            description: 'Project icon identifier',
          },
          tags: {
            type: 'array',
            items: {
              type: 'string',
            },
            description: 'Project tags',
          },
          collaborators: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                email: { type: 'string', format: 'email' },
                role: { type: 'string', enum: ['owner', 'admin', 'editor', 'viewer'] },
                permissions: {
                  type: 'array',
                  items: { type: 'string' },
                },
              },
            },
            description: 'Project collaborators',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Project creation date',
          },
          updated_at: {
            type: 'string',
            format: 'date-time',
            description: 'Project last update date',
          },
          deadline: {
            type: 'string',
            format: 'date-time',
            nullable: true,
            description: 'Project deadline',
          },
        },
        required: ['id', 'name', 'status', 'priority', 'created_at', 'updated_at'],
      },

      // Conversation schemas
      Conversation: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uuid',
            description: 'Conversation unique identifier',
          },
          project_id: {
            type: 'string',
            format: 'uuid',
            nullable: true,
            description: 'Associated project ID',
          },
          title: {
            type: 'string',
            maxLength: 500,
            description: 'Conversation title',
          },
          description: {
            type: 'string',
            nullable: true,
            description: 'Conversation description',
          },
          summary: {
            type: 'string',
            nullable: true,
            description: 'AI-generated conversation summary',
          },
          importance_level: {
            type: 'integer',
            minimum: 1,
            maximum: 10,
            description: 'Conversation importance (1-10)',
          },
          status: {
            type: 'string',
            enum: ['active', 'archived', 'pinned'],
            description: 'Conversation status',
          },
          conversation_type: {
            type: 'string',
            enum: ['chat', 'brainstorm', 'analysis', 'support'],
            description: 'Type of conversation',
          },
          message_count: {
            type: 'integer',
            minimum: 0,
            description: 'Number of messages in conversation',
          },
          total_tokens: {
            type: 'integer',
            minimum: 0,
            description: 'Total tokens used',
          },
          estimated_cost: {
            type: 'number',
            minimum: 0,
            description: 'Estimated cost in USD',
          },
          tags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Conversation tags',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Conversation creation date',
          },
          updated_at: {
            type: 'string',
            format: 'date-time',
            description: 'Last update date',
          },
          last_message_at: {
            type: 'string',
            format: 'date-time',
            nullable: true,
            description: 'Last message timestamp',
          },
        },
        required: ['id', 'title', 'importance_level', 'status', 'created_at', 'updated_at'],
      },

      // Message schemas
      Message: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uuid',
            description: 'Message unique identifier',
          },
          conversation_id: {
            type: 'string',
            format: 'uuid',
            description: 'Parent conversation ID',
          },
          role: {
            type: 'string',
            enum: ['user', 'assistant', 'system'],
            description: 'Message sender role',
          },
          content: {
            type: 'string',
            description: 'Message content',
          },
          content_type: {
            type: 'string',
            enum: ['text', 'markdown', 'code', 'json'],
            description: 'Content format',
          },
          tokens_used: {
            type: 'integer',
            minimum: 0,
            nullable: true,
            description: 'Tokens consumed for this message',
          },
          model_used: {
            type: 'string',
            nullable: true,
            description: 'Claude model version used',
          },
          processing_time_ms: {
            type: 'integer',
            minimum: 0,
            nullable: true,
            description: 'Processing time in milliseconds',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Message creation timestamp',
          },
        },
        required: ['id', 'conversation_id', 'role', 'content', 'created_at'],
      },

      // Database schemas
      DatabaseConfig: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uuid',
            description: 'Database configuration ID',
          },
          name: {
            type: 'string',
            description: 'Database display name',
          },
          type: {
            type: 'string',
            enum: ['local', 'cloud_postgres', 'cloud_mysql', 'cloud_mongodb'],
            description: 'Database type',
          },
          is_active: {
            type: 'boolean',
            description: 'Whether configuration is active',
          },
          is_default: {
            type: 'boolean',
            description: 'Whether this is the default database',
          },
          health_status: {
            type: 'string',
            enum: ['healthy', 'unhealthy', 'unknown'],
            description: 'Database health status',
          },
          last_health_check: {
            type: 'string',
            format: 'date-time',
            nullable: true,
            description: 'Last health check timestamp',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Configuration creation date',
          },
        },
        required: ['id', 'name', 'type', 'is_active', 'health_status'],
      },

      // Export schemas
      ExportJob: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            description: 'Export job unique identifier',
          },
          status: {
            type: 'string',
            enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
            description: 'Job status',
          },
          progress: {
            type: 'integer',
            minimum: 0,
            maximum: 100,
            description: 'Job progress percentage',
          },
          file_path: {
            type: 'string',
            nullable: true,
            description: 'Path to exported file',
          },
          file_size: {
            type: 'integer',
            minimum: 0,
            nullable: true,
            description: 'File size in bytes',
          },
          error_message: {
            type: 'string',
            nullable: true,
            description: 'Error message if job failed',
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Job creation timestamp',
          },
          started_at: {
            type: 'string',
            format: 'date-time',
            nullable: true,
            description: 'Job start timestamp',
          },
          completed_at: {
            type: 'string',
            format: 'date-time',
            nullable: true,
            description: 'Job completion timestamp',
          },
        },
        required: ['id', 'status', 'progress', 'created_at'],
      },

      // Health check schemas
      HealthStatus: {
        type: 'object',
        properties: {
          status: {
            type: 'string',
            enum: ['healthy', 'degraded', 'unhealthy'],
            description: 'Overall system health status',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Health check timestamp',
          },
          uptime: {
            type: 'number',
            description: 'System uptime in seconds',
          },
          environment: {
            type: 'string',
            description: 'Current environment',
          },
          version: {
            type: 'string',
            description: 'Application version',
          },
          response_time: {
            type: 'number',
            description: 'Health check response time in ms',
          },
        },
        required: ['status', 'timestamp', 'uptime', 'environment', 'version'],
      },
      DetailedHealthStatus: {
        allOf: [
          { $ref: '#/components/schemas/HealthStatus' },
          {
            type: 'object',
            properties: {
              checks: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    name: {
                      type: 'string',
                      description: 'Check name',
                    },
                    status: {
                      type: 'string',
                      enum: ['pass', 'fail', 'warn'],
                      description: 'Individual check status',
                    },
                    response_time: {
                      type: 'number',
                      description: 'Check response time in ms',
                    },
                    details: {
                      type: 'object',
                      description: 'Additional check details',
                    },
                    error: {
                      type: 'string',
                      description: 'Error message if check failed',
                    },
                  },
                  required: ['name', 'status'],
                },
                description: 'Individual health checks',
              },
              system: {
                type: 'object',
                properties: {
                  memory_usage: {
                    type: 'object',
                    description: 'Memory usage statistics',
                  },
                  cpu_usage: {
                    type: 'object',
                    description: 'CPU usage statistics',
                  },
                },
                description: 'System resource information',
              },
            },
          },
        ],
      },

      // WebSocket message schemas
      WebSocketMessage: {
        type: 'object',
        properties: {
          type: {
            type: 'string',
            enum: ['message', 'typing', 'status', 'notification', 'error'],
            description: 'Message type',
          },
          conversation_id: {
            type: 'string',
            format: 'uuid',
            description: 'Conversation ID for message routing',
          },
          project_id: {
            type: 'string',
            format: 'uuid',
            description: 'Project ID for message routing',
          },
          user_id: {
            type: 'string',
            format: 'uuid',
            description: 'User ID who sent the message',
          },
          data: {
            type: 'object',
            description: 'Message payload',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Message timestamp',
          },
        },
        required: ['type', 'user_id', 'data', 'timestamp'],
      },

      // Validation error schema
      ValidationError: {
        type: 'object',
        properties: {
          field: {
            type: 'string',
            description: 'Field that failed validation',
          },
          message: {
            type: 'string',
            description: 'Validation error message',
          },
          value: {
            description: 'Value that failed validation',
          },
          code: {
            type: 'string',
            description: 'Validation error code',
          },
        },
        required: ['field', 'message', 'code'],
      },
    },

    // Response examples
    examples: {
      SuccessResponse: {
        summary: 'Successful operation',
        value: {
          success: true,
          message: 'Operation completed successfully',
          timestamp: '2024-01-01T00:00:00.000Z',
          data: {},
        },
      },
      ErrorResponse: {
        summary: 'Error response',
        value: {
          success: false,
          error: 'Something went wrong',
          code: 'INTERNAL_ERROR',
          timestamp: '2024-01-01T00:00:00.000Z',
        },
      },
      ValidationErrorResponse: {
        summary: 'Validation error',
        value: {
          success: false,
          error: 'Validation failed',
          code: 'VALIDATION_ERROR',
          timestamp: '2024-01-01T00:00:00.000Z',
          details: [
            {
              field: 'email',
              message: 'Valid email is required',
              code: 'INVALID_EMAIL',
            },
          ],
        },
      },
      UnauthorizedResponse: {
        summary: 'Authentication required',
        value: {
          success: false,
          error: 'Authentication required',
          code: 'AUTHENTICATION_ERROR',
          timestamp: '2024-01-01T00:00:00.000Z',
        },
      },
      ForbiddenResponse: {
        summary: 'Insufficient permissions',
        value: {
          success: false,
          error: 'Insufficient permissions',
          code: 'AUTHORIZATION_ERROR',
          timestamp: '2024-01-01T00:00:00.000Z',
        },
      },
      NotFoundResponse: {
        summary: 'Resource not found',
        value: {
          success: false,
          error: 'Resource not found',
          code: 'NOT_FOUND',
          timestamp: '2024-01-01T00:00:00.000Z',
        },
      },
      RateLimitResponse: {
        summary: 'Rate limit exceeded',
        value: {
          success: false,
          error: 'Too many requests',
          code: 'RATE_LIMIT_EXCEEDED',
          timestamp: '2024-01-01T00:00:00.000Z',
        },
      },
    },

    // Common response templates
    responses: {
      Success: {
        description: 'Successful operation',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/SuccessResponse' },
            examples: {
              success: { $ref: '#/components/examples/SuccessResponse' },
            },
          },
        },
      },
      BadRequest: {
        description: 'Bad request - validation error',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              validation: { $ref: '#/components/examples/ValidationErrorResponse' },
            },
          },
        },
      },
      Unauthorized: {
        description: 'Authentication required',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              unauthorized: { $ref: '#/components/examples/UnauthorizedResponse' },
            },
          },
        },
      },
      Forbidden: {
        description: 'Insufficient permissions',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              forbidden: { $ref: '#/components/examples/ForbiddenResponse' },
            },
          },
        },
      },
      NotFound: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              notFound: { $ref: '#/components/examples/NotFoundResponse' },
            },
          },
        },
      },
      TooManyRequests: {
        description: 'Rate limit exceeded',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              rateLimit: { $ref: '#/components/examples/RateLimitResponse' },
            },
          },
        },
      },
      InternalServerError: {
        description: 'Internal server error',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
            examples: {
              error: { $ref: '#/components/examples/ErrorResponse' },
            },
          },
        },
      },
    },

    // Common parameters
    parameters: {
      LimitQuery: {
        name: 'limit',
        in: 'query',
        description: 'Number of items to return (1-100)',
        required: false,
        schema: {
          type: 'integer',
          minimum: 1,
          maximum: 100,
          default: 20,
        },
      },
      OffsetQuery: {
        name: 'offset',
        in: 'query',
        description: 'Number of items to skip',
        required: false,
        schema: {
          type: 'integer',
          minimum: 0,
          default: 0,
        },
      },
      SortByQuery: {
        name: 'sortBy',
        in: 'query',
        description: 'Field to sort by',
        required: false,
        schema: {
          type: 'string',
        },
      },
      SortOrderQuery: {
        name: 'sortOrder',
        in: 'query',
        description: 'Sort order',
        required: false,
        schema: {
          type: 'string',
          enum: ['asc', 'desc'],
          default: 'desc',
        },
      },
      SearchQuery: {
        name: 'search',
        in: 'query',
        description: 'Search term',
        required: false,
        schema: {
          type: 'string',
          minLength: 2,
          maxLength: 200,
        },
      },
      ProjectIdPath: {
        name: 'projectId',
        in: 'path',
        description: 'Project unique identifier',
        required: true,
        schema: {
          type: 'string',
          format: 'uuid',
        },
      },
      ConversationIdPath: {
        name: 'conversationId',
        in: 'path',
        description: 'Conversation unique identifier',
        required: true,
        schema: {
          type: 'string',
          format: 'uuid',
        },
      },
      MessageIdPath: {
        name: 'messageId',
        in: 'path',
        description: 'Message unique identifier',
        required: true,
        schema: {
          type: 'string',
          format: 'uuid',
        },
      },
      DatabaseIdPath: {
        name: 'databaseId',
        in: 'path',
        description: 'Database configuration unique identifier',
        required: true,
        schema: {
          type: 'string',
          format: 'uuid',
        },
      },
      JobIdPath: {
        name: 'jobId',
        in: 'path',
        description: 'Export job unique identifier',
        required: true,
        schema: {
          type: 'string',
          pattern: '^job_\\d+_[a-f0-9]{16},
        },
      },
    },
  },
  security: [
    {
      bearerAuth: [],
    },
  ],
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and session management',
      externalDocs: {
        description: 'Authentication Guide',
        url: 'https://docs.claude-memory.com/auth',
      },
    },
    {
      name: 'Projects',
      description: 'Project management and collaboration',
      externalDocs: {
        description: 'Project Management Guide',
        url: 'https://docs.claude-memory.com/projects',
      },
    },
    {
      name: 'Conversations',
      description: 'AI conversation management',
      externalDocs: {
        description: 'Conversation Guide',
        url: 'https://docs.claude-memory.com/conversations',
      },
    },
    {
      name: 'Database',
      description: 'Database configuration and management',
      externalDocs: {
        description: 'Database Setup Guide',
        url: 'https://docs.claude-memory.com/database',
      },
    },
    {
      name: 'Export',
      description: 'Data export and import operations',
      externalDocs: {
        description: 'Data Portability Guide',
        url: 'https://docs.claude-memory.com/export',
      },
    },
    {
      name: 'Health',
      description: 'System health and monitoring',
      externalDocs: {
        description: 'Monitoring Guide',
        url: 'https://docs.claude-memory.com/monitoring',
      },
    },
    {
      name: 'Webhooks',
      description: 'Webhook management and delivery',
      externalDocs: {
        description: 'Webhook Integration Guide',
        url: 'https://docs.claude-memory.com/webhooks',
      },
    },
  ],
  externalDocs: {
    description: 'Complete Documentation',
    url: 'https://docs.claude-memory.com',
  },
};

const options = {
  definition: swaggerDefinition,
  apis: [
    './src/routes/*.ts',
    './src/controllers/*.ts',
    './src/types/*.ts',
  ],
};

// Generate swagger specification
export const swaggerSpec = swaggerJSDoc(options);

// Swagger UI options
export const swaggerUiOptions = {
  explorer: true,
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    tryItOutEnabled: true,
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    defaultModelsExpandDepth: 2,
    defaultModelExpandDepth: 2,
    docExpansion: 'list',
    deepLinking: true,
    displayOperationId: false,
    defaultModelRendering: 'model',
    showMutatedRequest: true,
    supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
    validatorUrl: null, // Disable validator
  },
  customCss: `
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info .title { color: #3B82F6; }
    .swagger-ui .scheme-container { background: #F8FAFC; padding: 10px; border-radius: 4px; }
    .swagger-ui .btn.authorize { background-color: #10B981; border-color: #10B981; }
    .swagger-ui .btn.authorize:hover { background-color: #059669; border-color: #059669; }
  `,
  customSiteTitle: 'Claude Memory API Documentation',
  customfavIcon: '/favicon.ico',
};

// Export configuration for different environments
export const getSwaggerConfig = (environment: string = config.node.env) => {
  const baseConfig = { ...swaggerSpec };

  switch (environment) {
    case 'development':
      baseConfig.servers = [
        {
          url: `http://localhost:${config.server.port}/api/v1`,
          description: 'Development server',
        },
      ];
      break;

    case 'staging':
      baseConfig.servers = [
        {
          url: 'https://staging-api.claude-memory.com/v1',
          description: 'Staging server',
        },
      ];
      break;

    case 'production':
      baseConfig.servers = [
        {
          url: 'https://api.claude-memory.com/v1',
          description: 'Production server',
        },
      ];
      break;
  }

  return baseConfig;
};

// Helper function to add custom middleware
export const setupSwaggerSecurity = () => {
  return (req: any, res: any, next: any) => {
    // Add security headers for Swagger UI
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  };
};

export default swaggerSpec;