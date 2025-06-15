import { Request, Response } from 'express';
import { body, query, param, validationResult } from 'express-validator';
import { conversationService } from '@/services/conversationService';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import { asyncHandler, createError } from '@/middleware/errorHandler';
import type { ApiResponse, PaginatedResponse, ConversationFilters, MessageFilters } from '@/types/database.types';

/**
 * Conversation Controller
 * Handles all conversation and message-related endpoints
 */
class ConversationController {
  /**
   * Get user's conversations with filtering and pagination
   * GET /api/v1/conversations
   */
  getConversations = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid query parameters', errors.array());
    }

    const userId = req.user!.id;
    const filters: ConversationFilters = {
      project_id: req.query.project_id as string,
      status: req.query.status as any,
      importance_level: req.query.importance_level ? parseInt(req.query.importance_level as string) : undefined,
      search: req.query.search as string,
      tags: req.query.tags ? (req.query.tags as string).split(',') : undefined,
      date_from: req.query.date_from as string,
      date_to: req.query.date_to as string,
      conversation_type: req.query.conversation_type as any,
      limit: req.query.limit ? parseInt(req.query.limit as string) : 20,
      offset: req.query.offset ? parseInt(req.query.offset as string) : 0,
      sortBy: req.query.sortBy as any,
      sortOrder: req.query.sortOrder as any,
      include_messages: req.query.include_messages === 'true',
      message_limit: req.query.message_limit ? parseInt(req.query.message_limit as string) : 5,
    };

    const result = await conversationService.getConversations(userId, filters);

    const response: PaginatedResponse = {
      success: true,
      data: result.conversations,
      pagination: {
        page: Math.floor((filters.offset || 0) / (filters.limit || 20)) + 1,
        limit: filters.limit || 20,
        total: result.total,
        totalPages: Math.ceil(result.total / (filters.limit || 20)),
        hasNext: (filters.offset || 0) + (filters.limit || 20) < result.total,
        hasPrev: (filters.offset || 0) > 0,
      },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Create a new conversation
   * POST /api/v1/conversations
   */
  createConversation = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const conversationData = {
      project_id: req.body.project_id,
      title: req.body.title,
      description: req.body.description,
      importance_level: req.body.importance_level,
      tags: req.body.tags,
    };

    const conversation = await conversationService.createConversation(userId, conversationData);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'create',
      conversation_id: conversation.id,
      project_id: conversation.project_id,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { conversation },
      message: 'Conversation created successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Get conversation by ID
   * GET /api/v1/conversations/:conversationId
   */
  getConversationById = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const includeMessages = req.query.includeMessages !== 'false';
    const messageLimit = req.query.message_limit ? parseInt(req.query.message_limit as string) : 100;

    const result = await conversationService.getConversationById(
      userId,
      conversationId,
      includeMessages,
      messageLimit
    );

    if (!result.conversation) {
      throw createError.notFound('Conversation');
    }

    const response: ApiResponse = {
      success: true,
      data: result,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Update conversation
   * PUT /api/v1/conversations/:conversationId
   */
  updateConversation = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const updates = {
      title: req.body.title,
      description: req.body.description,
      importance_level: req.body.importance_level,
      status: req.body.status,
      tags: req.body.tags,
      project_id: req.body.project_id,
    };

    // Remove undefined values
    Object.keys(updates).forEach(key => {
      if (updates[key as keyof typeof updates] === undefined) {
        delete updates[key as keyof typeof updates];
      }
    });

    const conversation = await conversationService.updateConversation(userId, conversationId, updates);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'update',
      conversation_id: conversationId,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { conversation },
      message: 'Conversation updated successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Delete conversation
   * DELETE /api/v1/conversations/:conversationId
   */
  deleteConversation = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const hardDelete = req.query.hard_delete === 'true';

    await conversationService.deleteConversation(userId, conversationId, hardDelete);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'delete',
      conversation_id: conversationId,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      message: `Conversation ${hardDelete ? 'permanently deleted' : 'archived'} successfully`,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Send message to conversation
   * POST /api/v1/conversations/:conversationId/messages
   */
  sendMessage = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const { content, message_type = 'text' } = req.body;

    const result = await conversationService.sendMessage(userId, conversationId, content, message_type);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'message_sent',
      conversation_id: conversationId,
      tokens_used: result.assistantMessage.tokens_used,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: {
        user_message: result.userMessage,
        assistant_message: result.assistantMessage,
      },
      message: 'Message sent successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Get conversation messages with pagination
   * GET /api/v1/conversations/:conversationId/messages
   */
  getConversationMessages = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;

    const options = {
      limit: req.query.limit ? parseInt(req.query.limit as string) : 50,
      offset: req.query.offset ? parseInt(req.query.offset as string) : 0,
      before: req.query.before as string,
      after: req.query.after as string,
      includeDeleted: req.query.include_deleted === 'true',
    };

    const result = await conversationService.getConversationMessages(userId, conversationId, options);

    const response: PaginatedResponse = {
      success: true,
      data: result.messages,
      pagination: {
        page: Math.floor((options.offset || 0) / (options.limit || 50)) + 1,
        limit: options.limit || 50,
        total: result.total,
        totalPages: Math.ceil(result.total / (options.limit || 50)),
        hasNext: result.hasMore,
        hasPrev: (options.offset || 0) > 0,
      },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Search conversations and messages
   * GET /api/v1/conversations/search
   */
  searchConversations = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid search parameters', errors.array());
    }

    const userId = req.user!.id;
    const query = req.query.q as string;
    const filters = {
      project_id: req.query.project_id as string,
      importance_level: req.query.importance_level ? parseInt(req.query.importance_level as string) : undefined,
      date_from: req.query.date_from as string,
      date_to: req.query.date_to as string,
      limit: req.query.limit ? parseInt(req.query.limit as string) : 20,
    };

    if (!query || query.trim().length < 2) {
      throw createError.validation('Search query must be at least 2 characters long', []);
    }

    const result = await conversationService.searchConversations(userId, query, filters);

    const response: PaginatedResponse = {
      success: true,
      data: result.conversations,
      pagination: {
        page: 1,
        limit: filters.limit || 20,
        total: result.total,
        totalPages: Math.ceil(result.total / (filters.limit || 20)),
        hasNext: result.total > (filters.limit || 20),
        hasPrev: false,
      },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Get conversation analytics
   * GET /api/v1/conversations/:conversationId/analytics
   */
  /**
   * Get conversation analytics
   * GET /api/v1/conversations/:conversationId/analytics
   */
  getConversationAnalytics = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const dateRange = req.query.date_range ? parseInt(req.query.date_range as string) : 30;

    const analytics = await conversationService.getConversationAnalytics(userId, conversationId, dateRange);

    const response: ApiResponse = {
      success: true,
      data: { analytics },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Export conversation
   * GET /api/v1/conversations/:conversationId/export
   */
  exportConversation = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;
    const format = (req.query.format as 'json' | 'markdown' | 'txt') || 'json';

    const exportResult = await conversationService.exportConversation(userId, conversationId, format);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'export',
      conversation_id: conversationId,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    // Set appropriate headers for file download
    res.setHeader('Content-Type', exportResult.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${exportResult.filename}"`);
    res.setHeader('Content-Length', Buffer.byteLength(exportResult.content, 'utf8'));

    res.status(200).send(exportResult.content);
  });

  /**
   * Generate conversation summary
   * POST /api/v1/conversations/:conversationId/summary
   */
  generateSummary = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const conversationId = req.params.conversationId;

    await conversationService.generateConversationSummary(userId, conversationId);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'summary_generated',
      conversation_id: conversationId,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      message: 'Conversation summary generated successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Delete a specific message
   * DELETE /api/v1/conversations/:conversationId/messages/:messageId
   */
  deleteMessage = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const messageId = req.params.messageId;
    const hardDelete = req.query.hard_delete === 'true';

    await conversationService.deleteMessage(userId, messageId, hardDelete);

    // Log audit event
    await auditService.log({
      user_id: userId,
      action: 'message_delete',
      resource_type: 'message',
      resource_id: messageId,
      details: {
        hard_delete: hardDelete,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      message: `Message ${hardDelete ? 'permanently deleted' : 'soft deleted'} successfully`,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Bulk operations on conversations
   * POST /api/v1/conversations/bulk
   */
  bulkOperations = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { action, conversation_ids, data } = req.body;

    if (!Array.isArray(conversation_ids) || conversation_ids.length === 0) {
      throw createError.validation('conversation_ids must be a non-empty array', []);
    }

    const results = [];
    const errors_occurred = [];

    for (const conversationId of conversation_ids) {
      try {
        switch (action) {
          case 'update':
            const conversation = await conversationService.updateConversation(userId, conversationId, data);
            results.push({ conversation_id: conversationId, status: 'success', data: conversation });
            break;

          case 'delete':
            await conversationService.deleteConversation(userId, conversationId, data?.hard_delete || false);
            results.push({ conversation_id: conversationId, status: 'success' });
            break;

          case 'archive':
            const archived = await conversationService.updateConversation(userId, conversationId, { status: 'archived' });
            results.push({ conversation_id: conversationId, status: 'success', data: archived });
            break;

          default:
            throw new Error(`Unsupported bulk action: ${action}`);
        }
      } catch (error: any) {
        errors_occurred.push({
          conversation_id: conversationId,
          error: error.message,
        });
      }
    }

    // Log bulk operation
    await auditService.log({
      user_id: userId,
      action: `bulk_${action}`,
      resource_type: 'conversation',
      details: {
        conversation_ids,
        success_count: results.length,
        error_count: errors_occurred.length,
        data,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: errors_occurred.length === 0,
      data: {
        results,
        errors: errors_occurred,
        summary: {
          total: conversation_ids.length,
          success: results.length,
          failed: errors_occurred.length,
        },
      },
      message: `Bulk ${action} completed. ${results.length} successful, ${errors_occurred.length} failed.`,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Get conversation templates
   * GET /api/v1/conversations/templates
   */
  getConversationTemplates = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;
    const projectId = req.query.project_id as string;

    // This would be implemented in the conversation service
    // For now, return a placeholder response
    const templates = [
      {
        id: 'template_1',
        name: 'Project Planning',
        description: 'Template for project planning conversations',
        category: 'planning',
        prompt_text: 'Let\'s plan a new project. What are the main objectives?',
        variables: ['project_name', 'deadline', 'team_size'],
        usage_count: 15,
      },
      {
        id: 'template_2',
        name: 'Code Review',
        description: 'Template for code review discussions',
        category: 'development',
        prompt_text: 'I need help reviewing this code. Here\'s what I\'m working on:',
        variables: ['language', 'code_snippet'],
        usage_count: 8,
      },
    ];

    const response: ApiResponse = {
      success: true,
      data: { templates },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Create conversation from template
   * POST /api/v1/conversations/from-template
   */
  createFromTemplate = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { template_id, variables, project_id, title } = req.body;

    // This would be implemented in the conversation service
    // For now, create a regular conversation
    const conversationData = {
      project_id,
      title: title || `Conversation from template ${template_id}`,
      description: `Created from template: ${template_id}`,
      importance_level: 3,
      tags: ['template', template_id],
    };

    const conversation = await conversationService.createConversation(userId, conversationData);

    // Log audit event
    await auditService.logConversation({
      user_id: userId,
      action: 'create_from_template',
      conversation_id: conversation.id,
      project_id: conversation.project_id,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { conversation },
      message: 'Conversation created from template successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });
}

// Create controller instance
export const conversationController = new ConversationController();

/**
 * Validation Rules
 */

// Create conversation validation
export const createConversationValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Title must be between 1 and 500 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  body('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
  body('importance_level')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Importance level must be between 1 and 10'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
    .custom((tags) => {
      if (tags && tags.length > 20) {
        throw new Error('Maximum 20 tags allowed');
      }
      if (tags && tags.some((tag: any) => typeof tag !== 'string' || tag.length > 50)) {
        throw new Error('Each tag must be a string with maximum 50 characters');
      }
      return true;
    }),
];

// Update conversation validation
export const updateConversationValidation = [
  param('conversationId')
    .isUUID()
    .withMessage('Conversation ID must be a valid UUID'),
  body('title')
    .optional()
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Title must be between 1 and 500 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  body('importance_level')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Importance level must be between 1 and 10'),
  body('status')
    .optional()
    .isIn(['active', 'archived', 'pinned'])
    .withMessage('Status must be active, archived, or pinned'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
];

// Send message validation
export const sendMessageValidation = [
  param('conversationId')
    .isUUID()
    .withMessage('Conversation ID must be a valid UUID'),
  body('content')
    .trim()
    .isLength({ min: 1, max: 50000 })
    .withMessage('Message content must be between 1 and 50,000 characters'),
  body('message_type')
    .optional()
    .isIn(['text', 'command'])
    .withMessage('Message type must be text or command'),
];

// Get conversations validation
export const getConversationsValidation = [
  query('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
  query('status')
    .optional()
    .isIn(['active', 'archived', 'pinned'])
    .withMessage('Status must be active, archived, or pinned'),
  query('importance_level')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Importance level must be between 1 and 10'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Offset must be 0 or greater'),
  query('sortBy')
    .optional()
    .isIn(['title', 'created_at', 'updated_at', 'last_message_at', 'importance_level'])
    .withMessage('Invalid sort field'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc'),
];

// Search conversations validation
export const searchConversationsValidation = [
  query('q')
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Search query must be between 2 and 200 characters'),
  query('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50'),
];

// Conversation ID param validation
export const conversationIdValidation = [
  param('conversationId')
    .isUUID()
    .withMessage('Conversation ID must be a valid UUID'),
];

// Bulk operations validation
export const bulkOperationsValidation = [
  body('action')
    .isIn(['update', 'delete', 'archive'])
    .withMessage('Action must be update, delete, or archive'),
  body('conversation_ids')
    .isArray({ min: 1, max: 100 })
    .withMessage('conversation_ids must be an array with 1-100 items')
    .custom((ids) => {
      if (!ids.every((id: any) => typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))) {
        throw new Error('All conversation IDs must be valid UUIDs');
      }
      return true;
    }),
  body('data')
    .optional()
    .isObject()
    .withMessage('Data must be an object'),
];

// Create from template validation
export const createFromTemplateValidation = [
  body('template_id')
    .notEmpty()
    .withMessage('Template ID is required'),
  body('title')
    .optional()
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Title must be between 1 and 500 characters'),
  body('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
  body('variables')
    .optional()
    .isObject()
    .withMessage('Variables must be an object'),
];