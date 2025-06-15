import { Request, Response } from 'express';
import { body, query, param, validationResult } from 'express-validator';
import { projectService } from '@/services/projectService';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import { asyncHandler, createError } from '@/middleware/errorHandler';
import type { ApiResponse, PaginatedResponse, ProjectFilters } from '@/types/database.types';

/**
 * Project Controller
 * Handles all project-related endpoints
 */
class ProjectController {
  /**
   * Get user's projects with filtering and pagination
   * GET /api/v1/projects
   */
  getProjects = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid query parameters', errors.array());
    }

    const userId = req.user!.id;
    const filters: ProjectFilters = {
      status: req.query.status as any,
      priority: req.query.priority as any,
      search: req.query.search as string,
      tags: req.query.tags ? (req.query.tags as string).split(',') : undefined,
      created_after: req.query.created_after as string,
      created_before: req.query.created_before as string,
      deadline_after: req.query.deadline_after as string,
      deadline_before: req.query.deadline_before as string,
      has_deadline: req.query.has_deadline ? req.query.has_deadline === 'true' : undefined,
      has_collaborators: req.query.has_collaborators ? req.query.has_collaborators === 'true' : undefined,
      limit: req.query.limit ? parseInt(req.query.limit as string) : 20,
      offset: req.query.offset ? parseInt(req.query.offset as string) : 0,
      sortBy: req.query.sortBy as any,
      sortOrder: req.query.sortOrder as any,
      include_stats: req.query.include_stats === 'true',
      include_archived: req.query.include_archived === 'true',
    };

    const result = await projectService.getUserProjects(userId, filters);

    res.status(200).json(result);
  });

  /**
   * Create a new project
   * POST /api/v1/projects
   */
  createProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const projectData = {
      name: req.body.name,
      description: req.body.description,
      priority: req.body.priority,
      color: req.body.color,
      icon: req.body.icon,
      tags: req.body.tags,
      deadline: req.body.deadline,
      collaborators: req.body.collaborators,
      settings: req.body.settings,
    };

    const project = await projectService.createProject(userId, projectData);

    const response: ApiResponse = {
      success: true,
      data: { project },
      message: 'Project created successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Get project by ID
   * GET /api/v1/projects/:projectId
   */
  getProjectById = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    
    const options = {
      include_stats: req.query.include_stats === 'true',
      include_conversations: req.query.include_conversations === 'true',
      include_analytics: req.query.include_analytics === 'true',
      conversation_limit: req.query.conversation_limit ? parseInt(req.query.conversation_limit as string) : 10,
    };

    const result = await projectService.getProjectById(userId, projectId, options);

    if (!result.project) {
      throw createError.notFound('Project');
    }

    const response: ApiResponse = {
      success: true,
      data: result,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Update project
   * PUT /api/v1/projects/:projectId
   */
  updateProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const updates = {
      name: req.body.name,
      description: req.body.description,
      status: req.body.status,
      priority: req.body.priority,
      color: req.body.color,
      icon: req.body.icon,
      tags: req.body.tags,
      deadline: req.body.deadline ? new Date(req.body.deadline) : undefined,
      collaborators: req.body.collaborators,
      settings: req.body.settings,
    };

    // Remove undefined values
    Object.keys(updates).forEach(key => {
      if (updates[key as keyof typeof updates] === undefined) {
        delete updates[key as keyof typeof updates];
      }
    });

    const project = await projectService.updateProject(userId, projectId, updates);

    const response: ApiResponse = {
      success: true,
      data: { project },
      message: 'Project updated successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Delete project
   * DELETE /api/v1/projects/:projectId
   */
  deleteProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const options = {
      hard_delete: req.query.hard_delete === 'true',
      backup_conversations: req.query.backup_conversations === 'true',
    };

    const result = await projectService.deleteProject(userId, projectId, options);

    const response: ApiResponse = {
      success: true,
      data: result,
      message: `Project ${options.hard_delete ? 'permanently deleted' : 'archived'} successfully`,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Archive project
   * POST /api/v1/projects/:projectId/archive
   */
  archiveProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;

    const project = await projectService.updateProject(userId, projectId, {
      status: 'archived',
    });

    const response: ApiResponse = {
      success: true,
      data: { project },
      message: 'Project archived successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Get project statistics
   * GET /api/v1/projects/:projectId/stats
   */
  getProjectStats = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const timeRange = req.query.time_range ? parseInt(req.query.time_range as string) : 30;

    const analytics = await projectService.getProjectAnalytics(userId, projectId, timeRange);

    const response: ApiResponse = {
      success: true,
      data: { analytics },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Get project dashboard data
   * GET /api/v1/projects/dashboard
   */
  getDashboard = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;

    const dashboard = await projectService.getProjectDashboard(userId);

    const response: ApiResponse = {
      success: true,
      data: dashboard,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Duplicate project
   * POST /api/v1/projects/:projectId/duplicate
   */
  duplicateProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const { name, include_conversations = false } = req.body;

    // Get original project
    const originalResult = await projectService.getProjectById(userId, projectId, {
      include_conversations: include_conversations,
    });

    if (!originalResult.project) {
      throw createError.notFound('Project');
    }

    const original = originalResult.project;

    // Create duplicate
    const duplicateData = {
      name: name || `${original.name} (Copy)`,
      description: original.description,
      priority: original.priority,
      color: original.color,
      icon: original.icon,
      tags: [...(original.tags || []), 'duplicate'],
      settings: original.settings,
    };

    const duplicate = await projectService.createProject(userId, duplicateData);

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'duplicate',
      project_id: duplicate.id,
      changes: {
        original_project_id: projectId,
        include_conversations,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { 
        project: duplicate,
        original_project_id: projectId,
      },
      message: 'Project duplicated successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Get project collaborators
   * GET /api/v1/projects/:projectId/collaborators
   */
  getCollaborators = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;

    const result = await projectService.getProjectById(userId, projectId);

    if (!result.project) {
      throw createError.notFound('Project');
    }

    const collaborators = result.project.collaborators || [];

    const response: ApiResponse = {
      success: true,
      data: { collaborators },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Add project collaborator
   * POST /api/v1/projects/:projectId/collaborators
   */
  addCollaborator = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const { email, role, permissions } = req.body;

    // Get current project
    const result = await projectService.getProjectById(userId, projectId);
    if (!result.project) {
      throw createError.notFound('Project');
    }

    const currentCollaborators = result.project.collaborators || [];
    
    // Check if collaborator already exists
    if (currentCollaborators.some((c: any) => c.email === email)) {
      throw createError.conflict('Collaborator already exists');
    }

    // Add new collaborator
    const newCollaborator = {
      email,
      role: role || 'viewer',
      permissions: permissions || ['read'],
      added_at: new Date().toISOString(),
      added_by: userId,
      status: 'pending',
    };

    const updatedCollaborators = [...currentCollaborators, newCollaborator];

    const project = await projectService.updateProject(userId, projectId, {
      collaborators: updatedCollaborators,
    });

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'add_collaborator',
      project_id: projectId,
      changes: {
        collaborator_email: email,
        role,
        permissions,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { 
        project,
        collaborator: newCollaborator,
      },
      message: 'Collaborator added successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Remove project collaborator
   * DELETE /api/v1/projects/:projectId/collaborators/:email
   */
  removeCollaborator = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const email = req.params.email;

    // Get current project
    const result = await projectService.getProjectById(userId, projectId);
    if (!result.project) {
      throw createError.notFound('Project');
    }

    const currentCollaborators = result.project.collaborators || [];
    
    // Check if collaborator exists
    const collaboratorIndex = currentCollaborators.findIndex((c: any) => c.email === email);
    if (collaboratorIndex === -1) {
      throw createError.notFound('Collaborator');
    }

    // Remove collaborator
    const updatedCollaborators = currentCollaborators.filter((c: any) => c.email !== email);

    const project = await projectService.updateProject(userId, projectId, {
      collaborators: updatedCollaborators,
    });

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'remove_collaborator',
      project_id: projectId,
      changes: {
        collaborator_email: email,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { project },
      message: 'Collaborator removed successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Update collaborator permissions
   * PUT /api/v1/projects/:projectId/collaborators/:email
   */
  updateCollaborator = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const email = req.params.email;
    const { role, permissions } = req.body;

    // Get current project
    const result = await projectService.getProjectById(userId, projectId);
    if (!result.project) {
      throw createError.notFound('Project');
    }

    const currentCollaborators = result.project.collaborators || [];
    
    // Find and update collaborator
    const collaboratorIndex = currentCollaborators.findIndex((c: any) => c.email === email);
    if (collaboratorIndex === -1) {
      throw createError.notFound('Collaborator');
    }

    currentCollaborators[collaboratorIndex] = {
      ...currentCollaborators[collaboratorIndex],
      role: role || currentCollaborators[collaboratorIndex].role,
      permissions: permissions || currentCollaborators[collaboratorIndex].permissions,
      updated_at: new Date().toISOString(),
      updated_by: userId,
    };

    const project = await projectService.updateProject(userId, projectId, {
      collaborators: currentCollaborators,
    });

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'update_collaborator',
      project_id: projectId,
      changes: {
        collaborator_email: email,
        role,
        permissions,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { 
        project,
        collaborator: currentCollaborators[collaboratorIndex],
      },
      message: 'Collaborator updated successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Bulk operations on projects
   * POST /api/v1/projects/bulk
   */
  bulkOperations = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { action, project_ids, data } = req.body;

    if (!Array.isArray(project_ids) || project_ids.length === 0) {
      throw createError.validation('project_ids must be a non-empty array', []);
    }

    const results = [];
    const errors_occurred = [];

    for (const projectId of project_ids) {
      try {
        switch (action) {
          case 'update':
            const project = await projectService.updateProject(userId, projectId, data);
            results.push({ project_id: projectId, status: 'success', data: project });
            break;

          case 'delete':
            const deleteResult = await projectService.deleteProject(userId, projectId, data);
            results.push({ project_id: projectId, status: 'success', data: deleteResult });
            break;

          case 'archive':
            const archived = await projectService.updateProject(userId, projectId, { status: 'archived' });
            results.push({ project_id: projectId, status: 'success', data: archived });
            break;

          case 'restore':
            const restored = await projectService.updateProject(userId, projectId, { status: 'active' });
            results.push({ project_id: projectId, status: 'success', data: restored });
            break;

          default:
            throw new Error(`Unsupported bulk action: ${action}`);
        }
      } catch (error: any) {
        errors_occurred.push({
          project_id: projectId,
          error: error.message,
        });
      }
    }

    // Log bulk operation
    await auditService.log({
      user_id: userId,
      action: `bulk_${action}`,
      resource_type: 'project',
      details: {
        project_ids,
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
          total: project_ids.length,
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
   * Get project templates
   * GET /api/v1/projects/templates
   */
  getProjectTemplates = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;
    const category = req.query.category as string;

    // This would be implemented in the project service
    // For now, return placeholder templates
    const templates = [
      {
        id: 'template_1',
        name: 'Software Development Project',
        description: 'Template for software development projects with common conversation types',
        category: 'development',
        icon: 'code',
        color: '#3B82F6',
        settings: {
          default_conversations: [
            { title: 'Project Planning', type: 'planning' },
            { title: 'Code Review', type: 'review' },
            { title: 'Bug Reports', type: 'support' },
          ],
        },
        usage_count: 45,
      },
      {
        id: 'template_2',
        name: 'Research Project',
        description: 'Template for research and analysis projects',
        category: 'research',
        icon: 'search',
        color: '#10B981',
        settings: {
          default_conversations: [
            { title: 'Literature Review', type: 'analysis' },
            { title: 'Data Analysis', type: 'analysis' },
            { title: 'Research Notes', type: 'chat' },
          ],
        },
        usage_count: 23,
      },
    ];

    const filteredTemplates = category 
      ? templates.filter(t => t.category === category)
      : templates;

    const response: ApiResponse = {
      success: true,
      data: { templates: filteredTemplates },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Create project from template
   * POST /api/v1/projects/from-template
   */
  createFromTemplate = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const { template_id, name, description, customizations } = req.body;

    // This would fetch the actual template and apply customizations
    // For now, create a basic project
    const projectData = {
      name,
      description: description || `Project created from template ${template_id}`,
      tags: ['template', template_id],
      settings: {
        created_from_template: template_id,
        template_customizations: customizations,
        ...customizations?.settings,
      },
    };

    const project = await projectService.createProject(userId, projectData);

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'create_from_template',
      project_id: project.id,
      changes: {
        template_id,
        customizations,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    const response: ApiResponse = {
      success: true,
      data: { project },
      message: 'Project created from template successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  });

  /**
   * Export project data
   * GET /api/v1/projects/:projectId/export
   */
  exportProject = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const projectId = req.params.projectId;
    const format = (req.query.format as 'json' | 'csv' | 'pdf') || 'json';
    const includeConversations = req.query.include_conversations !== 'false';

    // Get project with all data
    const result = await projectService.getProjectById(userId, projectId, {
      include_stats: true,
      include_conversations: includeConversations,
      include_analytics: true,
    });

    if (!result.project) {
      throw createError.notFound('Project');
    }

    // Log audit event
    await auditService.logProject({
      user_id: userId,
      action: 'export',
      project_id: projectId,
      changes: {
        format,
        include_conversations: includeConversations,
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
    });

    // Generate export based on format
    let content: string;
    let mimeType: string;
    let filename: string;

    switch (format) {
      case 'json':
        content = JSON.stringify(result, null, 2);
        mimeType = 'application/json';
        filename = `project_${result.project.name.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.json`;
        break;
      
      case 'csv':
        // Convert project data to CSV format
        content = this.generateCSVExport(result);
        mimeType = 'text/csv';
        filename = `project_${result.project.name.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.csv`;
        break;
      
      default:
        throw createError.validation('Unsupported export format', []);
    }

    // Set appropriate headers for file download
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', Buffer.byteLength(content, 'utf8'));

    res.status(200).send(content);
  });

  /**
   * Generate CSV export content
   * @param projectData - Project data to export
   */
  private generateCSVExport(projectData: any): string {
    const lines = [];
    
    // Project header
    lines.push('Project Export');
    lines.push(`Name,"${projectData.project.name}"`);
    lines.push(`Description,"${projectData.project.description || ''}"`);
    lines.push(`Status,"${projectData.project.status}"`);
    lines.push(`Priority,"${projectData.project.priority}"`);
    lines.push(`Created,"${projectData.project.created_at}"`);
    lines.push('');

    // Conversations if included
    if (projectData.conversations && projectData.conversations.length > 0) {
      lines.push('Conversations');
      lines.push('Title,Status,Messages,Created,Updated');
      
      projectData.conversations.forEach((conv: any) => {
        lines.push(`"${conv.title}","${conv.status}",${conv.message_count || 0},"${conv.created_at}","${conv.updated_at}"`);
      });
      lines.push('');
    }

    // Analytics if included
    if (projectData.analytics) {
      lines.push('Analytics');
      lines.push(`Total Conversations,${projectData.analytics.overview?.total_conversations || 0}`);
      lines.push(`Total Messages,${projectData.analytics.overview?.total_messages || 0}`);
      lines.push(`Total Tokens,${projectData.analytics.overview?.total_tokens || 0}`);
      lines.push(`Total Cost,${projectData.analytics.overview?.total_cost || 0}`);
    }

    return lines.join('\n');
  }
}

// Create controller instance
export const projectController = new ProjectController();

/**
 * Validation Rules
 */

// Create project validation
export const createProjectValidation = [
  body('name')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Project name must be between 1 and 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Priority must be low, medium, high, or critical'),
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Color must be a valid hex color code'),
  body('icon')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Icon must not exceed 50 characters'),
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
  body('deadline')
    .optional()
    .isISO8601()
    .withMessage('Deadline must be a valid ISO 8601 date'),
  body('collaborators')
    .optional()
    .isArray()
    .withMessage('Collaborators must be an array'),
  body('settings')
    .optional()
    .isObject()
    .withMessage('Settings must be an object'),
];

// Update project validation
export const updateProjectValidation = [
  param('projectId')
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Project name must be between 1 and 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  body('status')
    .optional()
    .isIn(['active', 'archived', 'completed', 'paused'])
    .withMessage('Status must be active, archived, completed, or paused'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Priority must be low, medium, high, or critical'),
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Color must be a valid hex color code'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('deadline')
    .optional()
    .isISO8601()
    .withMessage('Deadline must be a valid ISO 8601 date'),
];

// Project ID param validation
export const projectIdValidation = [
  param('projectId')
    .isUUID()
    .withMessage('Project ID must be a valid UUID'),
];

// Get projects validation
export const getProjectsValidation = [
  query('status')
    .optional()
    .isIn(['active', 'archived', 'completed', 'paused'])
    .withMessage('Status must be active, archived, completed, or paused'),
  query('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Priority must be low, medium, high, or critical'),
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
    .isIn(['name', 'created_at', 'updated_at', 'priority', 'deadline', 'activity'])
    .withMessage('Invalid sort field'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc'),
];

// Collaborator validation
export const collaboratorValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('role')
    .optional()
    .isIn(['owner', 'admin', 'editor', 'viewer'])
    .withMessage('Role must be owner, admin, editor, or viewer'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array')
    .custom((permissions) => {
      const validPermissions = ['read', 'write', 'delete', 'manage'];
      if (permissions && !permissions.every((p: string) => validPermissions.includes(p))) {
        throw new Error('Invalid permission values');
      }
      return true;
    }),
];

// Bulk operations validation
export const bulkProjectOperationsValidation = [
  body('action')
    .isIn(['update', 'delete', 'archive', 'restore'])
    .withMessage('Action must be update, delete, archive, or restore'),
  body('project_ids')
    .isArray({ min: 1, max: 50 })
    .withMessage('project_ids must be an array with 1-50 items')
    .custom((ids) => {
      if (!ids.every((id: any) => typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))) {
        throw new Error('All project IDs must be valid UUIDs');
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
  body('name')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Project name must be between 1 and 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
  body('customizations')
    .optional()
    .isObject()
    .withMessage('Customizations must be an object'),
];