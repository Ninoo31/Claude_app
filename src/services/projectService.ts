// backend/src/services/projectService.ts - Service de gestion des projets
import { eq, and, desc, asc, sql, like, inArray, isNull, gte, lte, count } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { databaseService } from '@/services/databaseService';
import { auditService } from '@/services/auditService';
import { webhookService } from '@/services/webhookService';
import { logger } from '@/utils/logger';
import * as tenantSchema from '@/database/schemas/tenant.schema';
import type { 
  Project, 
  NewProject, 
  ProjectUpdate, 
  ProjectWithStats, 
  ProjectAnalyticsData,
  PaginatedResponse,
  SearchResult 
} from '@/types/database.types';

/**
 * Project Service - Complete project management
 * Handles CRUD operations, analytics, collaboration, and project lifecycle
 */
class ProjectService {
  /**
   * Create a new project with full validation and audit trail
   * @param userId - User ID
   * @param projectData - Project creation data
   */
  async createProject(userId: string, projectData: {
    name: string;
    description?: string;
    priority?: 'low' | 'medium' | 'high' | 'critical';
    color?: string;
    icon?: string;
    tags?: string[];
    deadline?: string;
    collaborators?: Array<{ email: string; role: string; permissions: string[] }>;
    settings?: Record<string, any>;
  }): Promise<Project> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Validate project name uniqueness
      const existingProject = await db
        .select({ id: tenantSchema.projects.id })
        .from(tenantSchema.projects)
        .where(
          and(
            eq(tenantSchema.projects.name, projectData.name),
            isNull(tenantSchema.projects.archived_at)
          )
        )
        .limit(1);

      if (existingProject.length > 0) {
        throw new Error('A project with this name already exists');
      }

      // Prepare project settings with defaults
      const defaultSettings = {
        auto_archive_days: 90,
        default_importance_level: 3,
        ai_summary_enabled: true,
        collaboration_enabled: true,
        webhook_notifications: false,
        auto_backup: true,
        conversation_templates: [],
        custom_fields: {},
      };

      const projectSettings = { ...defaultSettings, ...projectData.settings };

      // Create project
      const [project] = await db
        .insert(tenantSchema.projects)
        .values({
          name: projectData.name.trim(),
          description: projectData.description?.trim(),
          priority: projectData.priority || 'medium',
          color: projectData.color || '#3B82F6',
          icon: projectData.icon || 'folder',
          tags: projectData.tags || [],
          deadline: projectData.deadline ? new Date(projectData.deadline) : null,
          collaborators: projectData.collaborators || [],
          status: 'active',
          settings: projectSettings,
          metadata: {
            created_by: userId,
            creation_source: 'api',
            initial_setup_completed: false,
          },
        })
        .returning();

      // Create default conversation templates if enabled
      if (projectSettings.create_default_templates) {
        await this.createDefaultConversationTemplates(userId, project.id);
      }

      // Log audit trail
      await auditService.log({
        user_id: userId,
        action: 'create',
        resource_type: 'project',
        resource_id: project.id,
        details: {
          project_name: project.name,
          priority: project.priority,
          settings: projectSettings,
        },
      });

      // Trigger webhook if configured
      await webhookService.trigger(userId, 'project.created', {
        project,
        created_by: userId,
      });

      logger.info(`Project created: ${project.id} (${project.name}) for user ${userId}`);
      return project;
    } catch (error) {
      logger.error('Failed to create project:', error);
      throw error;
    }
  }

  /**
   * Get user's projects with advanced filtering and sorting
   * @param userId - User ID
   * @param filters - Comprehensive filter options
   */
  async getUserProjects(userId: string, filters?: {
    status?: 'active' | 'archived' | 'completed' | 'paused';
    priority?: 'low' | 'medium' | 'high' | 'critical';
    search?: string;
    tags?: string[];
    created_after?: string;
    created_before?: string;
    deadline_after?: string;
    deadline_before?: string;
    has_deadline?: boolean;
    has_collaborators?: boolean;
    limit?: number;
    offset?: number;
    sortBy?: 'name' | 'created_at' | 'updated_at' | 'priority' | 'deadline' | 'activity';
    sortOrder?: 'asc' | 'desc';
    include_stats?: boolean;
    include_archived?: boolean;
  }): Promise<PaginatedResponse<ProjectWithStats>> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      // Build base query with optional stats
      let baseQuery = db
        .select({
          ...tenantSchema.projects,
          ...(filters?.include_stats && {
            conversation_count: sql<number>`(
              SELECT COUNT(*) FROM ${tenantSchema.conversations} 
              WHERE project_id = ${tenantSchema.projects.id} 
              AND status != 'archived'
            )`,
            message_count: sql<number>`(
              SELECT COUNT(*) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            total_tokens: sql<number>`(
              SELECT COALESCE(SUM(m.tokens_used), 0) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            last_activity: sql<string>`(
              SELECT MAX(m.created_at) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            collaborator_count: sql<number>`jsonb_array_length(COALESCE(${tenantSchema.projects.collaborators}, '[]'::jsonb))`,
          }),
        })
        .from(tenantSchema.projects);

      let countQuery = db
        .select({ count: sql`count(*)` })
        .from(tenantSchema.projects);

      // Apply filters
      const conditions: any[] = [];

      if (filters?.status) {
        conditions.push(eq(tenantSchema.projects.status, filters.status));
      }

      if (!filters?.include_archived) {
        conditions.push(isNull(tenantSchema.projects.archived_at));
      }

      if (filters?.priority) {
        conditions.push(eq(tenantSchema.projects.priority, filters.priority));
      }

      if (filters?.search) {
        conditions.push(
          sql`(
            ${tenantSchema.projects.name} ILIKE ${`%${filters.search}%`} OR 
            ${tenantSchema.projects.description} ILIKE ${`%${filters.search}%`} OR
            EXISTS (
              SELECT 1 FROM jsonb_array_elements_text(${tenantSchema.projects.tags}) AS tag 
              WHERE tag ILIKE ${`%${filters.search}%`}
            )
          )`
        );
      }

      if (filters?.tags && filters.tags.length > 0) {
        conditions.push(
          sql`${tenantSchema.projects.tags} @> ${JSON.stringify(filters.tags)}`
        );
      }

      if (filters?.created_after) {
        conditions.push(gte(tenantSchema.projects.created_at, new Date(filters.created_after)));
      }

      if (filters?.created_before) {
        conditions.push(lte(tenantSchema.projects.created_at, new Date(filters.created_before)));
      }

      if (filters?.deadline_after) {
        conditions.push(
          and(
            isNull(tenantSchema.projects.deadline).not(),
            gte(tenantSchema.projects.deadline, new Date(filters.deadline_after))
          )
        );
      }

      if (filters?.deadline_before) {
        conditions.push(
          and(
            isNull(tenantSchema.projects.deadline).not(),
            lte(tenantSchema.projects.deadline, new Date(filters.deadline_before))
          )
        );
      }

      if (filters?.has_deadline === true) {
        conditions.push(isNull(tenantSchema.projects.deadline).not());
      } else if (filters?.has_deadline === false) {
        conditions.push(isNull(tenantSchema.projects.deadline));
      }

      if (filters?.has_collaborators === true) {
        conditions.push(sql`jsonb_array_length(COALESCE(${tenantSchema.projects.collaborators}, '[]'::jsonb)) > 0`);
      } else if (filters?.has_collaborators === false) {
        conditions.push(sql`jsonb_array_length(COALESCE(${tenantSchema.projects.collaborators}, '[]'::jsonb)) = 0`);
      }

      // Apply WHERE conditions
      if (conditions.length > 0) {
        const whereClause = conditions.reduce((acc, condition) => 
          acc ? and(acc, condition) : condition
        );
        baseQuery = baseQuery.where(whereClause);
        countQuery = countQuery.where(whereClause);
      }

      // Apply sorting
      const sortBy = filters?.sortBy || 'updated_at';
      const sortOrder = filters?.sortOrder || 'desc';
      
      switch (sortBy) {
        case 'activity':
          if (filters?.include_stats) {
            baseQuery = sortOrder === 'desc' 
              ? baseQuery.orderBy(sql`last_activity DESC NULLS LAST`)
              : baseQuery.orderBy(sql`last_activity ASC NULLS LAST`);
          } else {
            baseQuery = sortOrder === 'desc'
              ? baseQuery.orderBy(desc(tenantSchema.projects.updated_at))
              : baseQuery.orderBy(asc(tenantSchema.projects.updated_at));
          }
          break;
        case 'deadline':
          baseQuery = sortOrder === 'desc'
            ? baseQuery.orderBy(sql`${tenantSchema.projects.deadline} DESC NULLS LAST`)
            : baseQuery.orderBy(sql`${tenantSchema.projects.deadline} ASC NULLS LAST`);
          break;
        default:
          const sortColumn = tenantSchema.projects[sortBy as keyof typeof tenantSchema.projects];
          if (sortColumn) {
            baseQuery = sortOrder === 'desc' 
              ? baseQuery.orderBy(desc(sortColumn)) 
              : baseQuery.orderBy(asc(sortColumn));
          }
      }

      // Apply pagination
      const limit = filters?.limit || 20;
      const offset = filters?.offset || 0;
      
      baseQuery = baseQuery.limit(limit).offset(offset);

      // Execute queries
      const [projects, [{ count: totalCount }]] = await Promise.all([
        baseQuery,
        countQuery
      ]);

      const totalPages = Math.ceil(Number(totalCount) / limit);
      const currentPage = Math.floor(offset / limit) + 1;

      return {
        success: true,
        data: projects as ProjectWithStats[],
        pagination: {
          page: currentPage,
          limit,
          total: Number(totalCount),
          totalPages,
          hasNext: currentPage < totalPages,
          hasPrev: currentPage > 1,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Failed to get user projects:', error);
      throw error;
    }
  }

  /**
   * Get project by ID with comprehensive data
   * @param userId - User ID
   * @param projectId - Project ID
   * @param options - Data inclusion options
   */
  async getProjectById(userId: string, projectId: string, options?: {
    include_stats?: boolean;
    include_conversations?: boolean;
    include_analytics?: boolean;
    conversation_limit?: number;
  }): Promise<{
    project: ProjectWithStats | null;
    conversations?: any[];
    analytics?: Partial<ProjectAnalyticsData>;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get project with optional stats
      const projectQuery = db
        .select({
          ...tenantSchema.projects,
          ...(options?.include_stats && {
            conversation_count: sql<number>`(
              SELECT COUNT(*) FROM ${tenantSchema.conversations} 
              WHERE project_id = ${tenantSchema.projects.id} 
              AND status != 'archived'
            )`,
            message_count: sql<number>`(
              SELECT COUNT(*) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            total_tokens: sql<number>`(
              SELECT COALESCE(SUM(m.tokens_used), 0) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            last_activity: sql<string>`(
              SELECT MAX(m.created_at) FROM ${tenantSchema.messages} m
              JOIN ${tenantSchema.conversations} c ON m.conversation_id = c.id
              WHERE c.project_id = ${tenantSchema.projects.id}
              AND m.deleted_at IS NULL
            )`,
            collaborator_count: sql<number>`jsonb_array_length(COALESCE(${tenantSchema.projects.collaborators}, '[]'::jsonb))`,
          }),
        })
        .from(tenantSchema.projects)
        .where(eq(tenantSchema.projects.id, projectId))
        .limit(1);

      const [project] = await projectQuery;

      if (!project) {
        return { project: null };
      }

      const result: any = { project };

      // Include conversations if requested
      if (options?.include_conversations) {
        const conversationLimit = options.conversation_limit || 10;
        result.conversations = await db
          .select({
            id: tenantSchema.conversations.id,
            title: tenantSchema.conversations.title,
            status: tenantSchema.conversations.status,
            importance_level: tenantSchema.conversations.importance_level,
            message_count: tenantSchema.conversations.message_count,
            last_message_at: tenantSchema.conversations.last_message_at,
            created_at: tenantSchema.conversations.created_at,
            updated_at: tenantSchema.conversations.updated_at,
          })
          .from(tenantSchema.conversations)
          .where(eq(tenantSchema.conversations.project_id, projectId))
          .orderBy(desc(tenantSchema.conversations.updated_at))
          .limit(conversationLimit);
      }

      // Include analytics if requested
      if (options?.include_analytics) {
        result.analytics = await this.getProjectAnalytics(userId, projectId);
      }

      return result;
    } catch (error) {
      logger.error('Failed to get project by ID:', error);
      throw error;
    }
  }

  /**
   * Update project with validation and audit trail
   * @param userId - User ID
   * @param projectId - Project ID
   * @param updates - Project updates
   */
  async updateProject(userId: string, projectId: string, updates: ProjectUpdate): Promise<Project> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get current project for audit trail
      const [currentProject] = await db
        .select()
        .from(tenantSchema.projects)
        .where(eq(tenantSchema.projects.id, projectId))
        .limit(1);

      if (!currentProject) {
        throw new Error('Project not found');
      }

      // Validate name uniqueness if name is being updated
      if (updates.name && updates.name !== currentProject.name) {
        const existingProject = await db
          .select({ id: tenantSchema.projects.id })
          .from(tenantSchema.projects)
          .where(
            and(
              eq(tenantSchema.projects.name, updates.name),
              eq(tenantSchema.projects.id, projectId).not(),
              isNull(tenantSchema.projects.archived_at)
            )
          )
          .limit(1);

        if (existingProject.length > 0) {
          throw new Error('A project with this name already exists');
        }
      }

      // Handle status changes
      const statusUpdate: any = {};
      if (updates.status) {
        switch (updates.status) {
          case 'archived':
            statusUpdate.archived_at = new Date();
            break;
          case 'completed':
            statusUpdate.completed_at = new Date();
            break;
          case 'active':
            statusUpdate.archived_at = null;
            statusUpdate.completed_at = null;
            break;
        }
      }

      // Prepare update data
      const updateData = {
        ...updates,
        ...statusUpdate,
        updated_at: new Date(),
        metadata: {
          ...currentProject.metadata,
          last_modified_by: userId,
          modification_count: (currentProject.metadata as any)?.modification_count + 1 || 1,
        },
      };

      // Update project
      const [updatedProject] = await db
        .update(tenantSchema.projects)
        .set(updateData)
        .where(eq(tenantSchema.projects.id, projectId))
        .returning();

      // Log audit trail
      await auditService.log({
        user_id: userId,
        action: 'update',
        resource_type: 'project',
        resource_id: projectId,
        details: {
          changes: updates,
          previous_values: currentProject,
        },
      });

      // Trigger webhook
      await webhookService.trigger(userId, 'project.updated', {
        project: updatedProject,
        changes: updates,
        updated_by: userId,
      });

      logger.info(`Project updated: ${projectId} for user ${userId}`);
      return updatedProject;
    } catch (error) {
      logger.error('Failed to update project:', error);
      throw error;
    }
  }

  /**
   * Delete project with cascade handling
   * @param userId - User ID
   * @param projectId - Project ID
   * @param options - Deletion options
   */
  async deleteProject(userId: string, projectId: string, options?: {
    hard_delete?: boolean;
    backup_conversations?: boolean;
  }): Promise<{ deleted: boolean; backup_created?: boolean }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get project for audit trail
      const [project] = await db
        .select()
        .from(tenantSchema.projects)
        .where(eq(tenantSchema.projects.id, projectId))
        .limit(1);

      if (!project) {
        throw new Error('Project not found');
      }

      let backupCreated = false;

      // Create backup if requested
      if (options?.backup_conversations) {
        backupCreated = await this.backupProjectData(userId, projectId);
      }

      if (options?.hard_delete) {
        // Hard delete - permanently remove project and all related data
        await db
          .delete(tenantSchema.projects)
          .where(eq(tenantSchema.projects.id, projectId));
      } else {
        // Soft delete - mark as archived
        await db
          .update(tenantSchema.projects)
          .set({
            status: 'archived',
            archived_at: new Date(),
            updated_at: new Date(),
          })
          .where(eq(tenantSchema.projects.id, projectId));
      }

      // Log audit trail
      await auditService.log({
        user_id: userId,
        action: options?.hard_delete ? 'delete' : 'archive',
        resource_type: 'project',
        resource_id: projectId,
        details: {
          project_name: project.name,
          hard_delete: options?.hard_delete || false,
          backup_created: backupCreated,
        },
      });

      // Trigger webhook
      await webhookService.trigger(userId, 'project.deleted', {
        project_id: projectId,
        project_name: project.name,
        deleted_by: userId,
        hard_delete: options?.hard_delete || false,
      });

      logger.info(`Project ${options?.hard_delete ? 'deleted' : 'archived'}: ${projectId} for user ${userId}`);
      
      return { 
        deleted: true, 
        backup_created: backupCreated 
      };
    } catch (error) {
      logger.error('Failed to delete project:', error);
      throw error;
    }
  }

  /**
   * Get project analytics with comprehensive metrics
   * @param userId - User ID
   * @param projectId - Project ID
   * @param timeRange - Time range for analytics (default: 30 days)
   */
  async getProjectAnalytics(userId: string, projectId: string, timeRange = 30): Promise<ProjectAnalyticsData> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Overview metrics
      const [overview] = await db
        .select({
          total_conversations: sql<number>`COUNT(DISTINCT ${tenantSchema.conversations.id})`,
          total_messages: sql<number>`COUNT(${tenantSchema.messages.id})`,
          total_tokens: sql<number>`COALESCE(SUM(${tenantSchema.messages.tokens_used}), 0)`,
          total_cost: sql<number>`COALESCE(SUM(${tenantSchema.messages.cost}), 0)`,
          active_conversations: sql<number>`COUNT(DISTINCT CASE WHEN ${tenantSchema.conversations.status} = 'active' THEN ${tenantSchema.conversations.id} END)`,
          avg_importance: sql<number>`AVG(${tenantSchema.conversations.importance_level})`,
        })
        .from(tenantSchema.conversations)
        .leftJoin(tenantSchema.messages, eq(tenantSchema.conversations.id, tenantSchema.messages.conversation_id))
        .where(
          and(
            eq(tenantSchema.conversations.project_id, projectId),
            isNull(tenantSchema.messages.deleted_at)
          )
        );

      // Activity timeline (last 30 days)
      const activityTimeline = await db
        .select({
          date: sql<string>`DATE(${tenantSchema.conversations.created_at})`,
          conversations_created: sql<number>`COUNT(DISTINCT ${tenantSchema.conversations.id})`,
          messages_sent: sql<number>`COUNT(${tenantSchema.messages.id})`,
          tokens_used: sql<number>`COALESCE(SUM(${tenantSchema.messages.tokens_used}), 0)`,
        })
        .from(tenantSchema.conversations)
        .leftJoin(tenantSchema.messages, eq(tenantSchema.conversations.id, tenantSchema.messages.conversation_id))
        .where(
          and(
            eq(tenantSchema.conversations.project_id, projectId),
            gte(tenantSchema.conversations.created_at, sql`CURRENT_DATE - INTERVAL '${timeRange} days'`),
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(sql`DATE(${tenantSchema.conversations.created_at})`)
        .orderBy(sql`DATE(${tenantSchema.conversations.created_at})`);

      // Conversation distribution by importance
      const conversationDistribution = await db
        .select({
          importance_level: tenantSchema.conversations.importance_level,
          count: sql<number>`COUNT(*)`,
        })
        .from(tenantSchema.conversations)
        .where(eq(tenantSchema.conversations.project_id, projectId))
        .groupBy(tenantSchema.conversations.importance_level)
        .orderBy(tenantSchema.conversations.importance_level);

      // Add percentage calculation
      const totalConversations = conversationDistribution.reduce((sum, item) => sum + Number(item.count), 0);
      const distributionWithPercentage = conversationDistribution.map(item => ({
        importance_level: item.importance_level!,
        count: Number(item.count),
        percentage: totalConversations > 0 ? (Number(item.count) / totalConversations) * 100 : 0,
      }));

      // Topic analysis (from conversation analytics)
      const topicAnalysis = await db
        .select({
          topics: tenantSchema.conversationAnalytics.topics_discussed,
        })
        .from(tenantSchema.conversationAnalytics)
        .innerJoin(
          tenantSchema.conversations, 
          eq(tenantSchema.conversationAnalytics.conversation_id, tenantSchema.conversations.id)
        )
        .where(eq(tenantSchema.conversations.project_id, projectId));

      // Process topic data
      const topicFrequency: Record<string, { frequency: number; conversations: Set<string> }> = {};
      
      topicAnalysis.forEach(row => {
        const topics = Array.isArray(row.topics) ? row.topics : [];
        topics.forEach((topic: string) => {
          if (!topicFrequency[topic]) {
            topicFrequency[topic] = { frequency: 0, conversations: new Set() };
          }
          topicFrequency[topic].frequency += 1;
          topicFrequency[topic].conversations.add(row.topics as any); // conversation_id would be better
        });
      });

      const topicAnalysisResult = Object.entries(topicFrequency)
        .map(([topic, data]) => ({
          topic,
          frequency: data.frequency,
          conversations: data.conversations.size,
        }))
        .sort((a, b) => b.frequency - a.frequency)
        .slice(0, 20); // Top 20 topics

      // Cost analysis
      const costByModel = await db
        .select({
          model: tenantSchema.messages.model_used,
          cost: sql<number>`COALESCE(SUM(${tenantSchema.messages.cost}), 0)`,
          usage: sql<number>`COUNT(*)`,
        })
        .from(tenantSchema.messages)
        .innerJoin(tenantSchema.conversations, eq(tenantSchema.messages.conversation_id, tenantSchema.conversations.id))
        .where(
          and(
            eq(tenantSchema.conversations.project_id, projectId),
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(tenantSchema.messages.model_used);

      const costTrend = await db
        .select({
          date: sql<string>`DATE(${tenantSchema.messages.created_at})`,
          cost: sql<number>`COALESCE(SUM(${tenantSchema.messages.cost}), 0)`,
        })
        .from(tenantSchema.messages)
        .innerJoin(tenantSchema.conversations, eq(tenantSchema.messages.conversation_id, tenantSchema.conversations.id))
        .where(
          and(
            eq(tenantSchema.conversations.project_id, projectId),
            gte(tenantSchema.messages.created_at, sql`CURRENT_DATE - INTERVAL '${timeRange} days'`),
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(sql`DATE(${tenantSchema.messages.created_at})`)
        .orderBy(sql`DATE(${tenantSchema.messages.created_at})`);

      return {
        overview: {
          total_conversations: Number(overview.total_conversations),
          total_messages: Number(overview.total_messages),
          total_tokens: Number(overview.total_tokens),
          total_cost: Number(overview.total_cost),
          active_conversations: Number(overview.active_conversations),
          avg_importance: Number(overview.avg_importance) || 0,
        },
        activity_timeline: activityTimeline.map(item => ({
          date: item.date,
          conversations_created: Number(item.conversations_created),
          messages_sent: Number(item.messages_sent),
          tokens_used: Number(item.tokens_used),
        })),
        conversation_distribution: distributionWithPercentage,
        topic_analysis: topicAnalysisResult,
        cost_analysis: {
          total_cost: Number(overview.total_cost),
          cost_by_model: costByModel.map(item => ({
            model: item.model || 'unknown',
            cost: Number(item.cost),
            usage: Number(item.usage),
          })),
          cost_trend: costTrend.map(item => ({
            date: item.date,
            cost: Number(item.cost),
          })),
        },
      };
    } catch (error) {
      logger.error('Failed to get project analytics:', error);
      throw error;
    }
  }

   /**
   * Get project dashboard data
   * @param userId - User ID
   */
  async getProjectDashboard(userId: string): Promise<{
    total_projects: number;
    active_projects: number;
    archived_projects: number;
    recent_projects: Project[];
    project_priority_breakdown: Record<string, number>;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get project counts
      const [projectCounts] = await db
        .select({
          total: sql<number>`count(*)`,
          active: sql<number>`count(case when status = 'active' then 1 end)`,
          archived: sql<number>`count(case when status = 'archived' then 1 end)`,
        })
        .from(tenantSchema.projects);

      // Get recent projects
      const recentProjects = await db
        .select()
        .from(tenantSchema.projects)
        .where(eq(tenantSchema.projects.status, 'active'))
        .orderBy(desc(tenantSchema.projects.updated_at))
        .limit(5);

      // Get priority breakdown
      const priorityBreakdown = await db
        .select({
          priority: tenantSchema.projects.priority,
          count: sql<number>`count(*)`,
        })
        .from(tenantSchema.projects)
        .where(eq(tenantSchema.projects.status, 'active'))
        .groupBy(tenantSchema.projects.priority);

      const priorityMap = priorityBreakdown.reduce((acc, item) => {
        acc[item.priority!] = Number(item.count);
        return acc;
      }, {} as Record<string, number>);

      return {
        total_projects: Number(projectCounts.total),
        active_projects: Number(projectCounts.active),
        archived_projects: Number(projectCounts.archived),
        recent_projects: recentProjects,
        project_priority_breakdown: priorityMap,
      };
    } catch (error) {
      logger.error('Failed to get project dashboard:', error);
      throw error;
    }
  }
}

export const projectService = new ProjectService();