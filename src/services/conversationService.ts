import { eq, and, desc, asc, sql, like, isNull } from 'drizzle-orm';
import { databaseService } from '@/services/databaseService';
import { claudeService } from '@/services/claudeService';
import { logger } from '@/utils/logger';
import * as tenantSchema from '@/database/schemas/tenant.schema';
import type { Conversation, Message } from '@/types/database.types';
import { config } from '@/config/environment';

// Cleanup rate limits periodically
setInterval(() => {
  claudeService.cleanupRateLimits();
}, 300000); // Every 5 minutes import type { Conversation, NewConversation, Message, NewMessage } from '@/types/database.types';

/**
 * Conversation Service
 * Manages conversations within projects
 * Handles message storage, Claude integration, and conversation analytics
 */
class ConversationService {
  /**
   * Create a new conversation
   * @param userId - User ID
   * @param conversationData - Conversation creation data
   */
  async createConversation(userId: string, conversationData: {
    project_id?: string;
    title: string;
    description?: string;
    importance_level?: number;
    tags?: string[];
  }): Promise<Conversation> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      const [conversation] = await db
        .insert(tenantSchema.conversations)
        .values({
          project_id: conversationData.project_id,
          title: conversationData.title,
          description: conversationData.description,
          importance_level: conversationData.importance_level || 3,
          tags: conversationData.tags || [],
          status: 'active',
          metadata: {
            created_by: 'user',
            auto_summary: true,
          },
        })
        .returning();

      logger.info(`Conversation created: ${conversation.id} for user ${userId}`);
      return conversation;
    } catch (error) {
      logger.error('Failed to create conversation:', error);
      throw error;
    }
  }

  /**
   * Get conversations with filtering and pagination
   * @param userId - User ID
   * @param filters - Optional filters
   */
  async getConversations(userId: string, filters?: {
    project_id?: string;
    status?: 'active' | 'archived' | 'pinned';
    importance_level?: number;
    search?: string;
    tags?: string[];
    limit?: number;
    offset?: number;
    sortBy?: 'title' | 'created_at' | 'updated_at' | 'last_message_at' | 'importance_level';
    sortOrder?: 'asc' | 'desc';
  }): Promise<{ conversations: Conversation[]; total: number }> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      let query = db.select().from(tenantSchema.conversations);
      let countQuery = db.select({ count: sql`count(*)` }).from(tenantSchema.conversations);

      // Apply filters
      const conditions: any[] = [];

      if (filters?.project_id) {
        conditions.push(eq(tenantSchema.conversations.project_id, filters.project_id));
      }

      if (filters?.status) {
        conditions.push(eq(tenantSchema.conversations.status, filters.status));
      }

      if (filters?.importance_level) {
        conditions.push(eq(tenantSchema.conversations.importance_level, filters.importance_level));
      }

      if (filters?.search) {
        conditions.push(
          sql`(${tenantSchema.conversations.title} ILIKE ${`%${filters.search}%`} OR ${tenantSchema.conversations.description} ILIKE ${`%${filters.search}%`} OR ${tenantSchema.conversations.summary} ILIKE ${`%${filters.search}%`})`
        );
      }

      if (filters?.tags && filters.tags.length > 0) {
        conditions.push(
          sql`${tenantSchema.conversations.tags} @> ${JSON.stringify(filters.tags)}`
        );
      }

      // Apply WHERE conditions
      if (conditions.length > 0) {
        const whereClause = conditions.reduce((acc, condition) => 
          acc ? and(acc, condition) : condition
        );
        query = query.where(whereClause);
        countQuery = countQuery.where(whereClause);
      }

      // Apply sorting
      const sortBy = filters?.sortBy || 'updated_at';
      const sortOrder = filters?.sortOrder || 'desc';
      const sortColumn = tenantSchema.conversations[sortBy as keyof typeof tenantSchema.conversations];
      
      if (sortColumn) {
        query = sortOrder === 'desc' ? query.orderBy(desc(sortColumn)) : query.orderBy(asc(sortColumn));
      }

      // Apply pagination
      if (filters?.limit) {
        query = query.limit(filters.limit);
      }
      if (filters?.offset) {
        query = query.offset(filters.offset);
      }

      // Execute queries
      const [conversations, [{ count }]] = await Promise.all([
        query,
        countQuery
      ]);

      return {
        conversations,
        total: Number(count)
      };
    } catch (error) {
      logger.error('Failed to get conversations:', error);
      throw error;
    }
  }

  /**
   * Get conversation by ID with messages
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param includeMessages - Whether to include messages
   * @param messageLimit - Limit number of messages returned
   */
  async getConversationById(userId: string, conversationId: string, includeMessages = false, messageLimit = 100): Promise<{
    conversation: Conversation | null;
    messages?: Message[];
    hasMore?: boolean;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      const [conversation] = await db
        .select()
        .from(tenantSchema.conversations)
        .where(eq(tenantSchema.conversations.id, conversationId))
        .limit(1);

      if (!conversation) {
        return { conversation: null };
      }

      let messages: Message[] = [];
      let hasMore = false;

      if (includeMessages) {
        // Get messages with pagination
        const messagesResult = await db
          .select()
          .from(tenantSchema.messages)
          .where(
            and(
              eq(tenantSchema.messages.conversation_id, conversationId),
              isNull(tenantSchema.messages.deleted_at)
            )
          )
          .orderBy(asc(tenantSchema.messages.created_at))
          .limit(messageLimit + 1); // +1 to check if there are more

        if (messagesResult.length > messageLimit) {
          hasMore = true;
          messages = messagesResult.slice(0, messageLimit);
        } else {
          messages = messagesResult;
        }
      }

      return { conversation, messages, hasMore };
    } catch (error) {
      logger.error('Failed to get conversation by ID:', error);
      throw error;
    }
  }

  /**
   * Get messages for a conversation with pagination
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param options - Pagination and filtering options
   */
  async getConversationMessages(userId: string, conversationId: string, options?: {
    limit?: number;
    offset?: number;
    before?: string; // Message ID to get messages before
    after?: string;  // Message ID to get messages after
    includeDeleted?: boolean;
  }): Promise<{ messages: Message[]; hasMore: boolean; total: number }> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      let query = db.select().from(tenantSchema.messages);
      let countQuery = db.select({ count: sql`count(*)` }).from(tenantSchema.messages);

      // Base conditions
      const conditions = [eq(tenantSchema.messages.conversation_id, conversationId)];

      if (!options?.includeDeleted) {
        conditions.push(isNull(tenantSchema.messages.deleted_at));
      }

      // Pagination by message ID
      if (options?.before) {
        const beforeMessage = await db
          .select({ created_at: tenantSchema.messages.created_at })
          .from(tenantSchema.messages)
          .where(eq(tenantSchema.messages.id, options.before))
          .limit(1);
        
        if (beforeMessage.length > 0) {
          conditions.push(sql`${tenantSchema.messages.created_at} < ${beforeMessage[0].created_at}`);
        }
      }

      if (options?.after) {
        const afterMessage = await db
          .select({ created_at: tenantSchema.messages.created_at })
          .from(tenantSchema.messages)
          .where(eq(tenantSchema.messages.id, options.after))
          .limit(1);
        
        if (afterMessage.length > 0) {
          conditions.push(sql`${tenantSchema.messages.created_at} > ${afterMessage[0].created_at}`);
        }
      }

      // Apply conditions
      const whereClause = conditions.reduce((acc, condition) => 
        acc ? and(acc, condition) : condition
      );
      
      query = query.where(whereClause);
      countQuery = countQuery.where(whereClause);

      // Apply ordering and pagination
      query = query.orderBy(asc(tenantSchema.messages.created_at));
      
      const limit = options?.limit || 50;
      const offset = options?.offset || 0;
      
      query = query.limit(limit + 1).offset(offset); // +1 to check hasMore

      // Execute queries
      const [messagesResult, [{ count }]] = await Promise.all([
        query,
        countQuery
      ]);

      const hasMore = messagesResult.length > limit;
      const messages = hasMore ? messagesResult.slice(0, limit) : messagesResult;

      return {
        messages,
        hasMore,
        total: Number(count)
      };
    } catch (error) {
      logger.error('Failed to get conversation messages:', error);
      throw error;
    }
  }

  /**
   * Send message to Claude and store response
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param content - Message content
   * @param messageType - Type of message
   */
  async sendMessage(userId: string, conversationId: string, content: string, messageType: 'text' | 'command' = 'text'): Promise<{
    userMessage: Message;
    assistantMessage: Message;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get conversation for context
      const { conversation, messages } = await this.getConversationById(userId, conversationId, true, 20);
      if (!conversation) {
        throw new Error('Conversation not found');
      }

      // Store user message
      const [userMessage] = await db
        .insert(tenantSchema.messages)
        .values({
          conversation_id: conversationId,
          role: 'user',
          content,
          content_type: messageType,
          metadata: {
             timestamp: new Date().toISOString(),
            user_id: userId,
          },
        })
        .returning();

      // Get Claude response via n8n workflow
      const startTime = Date.now();
      const claudeResponse = await claudeService.sendMessage({
        user_id: userId,
        conversation_id: conversationId,
        user_message: content,
        importance_level: conversation.importance_level,
        conversation_context: {
          title: conversation.title,
          summary: conversation.summary,
          recent_messages: messages?.slice(-10).map(m => ({
            role: m.role,
            content: m.content,
            created_at: m.created_at
          })) || []
        }
      });
       const processingTime = Date.now() - startTime;

      // Store assistant response
      const [assistantMessage] = await db
        .insert(tenantSchema.messages)
        .values({
          conversation_id: conversationId,
          role: 'assistant',
          content: claudeResponse.response,
          content_type: 'text',
          tokens_used: claudeResponse.tokens_used,
          model_used: claudeResponse.model_used || 'claude-sonnet-4',
          processing_time_ms: processingTime,
          metadata: {
            timestamp: new Date().toISOString(),
            n8n_response: claudeResponse,
          },
        })
        .returning();

      // Update conversation statistics (handled by database triggers)
      // But we can also update last_message_at explicitly
      await db
        .update(tenantSchema.conversations)
        .set({
          last_message_at: new Date(),
          updated_at: new Date(),
        })
        .where(eq(tenantSchema.conversations.id, conversationId));

      // Auto-generate summary if needed (every 10 messages)
      if (conversation.message_count && conversation.message_count > 0 && conversation.message_count % 10 === 0) {
        this.generateConversationSummary(userId, conversationId).catch(error => {
          logger.warn('Failed to generate auto-summary:', error);
        });
      }

      // Generate analytics for today
      this.updateConversationAnalytics(userId, conversationId).catch(error => {
        logger.warn('Failed to update analytics:', error);
      });

      logger.info(`Message sent to conversation ${conversationId} for user ${userId}`);

      return { userMessage, assistantMessage };
    } catch (error) {
      logger.error('Failed to send message:', error);
      throw error;
    }
  }

  /**
   * Generate AI summary for conversation
   * @param userId - User ID
   * @param conversationId - Conversation ID
   */
  async generateConversationSummary(userId: string, conversationId: string): Promise<void> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get recent messages for summary
      const messages = await db
        .select()
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .orderBy(desc(tenantSchema.messages.created_at))
        .limit(30); // Get last 30 messages for comprehensive summary

      if (messages.length < 5) return; // Not enough content for summary

      // Create summary prompt
      const conversationText = messages.reverse().map(m => `${m.role}: ${m.content}`).join('\n\n');
      const summaryPrompt = `Please analyze this conversation and provide:
1. A concise summary (2-3 sentences)
2. Key topics discussed (comma-separated list of 3-5 topics)
3. Main achievements or decisions made
4. Any action items or next steps

Conversation:
${conversationText}

Please format your response as:
SUMMARY: [your summary]
TOPICS: [topic1, topic2, topic3]
ACHIEVEMENTS: [achievements if any]
ACTIONS: [action items if any]`;

      // Request summary from Claude
      const summaryRequest = {
        user_id: userId,
        conversation_id: `${conversationId}_summary`,
        user_message: summaryPrompt,
        importance_level: 5
      };

      const summaryResponse = await claudeService.sendMessage(summaryRequest);

      // Parse the response
      const { summary, topics } = this.parseSummaryResponse(summaryResponse.response);

      // Update conversation
      await db
        .update(tenantSchema.conversations)
        .set({
          summary,
          key_topics: topics.join(', '),
          updated_at: new Date(),
        })
        .where(eq(tenantSchema.conversations.id, conversationId));

      logger.info(`Generated summary for conversation ${conversationId}`);
    } catch (error) {
      logger.error('Failed to generate conversation summary:', error);
      throw error;
    }
  }

  /**
   * Parse Claude's summary response
   * @param response - Raw Claude response
   */
  private parseSummaryResponse(response: string): { summary: string; topics: string[] } {
    try {
      const lines = response.split('\n');
      let summary = '';
      let topics: string[] = [];

      for (const line of lines) {
        if (line.startsWith('SUMMARY:')) {
          summary = line.replace('SUMMARY:', '').trim();
        } else if (line.startsWith('TOPICS:')) {
          const topicsStr = line.replace('TOPICS:', '').trim();
          topics = topicsStr.split(',').map(t => t.trim()).filter(t => t.length > 0);
        }
      }

      // Fallback if parsing fails
      if (!summary) {
        summary = response.substring(0, 200) + '...';
      }
      if (topics.length === 0) {
        topics = this.extractTopicsFromText(response);
      }

      return { summary, topics };
    } catch (error) {
      logger.warn('Failed to parse summary response, using fallback');
      return {
        summary: response.substring(0, 200) + '...',
        topics: this.extractTopicsFromText(response)
      };
    }
  }

  /**
   * Extract topics from text using simple keyword analysis
   * @param text - Text to analyze
   */
  private extractTopicsFromText(text: string): string[] {
    const commonWords = new Set([
      'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
      'this', 'that', 'these', 'those', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may',
      'might', 'must', 'can', 'shall', 'summary', 'topics', 'achievements', 'actions'
    ]);

    const words = text.toLowerCase()
      .replace(/[^\w\s]/g, '')
      .split(/\s+/)
      .filter(word => word.length > 3 && !commonWords.has(word));

    // Count word frequency
    const wordCount = words.reduce((acc, word) => {
      acc[word] = (acc[word] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Return top 5 most frequent words as topics
    return Object.entries(wordCount)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([word]) => word);
  }

  /**
   * Update conversation analytics for today
   * @param userId - User ID
   * @param conversationId - Conversation ID
   */
  private async updateConversationAnalytics(userId: string, conversationId: string): Promise<void> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      // Use the database function to generate analytics
      await db.execute(sql`SELECT generate_conversation_analytics(${conversationId})`);
      
      logger.debug(`Updated analytics for conversation ${conversationId}`);
    } catch (error) {
      logger.error('Failed to update conversation analytics:', error);
    }
  }

  /**
   * Update conversation
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param updates - Conversation updates
   */
  async updateConversation(userId: string, conversationId: string, updates: Partial<{
    title: string;
    description: string;
    importance_level: number;
    status: 'active' | 'archived' | 'pinned';
    tags: string[];
    project_id: string;
  }>): Promise<Conversation> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      const [updatedConversation] = await db
        .update(tenantSchema.conversations)
        .set({
          ...updates,
          updated_at: new Date(),
        })
        .where(eq(tenantSchema.conversations.id, conversationId))
        .returning();

      if (!updatedConversation) {
        throw new Error('Conversation not found');
      }

      logger.info(`Conversation updated: ${conversationId} for user ${userId}`);
      return updatedConversation;
    } catch (error) {
      logger.error('Failed to update conversation:', error);
      throw error;
    }
  }

  /**
   * Delete conversation and all messages (soft delete by default)
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param hardDelete - Whether to permanently delete (default: false)
   */
  async deleteConversation(userId: string, conversationId: string, hardDelete = false): Promise<void> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      if (hardDelete) {
        // Permanently delete conversation and all messages
        await db
          .delete(tenantSchema.conversations)
          .where(eq(tenantSchema.conversations.id, conversationId));
      } else {
        // Soft delete - just mark as archived
        await db
          .update(tenantSchema.conversations)
          .set({
            status: 'archived',
            updated_at: new Date(),
          })
          .where(eq(tenantSchema.conversations.id, conversationId));
      }

      logger.info(`Conversation ${hardDelete ? 'permanently deleted' : 'archived'}: ${conversationId} for user ${userId}`);
    } catch (error) {
      logger.error('Failed to delete conversation:', error);
      throw error;
    }
  }

  /**
   * Delete a specific message (soft delete)
   * @param userId - User ID
   * @param messageId - Message ID
   * @param hardDelete - Whether to permanently delete
   */
  async deleteMessage(userId: string, messageId: string, hardDelete = false): Promise<void> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      if (hardDelete) {
        await db
          .delete(tenantSchema.messages)
          .where(eq(tenantSchema.messages.id, messageId));
      } else {
        await db
          .update(tenantSchema.messages)
          .set({
            deleted_at: new Date(),
            updated_at: new Date(),
          })
          .where(eq(tenantSchema.messages.id, messageId));
      }

      logger.info(`Message ${hardDelete ? 'permanently deleted' : 'soft deleted'}: ${messageId} for user ${userId}`);
    } catch (error) {
      logger.error('Failed to delete message:', error);
      throw error;
    }
  }

  /**
   * Search conversations and messages using advanced full-text search
   * @param userId - User ID
   * @param query - Search query
   * @param filters - Optional filters
   */
  async searchConversations(userId: string, query: string, filters?: {
    project_id?: string;
    importance_level?: number;
    date_from?: string;
    date_to?: string;
    limit?: number;
  }): Promise<{
    conversations: Array<Conversation & { relevance_score: number; matched_content?: string; match_type: string }>;
    total: number;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Use the advanced search function from the database
      const searchResults = await db.execute(sql`
        SELECT * FROM search_conversations_advanced(
          ${query},
          ${filters?.project_id || null},
          ${filters?.importance_level || null},
          ${filters?.date_from ? new Date(filters.date_from) : null},
          ${filters?.date_to ? new Date(filters.date_to) : null},
          ${filters?.limit || 20}
        )
      `);

      // Get total count for pagination
      const [totalResult] = await db
        .select({ count: sql`count(*)` })
        .from(tenantSchema.conversations)
        .where(
          sql`to_tsvector('english', ${tenantSchema.conversations.title} || ' ' || COALESCE(${tenantSchema.conversations.description}, '') || ' ' || COALESCE(${tenantSchema.conversations.summary}, '')) @@ plainto_tsquery('english', ${query})`
        );

      return {
        conversations: searchResults.rows as any,
        total: Number(totalResult.count)
      };
    } catch (error) {
      logger.error('Failed to search conversations:', error);
      throw error;
    }
  }

  /**
   * Get conversation analytics with detailed metrics
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param dateRange - Date range for analytics (default: last 30 days)
   */
  async getConversationAnalytics(userId: string, conversationId: string, dateRange = 30): Promise<{
    message_count_by_day: Array<{ date: string; count: number }>;
    tokens_by_day: Array<{ date: string; tokens: number }>;
    average_response_time: number;
    most_active_hours: Array<{ hour: number; count: number }>;
    sentiment_trend: Array<{ date: string; sentiment: string }>;
    topic_evolution: Array<{ date: string; topics: string[] }>;
    user_engagement: {
      total_sessions: number;
      avg_session_length: number;
      messages_per_session: number;
    };
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Messages by day
      const messagesByDay = await db
        .select({
          date: sql<string>`date(${tenantSchema.messages.created_at})`,
          count: sql<number>`count(*)`,
        })
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            sql`${tenantSchema.messages.created_at} >= current_date - interval '${dateRange} days'`,
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(sql`date(${tenantSchema.messages.created_at})`)
        .orderBy(sql`date(${tenantSchema.messages.created_at})`);

      // Tokens by day
      const tokensByDay = await db
        .select({
          date: sql<string>`date(${tenantSchema.messages.created_at})`,
          tokens: sql<number>`sum(${tenantSchema.messages.tokens_used})`,
        })
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            sql`${tenantSchema.messages.created_at} >= current_date - interval '${dateRange} days'`,
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(sql`date(${tenantSchema.messages.created_at})`)
        .orderBy(sql`date(${tenantSchema.messages.created_at})`);

      // Average response time
      const [avgResponseTime] = await db
        .select({
          avg_time: sql<number>`avg(${tenantSchema.messages.processing_time_ms})`,
        })
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            eq(tenantSchema.messages.role, 'assistant'),
            isNull(tenantSchema.messages.deleted_at)
          )
        );

      // Most active hours
      const activeHours = await db
        .select({
          hour: sql<number>`extract(hour from ${tenantSchema.messages.created_at})`,
          count: sql<number>`count(*)`,
        })
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            isNull(tenantSchema.messages.deleted_at)
          )
        )
        .groupBy(sql`extract(hour from ${tenantSchema.messages.created_at})`)
        .orderBy(sql`count(*) DESC`);

      // Get analytics data from conversation_analytics table
      const analyticsData = await db
        .select()
        .from(tenantSchema.conversationAnalytics)
        .where(
          and(
            eq(tenantSchema.conversationAnalytics.conversation_id, conversationId),
            sql`${tenantSchema.conversationAnalytics.date} >= current_date - interval '${dateRange} days'`
          )
        )
        .orderBy(tenantSchema.conversationAnalytics.date);

      // Calculate user engagement metrics
      const [engagementMetrics] = await db
        .select({
          total_messages: sql<number>`count(*)`,
          unique_days: sql<number>`count(distinct date(${tenantSchema.messages.created_at}))`,
          first_message: sql<string>`min(${tenantSchema.messages.created_at})`,
          last_message: sql<string>`max(${tenantSchema.messages.created_at})`,
        })
        .from(tenantSchema.messages)
        .where(
          and(
            eq(tenantSchema.messages.conversation_id, conversationId),
            eq(tenantSchema.messages.role, 'user'),
            isNull(tenantSchema.messages.deleted_at)
          )
        );

      // Calculate session metrics (sessions are periods of activity with gaps > 1 hour)
      const sessionData = await db.execute(sql`
        WITH message_gaps AS (
          SELECT 
            created_at,
            LAG(created_at) OVER (ORDER BY created_at) as prev_created_at,
            EXTRACT(EPOCH FROM (created_at - LAG(created_at) OVER (ORDER BY created_at)))/3600 as gap_hours
          FROM ${tenantSchema.messages}
          WHERE conversation_id = ${conversationId} 
            AND role = 'user' 
            AND deleted_at IS NULL
        ),
        sessions AS (
          SELECT 
            created_at,
            SUM(CASE WHEN gap_hours > 1 OR gap_hours IS NULL THEN 1 ELSE 0 END) 
              OVER (ORDER BY created_at) as session_id
          FROM message_gaps
        )
        SELECT 
          COUNT(DISTINCT session_id) as total_sessions,
          AVG(session_length) as avg_session_length,
          AVG(messages_per_session) as avg_messages_per_session
        FROM (
          SELECT 
            session_id,
            COUNT(*) as messages_per_session,
            EXTRACT(EPOCH FROM (MAX(created_at) - MIN(created_at)))/60 as session_length
          FROM sessions
          GROUP BY session_id
        ) session_stats
      `);

      const sessionMetrics = sessionData.rows[0] || {
        total_sessions: 0,
        avg_session_length: 0,
        avg_messages_per_session: 0
      };

      return {
        message_count_by_day: messagesByDay.map(row => ({
          date: row.date,
          count: Number(row.count)
        })),
        tokens_by_day: tokensByDay.map(row => ({
          date: row.date,
          tokens: Number(row.tokens) || 0
        })),
        average_response_time: Number(avgResponseTime?.avg_time) || 0,
        most_active_hours: activeHours.map(row => ({
          hour: Number(row.hour),
          count: Number(row.count)
        })),
        sentiment_trend: analyticsData.map(row => ({
          date: row.date.toISOString().split('T')[0],
          sentiment: row.sentiment_score || 'neutral'
        })),
        topic_evolution: analyticsData.map(row => ({
          date: row.date.toISOString().split('T')[0],
          topics: Array.isArray(row.topics_discussed) ? row.topics_discussed : []
        })),
        user_engagement: {
          total_sessions: Number(sessionMetrics.total_sessions) || 0,
          avg_session_length: Number(sessionMetrics.avg_session_length) || 0,
          messages_per_session: Number(sessionMetrics.avg_messages_per_session) || 0,
        }
      };
    } catch (error) {
      logger.error('Failed to get conversation analytics:', error);
      throw error;
    }
  }
/**
   * Export conversation data in various formats
   * @param userId - User ID
   * @param conversationId - Conversation ID
   * @param format - Export format
   */
  async exportConversation(userId: string, conversationId: string, format: 'json' | 'markdown' | 'txt' = 'json'): Promise<{
    filename: string;
    content: string;
    mimeType: string;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Get conversation with all messages
      const { conversation, messages } = await this.getConversationById(userId, conversationId, true, 10000);
      
      if (!conversation) {
        throw new Error('Conversation not found');
      }

      const timestamp = new Date().toISOString().split('T')[0];
      const safeTitle = conversation.title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);

      switch (format) {
        case 'json':
          return {
            filename: `conversation_${safeTitle}_${timestamp}.json`,
            content: JSON.stringify({
              conversation,
              messages: messages || [],
              exported_at: new Date().toISOString(),
              total_messages: messages?.length || 0
            }, null, 2),
            mimeType: 'application/json'
          };

        case 'markdown':
          const markdownContent = this.generateMarkdownExport(conversation, messages || []);
          return {
            filename: `conversation_${safeTitle}_${timestamp}.md`,
            content: markdownContent,
            mimeType: 'text/markdown'
          };

        case 'txt':
          const txtContent = this.generateTextExport(conversation, messages || []);
          return {
            filename: `conversation_${safeTitle}_${timestamp}.txt`,
            content: txtContent,
            mimeType: 'text/plain'
          };

        default:
          throw new Error(`Unsupported export format: ${format}`);
      }
    } catch (error) {
      logger.error('Failed to export conversation:', error);
      throw error;
    }
  }

  /**
   * Generate markdown export content
   * @param conversation - Conversation data
   * @param messages - Messages array
   */
  private generateMarkdownExport(conversation: Conversation, messages: Message[]): string {
    const lines = [
      `# ${conversation.title}`,
      '',
      `**Description:** ${conversation.description || 'No description'}`,
      `**Created:** ${conversation.created_at}`,
      `**Last Updated:** ${conversation.updated_at}`,
      `**Importance Level:** ${conversation.importance_level}/10`,
      `**Total Messages:** ${messages.length}`,
      '',
      '---',
      ''
    ];

    for (const message of messages) {
      const role = message.role === 'user' ? '👤 **User**' : '🤖 **Assistant**';
      const timestamp = new Date(message.created_at).toLocaleString();
      
      lines.push(`## ${role} - ${timestamp}`);
      lines.push('');
      lines.push(message.content);
      lines.push('');
      
      if (message.tokens_used) {
        lines.push(`*Tokens used: ${message.tokens_used}*`);
        lines.push('');
      }
      
      lines.push('---');
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Generate plain text export content
   * @param conversation - Conversation data
   * @param messages - Messages array
   */
  private generateTextExport(conversation: Conversation, messages: Message[]): string {
    const lines = [
      `CONVERSATION: ${conversation.title}`,
      `DESCRIPTION: ${conversation.description || 'No description'}`,
      `CREATED: ${conversation.created_at}`,
      `LAST UPDATED: ${conversation.updated_at}`,
      `IMPORTANCE LEVEL: ${conversation.importance_level}/10`,
      `TOTAL MESSAGES: ${messages.length}`,
      '',
      '=' .repeat(80),
      ''
    ];

    for (const message of messages) {
      const role = message.role.toUpperCase();
      const timestamp = new Date(message.created_at).toLocaleString();
      
      lines.push(`[${timestamp}] ${role}:`);
      lines.push(message.content);
      lines.push('');
      lines.push('-'.repeat(40));
      lines.push('');
    }

    return lines.join('\n');
  }
}

export const conversationService = new ConversationService();