import { config } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * Enhanced Claude Service
 * Integrates with n8n workflow to communicate with Claude API
 * Handles message routing, response processing, and error handling
 */
class ClaudeService {
  private requestQueue: Map<string, Promise<any>> = new Map();
  private rateLimitTracker: Map<string, { count: number; resetTime: number }> = new Map();

  /**
   * Send message to Claude via n8n workflow with enhanced error handling and rate limiting
   * @param request - Message request data
   */
  async sendMessage(request: {
    user_id: string;
    conversation_id: string;
    user_message: string;
    importance_level: number;
    conversation_context?: {
      title: string;
      summary?: string | null;
      recent_messages: Array<{
        role: string;
        content: string;
        created_at: string | Date;
      }>;
    };
  }): Promise<{
    response: string;
    tokens_used?: number;
    model_used?: string;
    processing_time_ms?: number;
    metadata?: Record<string, any>;
  }> {
    const requestKey = `${request.user_id}:${request.conversation_id}`;
    
    try {
      // Check rate limiting
      await this.checkRateLimit(request.user_id);

      // Prevent duplicate requests
      if (this.requestQueue.has(requestKey)) {
        logger.debug(`Request already in progress for ${requestKey}, waiting...`);
        return await this.requestQueue.get(requestKey)!;
      }

      // Create and queue the request
      const requestPromise = this.executeClaudeRequest(request);
      this.requestQueue.set(requestKey, requestPromise);

      try {
        const result = await requestPromise;
        return result;
      } finally {
        this.requestQueue.delete(requestKey);
      }
    } catch (error) {
      this.requestQueue.delete(requestKey);
      throw error;
    }
  }

  /**
   * Execute the actual Claude request
   * @param request - Request data
   */
  private async executeClaudeRequest(request: any): Promise<any> {
    const startTime = Date.now();

    try {
      // Prepare the enhanced request payload
      const payload = {
        ...request,
        timestamp: new Date().toISOString(),
        client_info: {
          version: '1.0.0',
          platform: 'claude-memory-backend'
        }
      };

      // Call n8n webhook
      const response = await fetch(config.n8n.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Claude-Memory-Backend/1.0.0',
          ...(config.n8n.apiKey && { 'Authorization': `Bearer ${config.n8n.apiKey}` })
        },
        body: JSON.stringify(payload),
        timeout: 30000, // 30 second timeout
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`n8n webhook failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const data = await response.json();
      const processingTime = Date.now() - startTime;

      // Validate response structure
      if (!data.claude_response && !data.response) {
        throw new Error('Invalid response format: missing claude_response or response field');
      }

      // Update rate limit tracking
      this.updateRateLimit(request.user_id);

      logger.debug(`Claude response received in ${processingTime}ms for user ${request.user_id}`);

      return {
        response: data.claude_response || data.response || 'No response received',
        tokens_used: data.tokens_used || data.token_count,
        model_used: data.model_used || data.model || 'claude-sonnet-4',
        processing_time_ms: processingTime,
        metadata: {
          n8n_response_time: processingTime,
          workflow_data: data,
          request_timestamp: payload.timestamp,
        },
      };
    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      logger.error('Failed to send message to Claude:', {
        error: error.message,
        user_id: request.user_id,
        conversation_id: request.conversation_id,
        processing_time: processingTime
      });

      // Determine if this is a retryable error
      if (this.isRetryableError(error)) {
        logger.info(`Retryable error detected, will retry for user ${request.user_id}`);
        throw new Error(`Claude service temporarily unavailable: ${error.message}`);
      } else {
        throw new Error(`Claude service error: ${error.message}`);
      }
    }
  }

  /**
   * Check rate limiting for user
   * @param userId - User ID
   */
  private async checkRateLimit(userId: string): Promise<void> {
    const now = Date.now();
    const userLimit = this.rateLimitTracker.get(userId);

    if (userLimit) {
      if (now < userLimit.resetTime) {
        if (userLimit.count >= 60) { // 60 requests per minute max
          throw new Error('Rate limit exceeded. Please wait before sending another message.');
        }
      } else {
        // Reset counter after time window
        this.rateLimitTracker.set(userId, { count: 0, resetTime: now + 60000 });
      }
    } else {
      // First request for this user
      this.rateLimitTracker.set(userId, { count: 0, resetTime: now + 60000 });
    }
  }

  /**
   * Update rate limit tracking after successful request
   * @param userId - User ID
   */
  private updateRateLimit(userId: string): void {
    const userLimit = this.rateLimitTracker.get(userId);
    if (userLimit) {
      userLimit.count += 1;
    }
  }

  /**
   * Determine if an error is retryable
   * @param error - Error object
   */
  private isRetryableError(error: any): boolean {
    // Network errors, timeouts, and 5xx HTTP errors are typically retryable
    return (
      error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT' ||
      error.code === 'ENOTFOUND' ||
      error.message.includes('timeout') ||
      error.message.includes('5') // 5xx HTTP errors
    );
  }

  /**
   * Test Claude service connectivity with detailed diagnostics
   */
  async testConnection(): Promise<{
    success: boolean;
    response_time: number;
    error?: string;
    details: {
      webhook_url: string;
      has_api_key: boolean;
      test_timestamp: string;
    };
  }> {
    const startTime = Date.now();
    const testTimestamp = new Date().toISOString();

    try {
      const testResponse = await this.sendMessage({
        user_id: 'health_check',
        conversation_id: 'connectivity_test',
        user_message: 'Hello, this is a connectivity test. Please respond with a simple acknowledgment.',
        importance_level: 1,
        conversation_context: {
          title: 'Health Check',
          recent_messages: []
        }
      });

      const responseTime = Date.now() - startTime;

      return {
        success: true,
        response_time: responseTime,
        details: {
          webhook_url: config.n8n.webhookUrl,
          has_api_key: !!config.n8n.apiKey,
          test_timestamp: testTimestamp,
        },
      };
    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      
      return {
        success: false,
        response_time: responseTime,
        error: error.message,
        details: {
          webhook_url: config.n8n.webhookUrl,
          has_api_key: !!config.n8n.apiKey,
          test_timestamp: testTimestamp,
        },
      };
    }
  }

  /**
   * Get service health metrics
   */
  getServiceMetrics(): {
    active_requests: number;
    rate_limited_users: number;
    total_tracked_users: number;
  } {
    const now = Date.now();
    let rateLimitedUsers = 0;

    for (const [userId, limit] of this.rateLimitTracker.entries()) {
      if (now < limit.resetTime && limit.count >= 60) {
        rateLimitedUsers++;
      }
    }

    return {
      active_requests: this.requestQueue.size,
      rate_limited_users: rateLimitedUsers,
      total_tracked_users: this.rateLimitTracker.size,
    };
  }

  /**
   * Clear rate limit for a specific user (admin function)
   * @param userId - User ID
   */
  clearRateLimit(userId: string): void {
    this.rateLimitTracker.delete(userId);
    logger.info(`Rate limit cleared for user ${userId}`);
  }

  /**
   * Clean up expired rate limit entries (call periodically)
   */
  cleanupRateLimits(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [userId, limit] of this.rateLimitTracker.entries()) {
      if (now > limit.resetTime + 300000) { // 5 minutes after reset time
        this.rateLimitTracker.delete(userId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug(`Cleaned up ${cleaned} expired rate limit entries`);
    }
  }

  /**
   * Send a batch of messages (for import/migration scenarios)
   * @param requests - Array of message requests
   * @param options - Batch processing options
   */
  async sendMessageBatch(
    requests: Array<{
      user_id: string;
      conversation_id: string;
      user_message: string;
      importance_level: number;
      conversation_context?: any;
    }>,
    options: {
      max_concurrent: number;
      delay_between_batches: number;
    } = { max_concurrent: 5, delay_between_batches: 1000 }
  ): Promise<Array<{
    success: boolean;
    request_index: number;
    response?: any;
    error?: string;
  }>> {
    const results: Array<{
      success: boolean;
      request_index: number;
      response?: any;
      error?: string;
    }> = [];

    // Process requests in batches
    for (let i = 0; i < requests.length; i += options.max_concurrent) {
      const batch = requests.slice(i, i + options.max_concurrent);
      
      const batchPromises = batch.map(async (request, batchIndex) => {
        const requestIndex = i + batchIndex;
        try {
          const response = await this.sendMessage(request);
          return {
            success: true,
            request_index: requestIndex,
            response,
          };
        } catch (error: any) {
          return {
            success: false,
            request_index: requestIndex,
            error: error.message,
          };
        }
      });

      const batchResults = await Promise.allSettled(batchPromises);
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          results.push({
            success: false,
            request_index: i + results.length,
            error: result.reason?.message || 'Unknown error',
          });
        }
      }

      // Delay between batches to avoid overwhelming the service
      if (i + options.max_concurrent < requests.length) {
        await new Promise(resolve => setTimeout(resolve, options.delay_between_batches));
      }

      logger.info(`Processed batch ${Math.floor(i / options.max_concurrent) + 1}/${Math.ceil(requests.length / options.max_concurrent)}`);
    }

    return results;
  }
}

export const claudeService = new ClaudeService();