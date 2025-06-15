import axios, { AxiosInstance } from 'axios';
import { Config, claudeConfig } from '@/config/environment';
import { logger } from '@/utils/logger';
import { createError } from '@/middleware/errorHandler';

/**
 * Claude AI Service
 * Handles integration with Anthropic's Claude API
 */

var config: Config = claudeConfig;

interface ClaudeMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

interface ClaudeResponse {
  id: string;
  type: 'message';
  role: 'assistant';
  content: Array<{
    type: 'text';
    text: string;
  }>;
  model: string;
  stop_reason: string;
  stop_sequence: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

interface ClaudeRequestOptions {
  model?: string;
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  system?: string;
  stream?: boolean;
}

interface RateLimitInfo {
  requestsPerMinute: number;
  tokensPerMinute: number;
  currentRequests: number;
  currentTokens: number;
  resetTime: number;
}

interface ConversationContext {
  messages: ClaudeMessage[];
  systemPrompt?: string;
  userId: string;
  conversationId: string;
}

class ClaudeService {
  private client: AxiosInstance;
  private rateLimits: Map<string, RateLimitInfo> = new Map();
  private readonly DEFAULT_MODEL = claudeConfig.model;
  private readonly DEFAULT_MAX_TOKENS = claudeConfig.maxTokens;
  private readonly DEFAULT_TEMPERATURE = claudeConfig.temperature;

  constructor() {
    if (!claudeConfig.apiKey) {
      logger.warn('Claude API key not configured - Claude integration disabled');
      throw new Error('Claude API key not configured');
    }

    this.client = axios.create({
      baseURL: claudeConfig.apiUrl,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': claudeConfig.apiKey,
        'anthropic-version': '2023-06-01',
      },
      timeout: 60000, // 60 seconds
    });

    // Request interceptor for logging
    this.client.interceptors.request.use(
      (config) => {
        logger.debug('Claude API request:', {
          url: config.url,
          method: config.method,
          model: config.data?.model,
          maxTokens: config.data?.max_tokens,
        });
        return config;
      },
      (error) => {
        logger.error('Claude API request error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for logging and error handling
    this.client.interceptors.response.use(
      (response) => {
        logger.debug('Claude API response:', {
          status: response.status,
          model: response.data?.model,
          usage: response.data?.usage,
        });
        return response;
      },
      (error) => {
        logger.error('Claude API error:', {
          status: error.response?.status,
          data: error.response?.data,
          message: error.message,
        });
        return Promise.reject(this.handleApiError(error));
      }
    );

    logger.info('Claude service initialized');
  }

  /**
   * Send a message to Claude and get response
   */
  async sendMessage(
    context: ConversationContext,
    newMessage: string,
    options: ClaudeRequestOptions = {}
  ): Promise<{
    response: string;
    usage: {
      inputTokens: number;
      outputTokens: number;
      totalTokens: number;
    };
    model: string;
    processingTime: number;
  }> {
    const startTime = Date.now();

    try {
      // Check rate limits
      await this.checkRateLimit(context.userId);

      // Prepare messages
      const messages = [
        ...context.messages,
        { role: 'user' as const, content: newMessage },
      ];

      // Build request payload
      const payload = {
        model: options.model || this.DEFAULT_MODEL,
        max_tokens: options.max_tokens || this.DEFAULT_MAX_TOKENS,
        temperature: options.temperature || this.DEFAULT_TEMPERATURE,
        top_p: options.top_p || claudeConfig.topP,
        messages,
        system: options.system || context.systemPrompt,
      };

      // Make API call
      const response = await this.client.post<ClaudeResponse>('/messages', payload);
      const processingTime = Date.now() - startTime;

      // Extract response text
      const responseText = response.data.content
        .filter(item => item.type === 'text')
        .map(item => item.text)
        .join('');

      // Update rate limits
      this.updateRateLimit(context.userId, response.data.usage);

      // Log successful completion
      logger.info('Claude message processed', {
        userId: context.userId,
        conversationId: context.conversationId,
        model: response.data.model,
        inputTokens: response.data.usage.input_tokens,
        outputTokens: response.data.usage.output_tokens,
        processingTime,
      });

      return {
        response: responseText,
        usage: {
          inputTokens: response.data.usage.input_tokens,
          outputTokens: response.data.usage.output_tokens,
          totalTokens: response.data.usage.input_tokens + response.data.usage.output_tokens,
        },
        model: response.data.model,
        processingTime,
      };
    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      logger.error('Claude message failed:', {
        userId: context.userId,
        conversationId: context.conversationId,
        error: error.message,
        processingTime,
      });

      throw error;
    }
  }

  /**
   * Generate a conversation summary
   */
  async generateSummary(
    messages: ClaudeMessage[],
    userId: string,
    options: { maxLength?: number } = {}
  ): Promise<string> {
    try {
      const { maxLength = 200 } = options;

      // Create summary prompt
      const summaryPrompt = `Please provide a concise summary of this conversation in ${maxLength} characters or less. Focus on the main topics discussed and key outcomes.`;

      const context: ConversationContext = {
        messages,
        systemPrompt: summaryPrompt,
        userId,
        conversationId: 'summary-generation',
      };

      const result = await this.sendMessage(context, 'Generate summary', {
        max_tokens: Math.min(500, maxLength * 2), // Estimate tokens needed
        temperature: 0.3, // Lower temperature for more consistent summaries
      });

      return result.response.trim();
    } catch (error) {
      logger.error('Summary generation failed:', error);
      throw createError.externalService('Claude', 'Failed to generate summary');
    }
  }

  /**
   * Analyze conversation sentiment
   */
  async analyzeSentiment(
    messages: ClaudeMessage[],
    userId: string
  ): Promise<{
    sentiment: 'positive' | 'negative' | 'neutral';
    confidence: number;
    reasoning: string;
  }> {
    try {
      const sentimentPrompt = `Analyze the sentiment of this conversation and respond with a JSON object containing:
      - sentiment: "positive", "negative", or "neutral"
      - confidence: a number between 0 and 1
      - reasoning: a brief explanation of your assessment`;

      const context: ConversationContext = {
        messages,
        systemPrompt: sentimentPrompt,
        userId,
        conversationId: 'sentiment-analysis',
      };

      const result = await this.sendMessage(context, 'Analyze sentiment', {
        max_tokens: 300,
        temperature: 0.1,
      });

      try {
        const analysis = JSON.parse(result.response);
        return {
          sentiment: analysis.sentiment,
          confidence: Math.max(0, Math.min(1, analysis.confidence)),
          reasoning: analysis.reasoning || 'No reasoning provided',
        };
      } catch (parseError) {
        logger.warn('Failed to parse sentiment analysis JSON:', parseError);
        return {
          sentiment: 'neutral',
          confidence: 0.5,
          reasoning: 'Unable to parse sentiment analysis',
        };
      }
    } catch (error) {
      logger.error('Sentiment analysis failed:', error);
      throw createError.externalService('Claude', 'Failed to analyze sentiment');
    }
  }

  /**
   * Extract topics from conversation
   */
  async extractTopics(
    messages: ClaudeMessage[],
    userId: string,
    maxTopics: number = 5
  ): Promise<string[]> {
    try {
      const topicsPrompt = `Extract the main topics discussed in this conversation. Return a JSON array of topic strings (max ${maxTopics} topics).`;

      const context: ConversationContext = {
        messages,
        systemPrompt: topicsPrompt,
        userId,
        conversationId: 'topic-extraction',
      };

      const result = await this.sendMessage(context, 'Extract topics', {
        max_tokens: 200,
        temperature: 0.2,
      });

      try {
        const topics = JSON.parse(result.response);
        return Array.isArray(topics) ? topics.slice(0, maxTopics) : [];
      } catch (parseError) {
        logger.warn('Failed to parse topics JSON:', parseError);
        return [];
      }
    } catch (error) {
      logger.error('Topic extraction failed:', error);
      return [];
    }
  }

  /**
   * Check if a message is appropriate
   */
  async moderateContent(content: string, userId: string): Promise<{
    approved: boolean;
    reason?: string;
    confidence: number;
  }> {
    try {
      const moderationPrompt = `Review this message for inappropriate content including hate speech, violence, illegal activities, or harassment. Respond with JSON:
      - approved: true/false
      - reason: explanation if not approved
      - confidence: number between 0 and 1`;

      const context: ConversationContext = {
        messages: [],
        systemPrompt: moderationPrompt,
        userId,
        conversationId: 'content-moderation',
      };

      const result = await this.sendMessage(context, content, {
        max_tokens: 200,
        temperature: 0.1,
      });

      try {
        const moderation = JSON.parse(result.response);
        return {
          approved: Boolean(moderation.approved),
          reason: moderation.reason,
          confidence: Math.max(0, Math.min(1, moderation.confidence || 0.5)),
        };
      } catch (parseError) {
        logger.warn('Failed to parse moderation JSON:', parseError);
        // Default to approved if we can't parse the response
        return { approved: true, confidence: 0.5 };
      }
    } catch (error) {
      logger.error('Content moderation failed:', error);
      // Default to approved if moderation fails
      return { approved: true, confidence: 0.5 };
    }
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    try {
      // Since Anthropic doesn't have a models endpoint, return known models
      return [
        'claude-3-opus-20240229',
        'claude-3-sonnet-20240229',
        'claude-3-haiku-20240307',
        'claude-2.1',
        'claude-2.0',
        'claude-instant-1.2',
      ];
    } catch (error) {
      logger.error('Failed to get available models:', error);
      return [this.DEFAULT_MODEL];
    }
  }

  /**
   * Check API health
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    latency: number;
    error?: string;
  }> {
    const startTime = Date.now();

    try {
      // Simple health check with minimal token usage
      const response = await this.client.post('/messages', {
        model: 'claude-3-haiku-20240307', // Use fastest model for health check
        max_tokens: 10,
        messages: [{ role: 'user', content: 'ping' }],
      });

      const latency = Date.now() - startTime;

      return {
        healthy: response.status === 200,
        latency,
      };
    } catch (error) {
      const latency = Date.now() - startTime;
      
      return {
        healthy: false,
        latency,
        error: error.message,
      };
    }
  }

  /**
   * Rate limiting management
   */
  private async checkRateLimit(userId: string): Promise<void> {
    const limit = this.getRateLimit(userId);
    const now = Date.now();

    // Reset counters if window has passed
    if (now > limit.resetTime) {
      limit.currentRequests = 0;
      limit.currentTokens = 0;
      limit.resetTime = now + 60000; // Reset every minute
    }

    // Check request limit
    if (limit.currentRequests >= limit.requestsPerMinute) {
      throw createError.rateLimit('Claude API request limit exceeded');
    }

    // Increment request counter
    limit.currentRequests++;
  }

  private updateRateLimit(userId: string, usage: { input_tokens: number; output_tokens: number }): void {
    const limit = this.getRateLimit(userId);
    limit.currentTokens += usage.input_tokens + usage.output_tokens;

    // Check token limit
    if (limit.currentTokens >= limit.tokensPerMinute) {
      logger.warn('Claude API token limit approaching', {
        userId,
        currentTokens: limit.currentTokens,
        tokenLimit: limit.tokensPerMinute,
      });
    }
  }

  private getRateLimit(userId: string): RateLimitInfo {
    if (!this.rateLimits.has(userId)) {
      this.rateLimits.set(userId, {
        requestsPerMinute: 50, // Conservative default
        tokensPerMinute: 40000, // Conservative default
        currentRequests: 0,
        currentTokens: 0,
        resetTime: Date.now() + 60000,
      });
    }

    return this.rateLimits.get(userId)!;
  }

  /**
   * Clean up expired rate limit entries
   */
  public cleanupRateLimits(): void {
    const now = Date.now();
    const expired: string[] = [];

    for (const [userId, limit] of this.rateLimits.entries()) {
      // Remove entries that haven't been used in over an hour
      if (now > limit.resetTime + 3600000) {
        expired.push(userId);
      }
    }

    expired.forEach(userId => this.rateLimits.delete(userId));

    if (expired.length > 0) {
      logger.debug(`Cleaned up ${expired.length} expired rate limit entries`);
    }
  }

  /**
   * Get rate limit status for a user
   */
  public getRateLimitStatus(userId: string): RateLimitInfo {
    return { ...this.getRateLimit(userId) };
  }

  /**
   * Error handling
   */
  private handleApiError(error: any): Error {
    if (!error.response) {
      return createError.externalService('Claude', 'Network error');
    }

    const { status, data } = error.response;

    switch (status) {
      case 400:
        return createError.custom(
          data.error?.message || 'Invalid request to Claude API',
          400,
          'CLAUDE_BAD_REQUEST'
        );
      case 401:
        return createError.custom(
          'Invalid Claude API key',
          401,
          'CLAUDE_UNAUTHORIZED'
        );
      case 403:
        return createError.custom(
          'Claude API access forbidden',
          403,
          'CLAUDE_FORBIDDEN'
        );
      case 429:
        return createError.rateLimit('Claude API rate limit exceeded');
      case 500:
        return createError.externalService('Claude', 'Claude API server error');
      case 529:
        return createError.externalService('Claude', 'Claude API overloaded');
      default:
        return createError.externalService(
          'Claude',
          `Unexpected API error: ${status}`
        );
    }
  }

  /**
   * Token estimation
   */
  public estimateTokens(text: string): number {
    // Rough estimation: ~4 characters per token for English text
    return Math.ceil(text.length / 4);
  }

  /**
   * Calculate cost estimation
   */
  public estimateCost(
    inputTokens: number,
    outputTokens: number,
    model: string = this.DEFAULT_MODEL
  ): number {
    // Pricing as of 2024 (in USD per 1M tokens)
    const pricing: { [key: string]: { input: number; output: number } } = {
      'claude-3-opus-20240229': { input: 15, output: 75 },
      'claude-3-sonnet-20240229': { input: 3, output: 15 },
      'claude-3-haiku-20240307': { input: 0.25, output: 1.25 },
      'claude-2.1': { input: 8, output: 24 },
      'claude-2.0': { input: 8, output: 24 },
      'claude-instant-1.2': { input: 0.8, output: 2.4 },
    };

    const modelPricing = pricing[model] || pricing[this.DEFAULT_MODEL];
    
    const inputCost = (inputTokens / 1000000) * modelPricing.input;
    const outputCost = (outputTokens / 1000000) * modelPricing.output;

    return inputCost + outputCost;
  }

  /**
   * Stream support for real-time responses
   */
  async sendMessageStream(
    context: ConversationContext,
    newMessage: string,
    onChunk: (chunk: string) => void,
    options: ClaudeRequestOptions = {}
  ): Promise<{
    fullResponse: string;
    usage: {
      inputTokens: number;
      outputTokens: number;
      totalTokens: number;
    };
    model: string;
    processingTime: number;
  }> {
    const startTime = Date.now();

    try {
      // Check rate limits
      await this.checkRateLimit(context.userId);

      // Prepare messages
      const messages = [
        ...context.messages,
        { role: 'user' as const, content: newMessage },
      ];

      // Build request payload
      const payload = {
        model: options.model || this.DEFAULT_MODEL,
        max_tokens: options.max_tokens || this.DEFAULT_MAX_TOKENS,
        temperature: options.temperature || this.DEFAULT_TEMPERATURE,
        top_p: options.top_p || claudeConfig.topP,
        messages,
        system: options.system || context.systemPrompt,
        stream: true,
      };

      let fullResponse = '';
      let usage = { input_tokens: 0, output_tokens: 0 };
      let model = payload.model;

      const response = await this.client.post('/messages', payload, {
        responseType: 'stream',
      });

      return new Promise((resolve, reject) => {
        response.data.on('data', (chunk: Buffer) => {
          const lines = chunk.toString().split('\n');
          
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                
                if (data.type === 'content_block_delta') {
                  const text = data.delta?.text || '';
                  fullResponse += text;
                  onChunk(text);
                } else if (data.type === 'message_stop') {
                  usage = data.usage || usage;
                  model = data.model || model;
                }
              } catch (parseError) {
                // Ignore parsing errors for non-JSON lines
              }
            }
          }
        });

        response.data.on('end', () => {
          const processingTime = Date.now() - startTime;
          
          // Update rate limits
          this.updateRateLimit(context.userId, usage);

          resolve({
            fullResponse,
            usage: {
              inputTokens: usage.input_tokens,
              outputTokens: usage.output_tokens,
              totalTokens: usage.input_tokens + usage.output_tokens,
            },
            model,
            processingTime,
          });
        });

        response.data.on('error', (error: Error) => {
          reject(this.handleApiError(error));
        });
      });
    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      logger.error('Claude streaming failed:', {
        userId: context.userId,
        conversationId: context.conversationId,
        error: error.message,
        processingTime,
      });

      throw error;
    }
  }

  /**
   * Batch processing for multiple messages
   */
  async sendBatchMessages(
    contexts: ConversationContext[],
    messages: string[],
    options: ClaudeRequestOptions = {}
  ): Promise<Array<{
    success: boolean;
    response?: string;
    usage?: {
      inputTokens: number;
      outputTokens: number;
      totalTokens: number;
    };
    error?: string;
  }>> {
    if (contexts.length !== messages.length) {
      throw createError.custom(
        'Contexts and messages arrays must have the same length',
        400,
        'BATCH_LENGTH_MISMATCH'
      );
    }

    const results = await Promise.allSettled(
      contexts.map((context, index) =>
        this.sendMessage(context, messages[index], options)
      )
    );

    return results.map(result => {
      if (result.status === 'fulfilled') {
        return {
          success: true,
          response: result.value.response,
          usage: result.value.usage,
        };
      } else {
        return {
          success: false,
          error: result.reason.message,
        };
      }
    });
  }

  /**
   * Get service statistics
   */
  public getStatistics(): {
    totalUsers: number;
    totalRequests: number;
    totalTokens: number;
    averageLatency: number;
  } {
    let totalRequests = 0;
    let totalTokens = 0;

    for (const limit of this.rateLimits.values()) {
      totalRequests += limit.currentRequests;
      totalTokens += limit.currentTokens;
    }

    return {
      totalUsers: this.rateLimits.size,
      totalRequests,
      totalTokens,
      averageLatency: 0, // Would need to track this separately
    };
  }

  /**
   * Validate model availability
   */
  public isModelAvailable(model: string): boolean {
    const availableModels = [
      'claude-3-opus-20240229',
      'claude-3-sonnet-20240229',
      'claude-3-haiku-20240307',
      'claude-2.1',
      'claude-2.0',
      'claude-instant-1.2',
    ];

    return availableModels.includes(model);
  }

  /**
   * Get optimal model recommendation
   */
  public recommendModel(
    requirements: {
      speed?: 'fast' | 'balanced' | 'thorough';
      complexity?: 'simple' | 'moderate' | 'complex';
      budget?: 'low' | 'medium' | 'high';
    }
  ): string {
    const { speed = 'balanced', complexity = 'moderate', budget = 'medium' } = requirements;

    if (speed === 'fast' || budget === 'low') {
      return 'claude-3-haiku-20240307';
    }

    if (complexity === 'complex' && budget === 'high') {
      return 'claude-3-opus-20240229';
    }

    return 'claude-3-sonnet-20240229'; // Default balanced option
  }
}

// Export singleton instance
export const claudeService = new ClaudeService();

export default claudeService;