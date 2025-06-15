import crypto from 'crypto';
import { databaseService } from '@/services/databaseService';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import * as tenantSchema from '@/database/schemas/tenant.schema';
import type { WebhookEvent, WebhookDelivery } from '@/types/database.types';

/**
 * Webhook Service
 * Handles webhook management, delivery, and retries
 * Supports secure webhook delivery with signature verification
 */
class WebhookService {
  private deliveryQueue: Map<string, WebhookDelivery[]> = new Map();
  private retryTimers: Map<string, NodeJS.Timeout> = new Map();
  private maxRetries = 3;
  private retryDelays = [1000, 5000, 15000]; // 1s, 5s, 15s
  private deliveryTimeout = 30000; // 30 seconds
  private isProcessing = false;

  constructor() {
    this.startDeliveryProcessor();
  }

  /**
   * Trigger webhooks for a specific event
   * @param userId - User ID
   * @param eventType - Event type
   * @param eventData - Event data
   */
  async trigger(userId: string, eventType: string, eventData: any): Promise<void> {
    try {
      // Get active webhooks for this user
      const webhooks = await this.getActiveWebhooks(userId, eventType);
      
      if (webhooks.length === 0) {
        logger.debug(`No active webhooks found for event: ${eventType}`);
        return;
      }

      // Create webhook event
      const event: WebhookEvent = {
        event_type: eventType,
        event_id: this.generateEventId(),
        timestamp: new Date().toISOString(),
        user_id: userId,
        data: eventData,
        metadata: {
          source: 'claude-memory-backend',
          version: '1.0.0',
        },
      };

      // Queue deliveries for all matching webhooks
      for (const webhook of webhooks) {
        await this.queueDelivery(webhook, event);
      }

      logger.info(`Triggered ${webhooks.length} webhooks for event: ${eventType}`);
    } catch (error) {
      logger.error('Failed to trigger webhooks:', error);
    }
  }

  /**
   * Get active webhooks for user and event type
   * @param userId - User ID
   * @param eventType - Event type
   */
  private async getActiveWebhooks(userId: string, eventType: string): Promise<any[]> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      const webhooks = await db
        .select()
        .from(tenantSchema.webhooks)
        .where(
          `is_active = true AND (events @> $1 OR events @> $2)`,
          [JSON.stringify([eventType]), JSON.stringify(['*'])]
        );

      return webhooks;
    } catch (error) {
      logger.error('Failed to get webhooks:', error);
      return [];
    }
  }

  /**
   * Queue webhook delivery
   * @param webhook - Webhook configuration
   * @param event - Webhook event
   */
  private async queueDelivery(webhook: any, event: WebhookEvent): Promise<void> {
    const delivery: WebhookDelivery = {
      webhook_id: webhook.id,
      event,
      attempt: 0,
      status: 'pending',
      created_at: new Date(),
    };

    // Add to delivery queue
    if (!this.deliveryQueue.has(webhook.id)) {
      this.deliveryQueue.set(webhook.id, []);
    }
    
    this.deliveryQueue.get(webhook.id)!.push(delivery);
    
    // Start processing if not already running
    if (!this.isProcessing) {
      this.processDeliveryQueue();
    }
  }

  /**
   * Process webhook delivery queue
   */
  private async processDeliveryQueue(): Promise<void> {
    if (this.isProcessing) {
      return;
    }

    this.isProcessing = true;

    try {
      for (const [webhookId, deliveries] of this.deliveryQueue.entries()) {
        while (deliveries.length > 0) {
          const delivery = deliveries.shift()!;
          await this.deliverWebhook(delivery);
        }
      }
    } catch (error) {
      logger.error('Error processing webhook delivery queue:', error);
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Deliver webhook to endpoint
   * @param delivery - Webhook delivery
   */
  private async deliverWebhook(delivery: WebhookDelivery): Promise<void> {
    delivery.attempt++;
    delivery.status = 'pending';

    try {
      // Get webhook configuration
      const webhook = await this.getWebhookById(delivery.webhook_id);
      if (!webhook) {
        delivery.status = 'failed';
        delivery.error_message = 'Webhook configuration not found';
        return;
      }

      // Prepare payload
      const payload = JSON.stringify(delivery.event);
      const signature = this.generateSignature(payload, webhook.secret);

      // Make HTTP request
      const startTime = Date.now();
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Claude-Memory-Webhook/1.0',
          'X-Webhook-Event': delivery.event.event_type,
          'X-Webhook-ID': delivery.webhook_id,
          'X-Webhook-Signature': signature,
          'X-Webhook-Timestamp': delivery.event.timestamp,
        },
        body: payload,
        signal: AbortSignal.timeout(webhook.timeout_seconds * 1000 || this.deliveryTimeout),
      });

      delivery.delivery_time = Date.now() - startTime;
      delivery.response_status = response.status;

      if (response.ok) {
        delivery.status = 'delivered';
        delivery.response_body = await response.text().catch(() => '');
        
        // Update webhook success metrics
        await this.updateWebhookMetrics(webhook.id, true);
        
        logger.debug(`Webhook delivered successfully: ${delivery.webhook_id}`);
      } else {
        delivery.status = 'failed';
        delivery.response_body = await response.text().catch(() => '');
        delivery.error_message = `HTTP ${response.status}: ${response.statusText}`;
        
        // Retry if attempts remaining
        if (delivery.attempt < this.maxRetries) {
          await this.scheduleRetry(delivery);
        } else {
          await this.updateWebhookMetrics(webhook.id, false);
        }
      }
    } catch (error: any) {
      delivery.status = 'failed';
      delivery.error_message = error.message;
      
      if (error.name === 'TimeoutError') {
        delivery.status = 'timeout';
        delivery.error_message = 'Request timeout';
      }

      // Retry if attempts remaining
      if (delivery.attempt < this.maxRetries) {
        await this.scheduleRetry(delivery);
      } else {
        await this.updateWebhookMetrics(delivery.webhook_id, false);
      }
      
      logger.warn(`Webhook delivery failed: ${delivery.webhook_id}`, {
        attempt: delivery.attempt,
        error: error.message,
      });
    }

    // Log delivery for audit
    await auditService.log({
      user_id: delivery.event.user_id,
      action: 'webhook_delivery',
      resource_type: 'webhook',
      resource_id: delivery.webhook_id,
      details: {
        event_type: delivery.event.event_type,
        status: delivery.status,
        attempt: delivery.attempt,
        response_status: delivery.response_status,
        delivery_time: delivery.delivery_time,
        error: delivery.error_message,
      },
    });
  }

  /**
   * Schedule webhook retry
   * @param delivery - Failed webhook delivery
   */
  private async scheduleRetry(delivery: WebhookDelivery): Promise<void> {
    const retryDelay = this.retryDelays[delivery.attempt - 1] || this.retryDelays[this.retryDelays.length - 1];
    
    const timerId = setTimeout(async () => {
      this.retryTimers.delete(delivery.webhook_id);
      await this.deliverWebhook(delivery);
    }, retryDelay);

    this.retryTimers.set(delivery.webhook_id, timerId);
    
    logger.debug(`Scheduled webhook retry: ${delivery.webhook_id} in ${retryDelay}ms`);
  }

  /**
   * Get webhook by ID
   * @param webhookId - Webhook ID
   */
  private async getWebhookById(webhookId: string): Promise<any | null> {
    try {
      // Note: We need the user_id to get the correct database
      // For now, we'll use master database or implement a webhook cache
      // In production, you might want to cache webhook configs
      return null; // Placeholder - implement based on your needs
    } catch (error) {
      logger.error('Failed to get webhook by ID:', error);
      return null;
    }
  }

  /**
   * Update webhook metrics
   * @param webhookId - Webhook ID
   * @param success - Whether delivery was successful
   */
  private async updateWebhookMetrics(webhookId: string, success: boolean): Promise<void> {
    try {
      // Update webhook last status and failure count
      // Implementation depends on how you want to store these metrics
      logger.debug(`Updated webhook metrics: ${webhookId}, success: ${success}`);
    } catch (error) {
      logger.error('Failed to update webhook metrics:', error);
    }
  }

  /**
   * Generate webhook signature for security
   * @param payload - Webhook payload
   * @param secret - Webhook secret
   */
  private generateSignature(payload: string, secret: string): string {
    if (!secret) {
      return '';
    }

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload);
    return `sha256=${hmac.digest('hex')}`;
  }

  /**
   * Verify webhook signature
   * @param payload - Webhook payload
   * @param signature - Received signature
   * @param secret - Webhook secret
   */
  verifySignature(payload: string, signature: string, secret: string): boolean {
    if (!secret || !signature) {
      return false;
    }

    const expectedSignature = this.generateSignature(payload, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Create webhook
   * @param userId - User ID
   * @param webhookData - Webhook configuration
   */
  async createWebhook(userId: string, webhookData: {
    project_id?: string;
    name: string;
    url: string;
    events: string[];
    secret?: string;
    retry_count?: number;
    timeout_seconds?: number;
  }): Promise<any> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Validate webhook URL
      await this.validateWebhookUrl(webhookData.url);

      // Generate secret if not provided
      const secret = webhookData.secret || crypto.randomBytes(32).toString('hex');

      const [webhook] = await db
        .insert(tenantSchema.webhooks)
        .values({
          project_id: webhookData.project_id,
          name: webhookData.name,
          url: webhookData.url,
          secret,
          events: webhookData.events,
          retry_count: webhookData.retry_count || 3,
          timeout_seconds: webhookData.timeout_seconds || 30,
          is_active: true,
          failure_count: 0,
          metadata: {
            created_by: userId,
          },
        })
        .returning();

      // Test webhook
      await this.testWebhook(userId, webhook.id);

      logger.info(`Created webhook: ${webhook.id} for user: ${userId}`);
      return webhook;
    } catch (error) {
      logger.error('Failed to create webhook:', error);
      throw error;
    }
  }

  /**
   * Test webhook endpoint
   * @param userId - User ID
   * @param webhookId - Webhook ID
   */
  async testWebhook(userId: string, webhookId: string): Promise<{
    success: boolean;
    response_time?: number;
    status_code?: number;
    error?: string;
  }> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      const [webhook] = await db
        .select()
        .from(tenantSchema.webhooks)
        .where(`id = $1`, [webhookId])
        .limit(1);

      if (!webhook) {
        throw new Error('Webhook not found');
      }

      // Create test event
      const testEvent: WebhookEvent = {
        event_type: 'webhook.test',
        event_id: this.generateEventId(),
        timestamp: new Date().toISOString(),
        user_id: userId,
        data: {
          message: 'This is a test webhook delivery',
          webhook_id: webhookId,
        },
        metadata: {
          test: true,
        },
      };

      // Deliver test webhook
      const delivery: WebhookDelivery = {
        webhook_id: webhookId,
        event: testEvent,
        attempt: 1,
        status: 'pending',
        created_at: new Date(),
      };

      await this.deliverWebhook(delivery);

      return {
        success: delivery.status === 'delivered',
        response_time: delivery.delivery_time,
        status_code: delivery.response_status,
        error: delivery.error_message,
      };
    } catch (error: any) {
      logger.error('Failed to test webhook:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Validate webhook URL
   * @param url - Webhook URL
   */
  private async validateWebhookUrl(url: string): Promise<void> {
    try {
      const urlObj = new URL(url);
      
      // Security checks
      if (urlObj.protocol !== 'https:' && urlObj.protocol !== 'http:') {
        throw new Error('Invalid protocol. Only HTTP and HTTPS are supported');
      }

      // Prevent localhost/private IP access in production
      if (process.env.NODE_ENV === 'production') {
        const hostname = urlObj.hostname;
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('10.') ||
          hostname.startsWith('172.')
        ) {
          throw new Error('Private IP addresses are not allowed in production');
        }
      }
    } catch (error: any) {
      throw new Error(`Invalid webhook URL: ${error.message}`);
    }
  }

  /**
   * Get webhooks for user
   * @param userId - User ID
   * @param projectId - Optional project filter
   */
  async getWebhooks(userId: string, projectId?: string): Promise<any[]> {
    try {
      const db = await databaseService.getUserDatabase(userId);
      
      let query = db.select().from(tenantSchema.webhooks);
      
      if (projectId) {
        query = query.where(`project_id = $1`, [projectId]);
      }

      return await query.orderBy(tenantSchema.webhooks.created_at, 'desc');
    } catch (error) {
      logger.error('Failed to get webhooks:', error);
      throw error;
    }
  }

  /**
   * Update webhook
   * @param userId - User ID
   * @param webhookId - Webhook ID
   * @param updates - Webhook updates
   */
  async updateWebhook(userId: string, webhookId: string, updates: {
    name?: string;
    url?: string;
    events?: string[];
    is_active?: boolean;
    retry_count?: number;
    timeout_seconds?: number;
  }): Promise<any> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Validate URL if being updated
      if (updates.url) {
        await this.validateWebhookUrl(updates.url);
      }

      const [webhook] = await db
        .update(tenantSchema.webhooks)
        .set({
          ...updates,
          updated_at: new Date(),
        })
        .where(`id = $1`, [webhookId])
        .returning();

      if (!webhook) {
        throw new Error('Webhook not found');
      }

      logger.info(`Updated webhook: ${webhookId} for user: ${userId}`);
      return webhook;
    } catch (error) {
      logger.error('Failed to update webhook:', error);
      throw error;
    }
  }

  /**
   * Delete webhook
   * @param userId - User ID
   * @param webhookId - Webhook ID
   */
  async deleteWebhook(userId: string, webhookId: string): Promise<void> {
    try {
      const db = await databaseService.getUserDatabase(userId);

      // Cancel any pending retries
      if (this.retryTimers.has(webhookId)) {
        clearTimeout(this.retryTimers.get(webhookId)!);
        this.retryTimers.delete(webhookId);
      }

      // Remove from delivery queue
      this.deliveryQueue.delete(webhookId);

      // Delete from database
      const result = await db
        .delete(tenantSchema.webhooks)
        .where(`id = $1`, [webhookId]);

      if (result.rowCount === 0) {
        throw new Error('Webhook not found');
      }

      logger.info(`Deleted webhook: ${webhookId} for user: ${userId}`);
    } catch (error) {
      logger.error('Failed to delete webhook:', error);
      throw error;
    }
  }

  /**
   * Get webhook delivery history
   * @param userId - User ID
   * @param webhookId - Webhook ID
   * @param limit - Number of deliveries to return
   */
  async getDeliveryHistory(userId: string, webhookId: string, limit = 50): Promise<any[]> {
    try {
      // In a real implementation, you'd store delivery history in the database
      // For now, return empty array
      return [];
    } catch (error) {
      logger.error('Failed to get delivery history:', error);
      throw error;
    }
  }

  /**
   * Start delivery processor
   */
  private startDeliveryProcessor(): void {
    // Process queue every 5 seconds
    setInterval(() => {
      if (!this.isProcessing && this.hasQueuedDeliveries()) {
        this.processDeliveryQueue();
      }
    }, 5000);
  }

  /**
   * Check if there are queued deliveries
   */
  private hasQueuedDeliveries(): boolean {
    for (const deliveries of this.deliveryQueue.values()) {
      if (deliveries.length > 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get service status
   */
  getStatus(): {
    queued_deliveries: number;
    active_retries: number;
    processing: boolean;
  } {
    let queuedCount = 0;
    for (const deliveries of this.deliveryQueue.values()) {
      queuedCount += deliveries.length;
    }

    return {
      queued_deliveries: queuedCount,
      active_retries: this.retryTimers.size,
      processing: this.isProcessing,
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down webhook service...');
      
      // Cancel all retry timers
      for (const timer of this.retryTimers.values()) {
        clearTimeout(timer);
      }
      this.retryTimers.clear();

      // Clear delivery queues
      this.deliveryQueue.clear();

      logger.info('Webhook service shutdown completed');
    } catch (error) {
      logger.error('Error during webhook service shutdown:', error);
    }
  }
}

// Export singleton instance
export const webhookService = new WebhookService();