import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage } from 'http';
import jwt from 'jsonwebtoken';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { auditService } from '@/services/auditService';
import type { WebSocketMessage, WebSocketRoom, JWTPayload, AuthUser } from '@/types/database.types';

interface AuthenticatedWebSocket extends WebSocket {
  user?: AuthUser;
  userId?: string;
  sessionId?: string;
  rooms?: Set<string>;
  lastPing?: number;
  isAlive?: boolean;
}

/**
 * WebSocket Service
 * Handles real-time communication for the application
 * Supports rooms, authentication, and message broadcasting
 */
class WebSocketService {
  private wss: WebSocketServer | null = null;
  private clients: Map<string, AuthenticatedWebSocket> = new Map();
  private rooms: Map<string, WebSocketRoom> = new Map();
  private pingInterval: NodeJS.Timeout | null = null;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private readonly PING_INTERVAL = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly MAX_CONNECTIONS_PER_USER = 5;

  /**
   * Initialize WebSocket server
   * @param wss - WebSocket server instance
   */
  initialize(wss: WebSocketServer): void {
    this.wss = wss;
    this.setupWebSocketServer();
    this.startPingPong();
    this.startCleanup();
    
    logger.info('WebSocket service initialized');
  }

  /**
   * Setup WebSocket server event handlers
   */
  private setupWebSocketServer(): void {
    if (!this.wss) return;

    this.wss.on('connection', (ws: AuthenticatedWebSocket, req: IncomingMessage) => {
      this.handleConnection(ws, req);
    });

    this.wss.on('error', (error) => {
      logger.error('WebSocket server error:', error);
    });

    this.wss.on('close', () => {
      logger.info('WebSocket server closed');
      this.cleanup();
    });
  }

  /**
   * Handle new WebSocket connection
   * @param ws - WebSocket connection
   * @param req - HTTP request
   */
  private async handleConnection(ws: AuthenticatedWebSocket, req: IncomingMessage): Promise<void> {
    const clientIp = req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    logger.debug('New WebSocket connection attempt', { ip: clientIp, userAgent });

    try {
      // Extract token from query params or headers
      const url = new URL(req.url || '', `http://${req.headers.host}`);
      const token = url.searchParams.get('token') || req.headers.authorization?.replace('Bearer ', '');

      if (!token) {
        this.closeWithError(ws, 4001, 'Authentication token required');
        return;
      }

      // Verify JWT token
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;
      
      // Set up authenticated WebSocket
      ws.user = {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        name: '',
      };
      ws.userId = decoded.userId;
      ws.sessionId = decoded.sessionId;
      ws.rooms = new Set();
      ws.isAlive = true;
      ws.lastPing = Date.now();

      // Check connection limits
      const userConnections = Array.from(this.clients.values())
        .filter(client => client.userId === decoded.userId);
      
      if (userConnections.length >= this.MAX_CONNECTIONS_PER_USER) {
        this.closeWithError(ws, 4003, 'Maximum connections per user exceeded');
        return;
      }

      // Generate unique client ID
      const clientId = `${decoded.userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      this.clients.set(clientId, ws);

      // Setup WebSocket event handlers
      this.setupClientHandlers(ws, clientId);

      // Send welcome message
      this.sendToClient(ws, {
        type: 'status',
        data: {
          status: 'connected',
          client_id: clientId,
          user_id: decoded.userId,
        },
        timestamp: new Date().toISOString(),
        user_id: decoded.userId,
      });

      // Log connection
      await auditService.log({
        user_id: decoded.userId,
        action: 'websocket_connect',
        resource_type: 'websocket',
        details: {
          client_id: clientId,
          ip_address: clientIp,
          user_agent: userAgent,
        },
        ip_address: clientIp,
        user_agent: userAgent,
      });

      logger.info(`WebSocket client connected: ${clientId} (user: ${decoded.userId})`);

    } catch (error: any) {
      logger.warn('WebSocket authentication failed:', error.message);
      this.closeWithError(ws, 4002, 'Authentication failed');
    }
  }

  /**
   * Setup event handlers for authenticated client
   * @param ws - WebSocket connection
   * @param clientId - Client ID
   */
  private setupClientHandlers(ws: AuthenticatedWebSocket, clientId: string): void {
    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString());
        await this.handleClientMessage(ws, clientId, message);
      } catch (error: any) {
        logger.warn(`Invalid message from client ${clientId}:`, error.message);
        this.sendError(ws, 'Invalid message format');
      }
    });

    ws.on('pong', () => {
      ws.isAlive = true;
      ws.lastPing = Date.now();
    });

    ws.on('close', async (code, reason) => {
      await this.handleClientDisconnect(clientId, code, reason.toString());
    });

    ws.on('error', (error) => {
      logger.error(`WebSocket client error (${clientId}):`, error);
    });
  }

  /**
   * Handle message from client
   * @param ws - WebSocket connection
   * @param clientId - Client ID
   * @param message - Received message
   */
  private async handleClientMessage(
    ws: AuthenticatedWebSocket, 
    clientId: string, 
    message: any
  ): Promise<void> {
    if (!ws.user) return;

    const { type, data } = message;

    switch (type) {
      case 'join_room':
        await this.handleJoinRoom(ws, clientId, data.room_id);
        break;

      case 'leave_room':
        await this.handleLeaveRoom(ws, clientId, data.room_id);
        break;

      case 'typing':
        await this.handleTyping(ws, data);
        break;

      case 'message':
        await this.handleChatMessage(ws, data);
        break;

      case 'ping':
        this.sendToClient(ws, {
          type: 'pong',
          data: { timestamp: Date.now() },
          timestamp: new Date().toISOString(),
          user_id: ws.userId!,
        });
        break;

      default:
        this.sendError(ws, `Unknown message type: ${type}`);
    }
  }

  /**
   * Handle client joining a room
   * @param ws - WebSocket connection
   * @param clientId - Client ID
   * @param roomId - Room ID to join
   */
  private async handleJoinRoom(
    ws: AuthenticatedWebSocket, 
    clientId: string, 
    roomId: string
  ): Promise<void> {
    if (!ws.user || !roomId) return;

    try {
      // Validate room access (implement your authorization logic here)
      const canJoin = await this.validateRoomAccess(ws.user.id, roomId);
      if (!canJoin) {
        this.sendError(ws, 'Access denied to room');
        return;
      }

      // Create room if it doesn't exist
      if (!this.rooms.has(roomId)) {
        this.rooms.set(roomId, {
          id: roomId,
          type: this.getRoomType(roomId),
          participants: new Set(),
          created_at: new Date(),
        });
      }

      const room = this.rooms.get(roomId)!;
      
      // Add user to room
      room.participants.add(ws.userId!);
      ws.rooms!.add(roomId);

      // Notify room members
      this.broadcastToRoom(roomId, {
        type: 'notification',
        data: {
          event: 'user_joined',
          user_id: ws.user.id,
          room_id: roomId,
        },
        timestamp: new Date().toISOString(),
        user_id: ws.user.id,
      }, ws.userId);

      // Confirm join to client
      this.sendToClient(ws, {
        type: 'status',
        data: {
          event: 'room_joined',
          room_id: roomId,
          participants_count: room.participants.size,
        },
        timestamp: new Date().toISOString(),
        user_id: ws.user.id,
      });

      logger.debug(`Client ${clientId} joined room ${roomId}`);

    } catch (error: any) {
      logger.error('Failed to join room:', error);
      this.sendError(ws, 'Failed to join room');
    }
  }

  /**
   * Handle client leaving a room
   * @param ws - WebSocket connection
   * @param clientId - Client ID
   * @param roomId - Room ID to leave
   */
  private async handleLeaveRoom(
    ws: AuthenticatedWebSocket, 
    clientId: string, 
    roomId: string
  ): Promise<void> {
    if (!ws.user || !roomId || !ws.rooms?.has(roomId)) return;

    const room = this.rooms.get(roomId);
    if (room) {
      room.participants.delete(ws.userId!);
      ws.rooms.delete(roomId);

      // Notify room members
      this.broadcastToRoom(roomId, {
        type: 'notification',
        data: {
          event: 'user_left',
          user_id: ws.user.id,
          room_id: roomId,
        },
        timestamp: new Date().toISOString(),
        user_id: ws.user.id,
      }, ws.userId);

      // Remove empty rooms
      if (room.participants.size === 0) {
        this.rooms.delete(roomId);
      }
    }

    logger.debug(`Client ${clientId} left room ${roomId}`);
  }

  /**
   * Handle typing indicator
   * @param ws - WebSocket connection
   * @param data - Typing data
   */
  private async handleTyping(ws: AuthenticatedWebSocket, data: any): Promise<void> {
    if (!ws.user || !data.room_id) return;

    const { room_id, is_typing } = data;

    // Broadcast typing status to room members
    this.broadcastToRoom(room_id, {
      type: 'typing',
      data: {
        user_id: ws.user.id,
        is_typing,
        room_id,
      },
      timestamp: new Date().toISOString(),
      user_id: ws.user.id,
    }, ws.userId);
  }

  /**
   * Handle chat message
   * @param ws - WebSocket connection
   * @param data - Message data
   */
  private async handleChatMessage(ws: AuthenticatedWebSocket, data: any): Promise<void> {
    if (!ws.user) return;

    // This would typically save the message to database and broadcast
    // For now, just broadcast to room members
    const { room_id, content, message_id } = data;

    if (!room_id || !content) {
      this.sendError(ws, 'Room ID and content are required');
      return;
    }

    const message: WebSocketMessage = {
      type: 'message',
      conversation_id: room_id,
      user_id: ws.user.id,
      data: {
        message_id: message_id || `msg_${Date.now()}`,
        content,
        sender: {
          id: ws.user.id,
          name: ws.user.name,
        },
      },
      timestamp: new Date().toISOString(),
    };

    this.broadcastToRoom(room_id, message);
  }

  /**
   * Handle client disconnect
   * @param clientId - Client ID
   * @param code - Close code
   * @param reason - Close reason
   */
  private async handleClientDisconnect(clientId: string, code: number, reason: string): Promise<void> {
    const ws = this.clients.get(clientId);
    if (!ws) return;

    // Leave all rooms
    if (ws.rooms) {
      for (const roomId of ws.rooms) {
        await this.handleLeaveRoom(ws, clientId, roomId);
      }
    }

    // Remove client
    this.clients.delete(clientId);

    // Log disconnection
    if (ws.user) {
      await auditService.log({
        user_id: ws.user.id,
        action: 'websocket_disconnect',
        resource_type: 'websocket',
        details: {
          client_id: clientId,
          close_code: code,
          reason,
        },
      });

      logger.info(`WebSocket client disconnected: ${clientId} (user: ${ws.user.id})`);
    }
  }

  /**
   * Send message to specific client
   * @param ws - WebSocket connection
   * @param message - Message to send
   */
  private sendToClient(ws: AuthenticatedWebSocket, message: WebSocketMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error: any) {
        logger.error('Failed to send message to client:', error);
      }
    }
  }

  /**
   * Send error message to client
   * @param ws - WebSocket connection
   * @param error - Error message
   */
  private sendError(ws: AuthenticatedWebSocket, error: string): void {
    this.sendToClient(ws, {
      type: 'error',
      data: { error },
      timestamp: new Date().toISOString(),
      user_id: ws.userId || 'unknown',
    });
  }

  /**
   * Broadcast message to all clients in a room
   * @param roomId - Room ID
   * @param message - Message to broadcast
   * @param excludeUserId - User ID to exclude from broadcast
   */
  broadcastToRoom(roomId: string, message: WebSocketMessage, excludeUserId?: string): void {
    const room = this.rooms.get(roomId);
    if (!room) return;

    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.rooms?.has(roomId) && ws.userId !== excludeUserId) {
        this.sendToClient(ws, message);
      }
    }
  }

  /**
   * Broadcast message to specific user (all their connections)
   * @param userId - User ID
   * @param message - Message to broadcast
   */
  broadcastToUser(userId: string, message: WebSocketMessage): void {
    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.userId === userId) {
        this.sendToClient(ws, message);
      }
    }
  }

  /**
   * Broadcast message to all connected clients
   * @param message - Message to broadcast
   */
  broadcastToAll(message: WebSocketMessage): void {
    for (const [clientId, ws] of this.clients.entries()) {
      this.sendToClient(ws, message);
    }
  }

  /**
   * Close connection with error
   * @param ws - WebSocket connection
   * @param code - Close code
   * @param reason - Close reason
   */
  private closeWithError(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch (error) {
      logger.error('Failed to close WebSocket with error:', error);
    }
  }

  /**
   * Validate room access for user
   * @param userId - User ID
   * @param roomId - Room ID
   */
  private async validateRoomAccess(userId: string, roomId: string): Promise<boolean> {
    // Implement your room access validation logic here
    // For example, check if user has access to the conversation/project
    
    try {
      // Example validation logic:
      // - For conversation rooms: check if user owns the conversation
      // - For project rooms: check if user is a collaborator
      // - For public rooms: allow all authenticated users
      
      return true; // Placeholder - implement actual validation
  /**
   * Validate room access for user
   * @param userId - User ID
   * @param roomId - Room ID
   */
  private async validateRoomAccess(userId: string, roomId: string): Promise<boolean> {
    // Implement your room access validation logic here
    // For example, check if user has access to the conversation/project
    
    try {
      // Example validation logic:
      // - For conversation rooms: check if user owns the conversation
      // - For project rooms: check if user is a collaborator
      // - For public rooms: allow all authenticated users
      
      return true; // Placeholder - implement actual validation
    } catch (error) {
      logger.error('Room access validation failed:', error);
      return false;
    }
  }

  /**
   * Get room type based on room ID
   * @param roomId - Room ID
   */
  private getRoomType(roomId: string): 'conversation' | 'project' | 'user' {
    if (roomId.startsWith('conv_')) return 'conversation';
    if (roomId.startsWith('proj_')) return 'project';
    return 'user';
  }

  /**
   * Start ping-pong mechanism to detect dead connections
   */
  private startPingPong(): void {
    this.pingInterval = setInterval(() => {
      for (const [clientId, ws] of this.clients.entries()) {
        if (ws.isAlive === false) {
          logger.debug(`Terminating dead connection: ${clientId}`);
          ws.terminate();
          this.clients.delete(clientId);
          continue;
        }

        ws.isAlive = false;
        ws.ping();
      }
    }, this.PING_INTERVAL);
  }

  /**
   * Start cleanup routine for inactive connections and empty rooms
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupInactiveConnections();
      this.cleanupEmptyRooms();
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * Clean up inactive connections
   */
  private cleanupInactiveConnections(): void {
    const now = Date.now();
    const INACTIVE_THRESHOLD = 5 * 60 * 1000; // 5 minutes

    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.lastPing && (now - ws.lastPing) > INACTIVE_THRESHOLD) {
        logger.debug(`Cleaning up inactive connection: ${clientId}`);
        ws.terminate();
        this.clients.delete(clientId);
      }
    }
  }

  /**
   * Clean up empty rooms
   */
  private cleanupEmptyRooms(): void {
    for (const [roomId, room] of this.rooms.entries()) {
      if (room.participants.size === 0) {
        this.rooms.delete(roomId);
        logger.debug(`Cleaned up empty room: ${roomId}`);
      }
    }
  }

  /**
   * Get service statistics
   */
  getStats(): {
    connected_clients: number;
    active_rooms: number;
    total_connections: number;
    rooms_by_type: Record<string, number>;
    clients_by_user: Record<string, number>;
  } {
    const roomsByType: Record<string, number> = {};
    const clientsByUser: Record<string, number> = {};

    // Count rooms by type
    for (const room of this.rooms.values()) {
      roomsByType[room.type] = (roomsByType[room.type] || 0) + 1;
    }

    // Count clients by user
    for (const ws of this.clients.values()) {
      if (ws.userId) {
        clientsByUser[ws.userId] = (clientsByUser[ws.userId] || 0) + 1;
      }
    }

    return {
      connected_clients: this.clients.size,
      active_rooms: this.rooms.size,
      total_connections: this.clients.size,
      rooms_by_type: roomsByType,
      clients_by_user: clientsByUser,
    };
  }

  /**
   * Get clients in a specific room
   * @param roomId - Room ID
   */
  getRoomClients(roomId: string): string[] {
    const room = this.rooms.get(roomId);
    return room ? Array.from(room.participants) : [];
  }

  /**
   * Get rooms for a specific user
   * @param userId - User ID
   */
  getUserRooms(userId: string): string[] {
    const userRooms: string[] = [];
    
    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.userId === userId && ws.rooms) {
        userRooms.push(...Array.from(ws.rooms));
      }
    }

    return [...new Set(userRooms)]; // Remove duplicates
  }

  /**
   * Check if user is online
   * @param userId - User ID
   */
  isUserOnline(userId: string): boolean {
    for (const ws of this.clients.values()) {
      if (ws.userId === userId && ws.readyState === WebSocket.OPEN) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get online users
   */
  getOnlineUsers(): string[] {
    const onlineUsers = new Set<string>();
    
    for (const ws of this.clients.values()) {
      if (ws.userId && ws.readyState === WebSocket.OPEN) {
        onlineUsers.add(ws.userId);
      }
    }

    return Array.from(onlineUsers);
  }

  /**
   * Notify conversation participants of new message
   * @param conversationId - Conversation ID
   * @param message - Message data
   */
  notifyConversationMessage(conversationId: string, message: {
    id: string;
    content: string;
    role: string;
    sender?: any;
    tokens_used?: number;
  }): void {
    const roomId = `conv_${conversationId}`;
    
    this.broadcastToRoom(roomId, {
      type: 'message',
      conversation_id: conversationId,
      data: {
        message_id: message.id,
        content: message.content,
        role: message.role,
        sender: message.sender,
        tokens_used: message.tokens_used,
        timestamp: new Date().toISOString(),
      },
      timestamp: new Date().toISOString(),
      user_id: message.sender?.id || 'system',
    });
  }

  /**
   * Notify project members of updates
   * @param projectId - Project ID
   * @param event - Event type
   * @param data - Event data
   */
  notifyProjectUpdate(projectId: string, event: string, data: any): void {
    const roomId = `proj_${projectId}`;
    
    this.broadcastToRoom(roomId, {
      type: 'notification',
      project_id: projectId,
      data: {
        event,
        ...data,
      },
      timestamp: new Date().toISOString(),
      user_id: data.user_id || 'system',
    });
  }

  /**
   * Send system notification to user
   * @param userId - User ID
   * @param notification - Notification data
   */
  sendNotificationToUser(userId: string, notification: {
    title: string;
    message: string;
    type: 'info' | 'success' | 'warning' | 'error';
    data?: any;
  }): void {
    this.broadcastToUser(userId, {
      type: 'notification',
      data: {
        notification_type: 'system',
        ...notification,
      },
      timestamp: new Date().toISOString(),
      user_id: userId,
    });
  }

  /**
   * Send typing indicator
   * @param conversationId - Conversation ID
   * @param userId - User ID who is typing
   * @param isTyping - Whether user is typing
   */
  sendTypingIndicator(conversationId: string, userId: string, isTyping: boolean): void {
    const roomId = `conv_${conversationId}`;
    
    this.broadcastToRoom(roomId, {
      type: 'typing',
      conversation_id: conversationId,
      data: {
        user_id: userId,
        is_typing: isTyping,
      },
      timestamp: new Date().toISOString(),
      user_id: userId,
    }, userId); // Exclude the typing user
  }

  /**
   * Force disconnect user
   * @param userId - User ID to disconnect
   * @param reason - Disconnect reason
   */
  disconnectUser(userId: string, reason: string = 'Forced disconnect'): void {
    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.userId === userId) {
        this.closeWithError(ws, 4000, reason);
        this.clients.delete(clientId);
      }
    }

    logger.info(`Forcefully disconnected user: ${userId}, reason: ${reason}`);
  }

  /**
   * Send maintenance notification to all users
   * @param message - Maintenance message
   * @param scheduledTime - Scheduled maintenance time
   */
  broadcastMaintenanceNotification(message: string, scheduledTime?: Date): void {
    this.broadcastToAll({
      type: 'notification',
      data: {
        notification_type: 'maintenance',
        message,
        scheduled_time: scheduledTime?.toISOString(),
        severity: 'warning',
      },
      timestamp: new Date().toISOString(),
      user_id: 'system',
    });
  }

  /**
   * Get detailed room information
   * @param roomId - Room ID
   */
  getRoomInfo(roomId: string): {
    room: WebSocketRoom | null;
    participants: Array<{
      user_id: string;
      connected_at: Date;
      client_count: number;
    }>;
  } {
    const room = this.rooms.get(roomId);
    if (!room) {
      return { room: null, participants: [] };
    }

    const participantInfo = new Map<string, { connected_at: Date; client_count: number }>();

    for (const [clientId, ws] of this.clients.entries()) {
      if (ws.rooms?.has(roomId) && ws.userId) {
        if (participantInfo.has(ws.userId)) {
          participantInfo.get(ws.userId)!.client_count++;
        } else {
          participantInfo.set(ws.userId, {
            connected_at: new Date(), // You might want to track actual connection time
            client_count: 1,
          });
        }
      }
    }

    const participants = Array.from(participantInfo.entries()).map(([userId, info]) => ({
      user_id: userId,
      connected_at: info.connected_at,
      client_count: info.client_count,
    }));

    return { room, participants };
  }

  /**
   * Cleanup and shutdown
   */
  async cleanup(): Promise<void> {
    try {
      logger.info('WebSocket service cleanup started');

      // Clear intervals
      if (this.pingInterval) {
        clearInterval(this.pingInterval);
        this.pingInterval = null;
      }

      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
        this.cleanupInterval = null;
      }

      // Send shutdown notification to all clients
      this.broadcastToAll({
        type: 'notification',
        data: {
          notification_type: 'system',
          message: 'Server is shutting down',
          severity: 'info',
        },
        timestamp: new Date().toISOString(),
        user_id: 'system',
      });

      // Close all connections
      for (const [clientId, ws] of this.clients.entries()) {
        ws.close(1001, 'Server shutdown');
      }

      // Clear data structures
      this.clients.clear();
      this.rooms.clear();

      // Close WebSocket server
      if (this.wss) {
        this.wss.close();
        this.wss = null;
      }

      logger.info('WebSocket service cleanup completed');
    } catch (error) {
      logger.error('Error during WebSocket service cleanup:', error);
    }
  }

  /**
   * Health check for WebSocket service
   */
  healthCheck(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: {
      server_running: boolean;
      connected_clients: number;
      active_rooms: number;
      ping_interval_active: boolean;
      cleanup_interval_active: boolean;
    };
  } {
    const isHealthy = this.wss !== null && this.pingInterval !== null && this.cleanupInterval !== null;
    
    return {
      status: isHealthy ? 'healthy' : 'unhealthy',
      details: {
        server_running: this.wss !== null,
        connected_clients: this.clients.size,
        active_rooms: this.rooms.size,
        ping_interval_active: this.pingInterval !== null,
        cleanup_interval_active: this.cleanupInterval !== null,
      },
    };
  }
}

// Export singleton instance
export const webSocketService = new WebSocketService();