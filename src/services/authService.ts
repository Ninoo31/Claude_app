import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { eq, and, gt } from 'drizzle-orm';

import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { databaseService } from '@/services/databaseService';
import * as masterSchema from '@/database/schemas/master.schema';
import type { User, NewUser, UserSession, NewUserSession, AuthUser, JWTPayload } from '@/types/database.types';

/**
 * Authentication Service
 * Handles user registration, login, session management
 * JWT token generation and validation
 */
class AuthService {
  private readonly SALT_ROUNDS = 12;
  private readonly SESSION_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

  /**
   * Register a new user
   * @param userData - User registration data
   */
  async register(userData: {
    email: string;
    password: string;
    name: string;
  }): Promise<{ user: AuthUser; tokens: { accessToken: string; refreshToken: string } }> {
    try {
      const masterDb = databaseService.getMasterDb();

      // Check if user already exists
      const existingUser = await masterDb
        .select()
        .from(masterSchema.users)
        .where(eq(masterSchema.users.email, userData.email.toLowerCase()))
        .limit(1);

      if (existingUser.length > 0) {
        throw new Error('User with this email already exists');
      }

      // Hash password
      const passwordHash = await bcrypt.hash(userData.password, this.SALT_ROUNDS);

      // Create user
      const [newUser] = await masterDb
        .insert(masterSchema.users)
        .values({
          email: userData.email.toLowerCase(),
          password_hash: passwordHash,
          name: userData.name,
          email_verified: false, // In production, implement email verification
          is_active: true,
          role: 'user',
          preferences: {
            theme: 'dark',
            language: 'en',
            notifications: {
              email: true,
              push: false,
            },
          },
        })
        .returning();

      // Create session
      const session = await this.createSession(newUser.id, {
        ip_address: null,
        user_agent: null,
      });

      // Generate tokens
      const tokens = await this.generateTokens(newUser, session.id);

      logger.info(`User registered successfully: ${newUser.email}`);

      return {
        user: this.formatAuthUser(newUser),
        tokens,
      };
    } catch (error) {
      logger.error('Registration failed:', error);
      throw error;
    }
  }

  /**
   * Authenticate user login
   * @param credentials - Login credentials
   * @param sessionInfo - Session information (IP, user agent)
   */
  async login(
    credentials: { email: string; password: string },
    sessionInfo: { ip_address?: string; user_agent?: string }
  ): Promise<{ user: AuthUser; tokens: { accessToken: string; refreshToken: string } }> {
    try {
      const masterDb = databaseService.getMasterDb();

      // Find user by email
      const [user] = await masterDb
        .select()
        .from(masterSchema.users)
        .where(
          and(
            eq(masterSchema.users.email, credentials.email.toLowerCase()),
            eq(masterSchema.users.is_active, true)
          )
        )
        .limit(1);

      if (!user) {
        throw new Error('Invalid email or password');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(credentials.password, user.password_hash);
      if (!isValidPassword) {
        throw new Error('Invalid email or password');
      }

      // Update last login
      await masterDb
        .update(masterSchema.users)
        .set({ last_login_at: new Date() })
        .where(eq(masterSchema.users.id, user.id));

      // Create session
      const session = await this.createSession(user.id, sessionInfo);

      // Generate tokens
      const tokens = await this.generateTokens(user, session.id);

      logger.info(`User logged in successfully: ${user.email}`);

      return {
        user: this.formatAuthUser(user),
        tokens,
      };
    } catch (error) {
      logger.error('Login failed:', error);
      throw error;
    }
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - Valid refresh token
   */
  async refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const masterDb = databaseService.getMasterDb();

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.jwt.secret) as JWTPayload;

      // Find session
      const [session] = await masterDb
        .select()
        .from(masterSchema.userSessions)
        .where(
          and(
            eq(masterSchema.userSessions.id, decoded.sessionId),
            eq(masterSchema.userSessions.refresh_token, refreshToken),
            gt(masterSchema.userSessions.expires_at, new Date())
          )
        )
        .limit(1);

      if (!session) {
        throw new Error('Invalid or expired refresh token');
      }

      // Get user
      const [user] = await masterDb
        .select()
        .from(masterSchema.users)
        .where(eq(masterSchema.users.id, session.user_id))
        .limit(1);

      if (!user || !user.is_active) {
        throw new Error('User not found or inactive');
      }

      // Generate new tokens
      const tokens = await this.generateTokens(user, session.id);

      // Update session with new refresh token
      await masterDb
        .update(masterSchema.userSessions)
        .set({
          refresh_token: tokens.refreshToken,
          last_used_at: new Date(),
        })
        .where(eq(masterSchema.userSessions.id, session.id));

      return tokens;
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  /**
   * Logout user and invalidate session
   * @param sessionId - Session ID to invalidate
   */
  async logout(sessionId: string): Promise<void> {
    try {
      const masterDb = databaseService.getMasterDb();

      await masterDb
        .delete(masterSchema.userSessions)
        .where(eq(masterSchema.userSessions.id, sessionId));

      logger.info(`Session logged out: ${sessionId}`);
    } catch (error) {
      logger.error('Logout failed:', error);
      throw error;
    }
  }

  /**
   * Verify JWT token and return user information
   * @param token - JWT access token
   */
  async verifyToken(token: string): Promise<AuthUser> {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;
      const masterDb = databaseService.getMasterDb();

      // Verify session is still valid
      const [session] = await masterDb
        .select()
        .from(masterSchema.userSessions)
        .where(
          and(
            eq(masterSchema.userSessions.id, decoded.sessionId),
            gt(masterSchema.userSessions.expires_at, new Date())
          )
        )
        .limit(1);

      if (!session) {
        throw new Error('Session expired or invalid');
      }

      // Get user
      const [user] = await masterDb
        .select()
        .from(masterSchema.users)
        .where(eq(masterSchema.users.id, decoded.userId))
        .limit(1);

      if (!user || !user.is_active) {
        throw new Error('User not found or inactive');
      }

      // Update session last used
      await masterDb
        .update(masterSchema.userSessions)
        .set({ last_used_at: new Date() })
        .where(eq(masterSchema.userSessions.id, session.id));

      return this.formatAuthUser(user);
    } catch (error) {
      logger.debug('Token verification failed:', error);
      throw error;
    }
  }

  /**
   * Get user by ID
   * @param userId - User ID
   */
  async getUserById(userId: string): Promise<AuthUser | null> {
    try {
      const masterDb = databaseService.getMasterDb();

      const [user] = await masterDb
        .select()
        .from(masterSchema.users)
        .where(eq(masterSchema.users.id, userId))
        .limit(1);

      return user ? this.formatAuthUser(user) : null;
    } catch (error) {
      logger.error('Get user by ID failed:', error);
      throw error;
    }
  }

  /**
   * Update user profile
   * @param userId - User ID
   * @param updates - Profile updates
   */
  async updateProfile(
    userId: string,
    updates: Partial<Pick<User, 'name' | 'avatar_url' | 'preferences'>>
  ): Promise<AuthUser> {
    try {
      const masterDb = databaseService.getMasterDb();

      const [updatedUser] = await masterDb
        .update(masterSchema.users)
        .set({
          ...updates,
          updated_at: new Date(),
        })
        .where(eq(masterSchema.users.id, userId))
        .returning();

      logger.info(`User profile updated: ${userId}`);
      return this.formatAuthUser(updatedUser);
    } catch (error) {
      logger.error('Profile update failed:', error);
      throw error;
    }
  }

  /**
   * Change user password
   * @param userId - User ID
   * @param currentPassword - Current password for verification
   * @param newPassword - New password
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
    try {
      const masterDb = databaseService.getMasterDb();

      // Get current user
      const [user] = await masterDb
        .select()
        .from(masterSchema.users)
        .where(eq(masterSchema.users.id, userId))
        .limit(1);

      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, this.SALT_ROUNDS);

      // Update password
      await masterDb
        .update(masterSchema.users)
        .set({
          password_hash: newPasswordHash,
          updated_at: new Date(),
        })
        .where(eq(masterSchema.users.id, userId));

      // Invalidate all user sessions except current one (optional)
      // await this.invalidateUserSessions(userId, currentSessionId);

      logger.info(`Password changed for user: ${userId}`);
    } catch (error) {
      logger.error('Password change failed:', error);
      throw error;
    }
  }

  /**
   * Create a new user session
   * @param userId - User ID
   * @param sessionInfo - Session metadata
   */
  private async createSession(
    userId: string,
    sessionInfo: { ip_address?: string | null; user_agent?: string | null }
  ): Promise<UserSession> {
    const masterDb = databaseService.getMasterDb();
    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + this.SESSION_DURATION);

    const [session] = await masterDb
      .insert(masterSchema.userSessions)
      .values({
        id: sessionId,
        user_id: userId,
        expires_at: expiresAt,
        ip_address: sessionInfo.ip_address,
        user_agent: sessionInfo.user_agent,
      })
      .returning();

    return session;
  }

  /**
   * Generate JWT access and refresh tokens
   * @param user - User object
   * @param sessionId - Session ID
   */
  private async generateTokens(
    user: User,
    sessionId: string
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    };

    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
    });

    const refreshToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.refreshExpiresIn,
    });

    return { accessToken, refreshToken };
  }

  /**
   * Format user object for API responses
   * @param user - Database user object
   */
  private formatAuthUser(user: User): AuthUser {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      avatar_url: user.avatar_url,
      preferences: user.preferences as Record<string, any>,
    };
  }

  /**
   * Clean up expired sessions (run as scheduled job)
   */
  async cleanupExpiredSessions(): Promise<void> {
    try {
      const masterDb = databaseService.getMasterDb();

      const result = await masterDb
        .delete(masterSchema.userSessions)
        .where(gt(new Date(), masterSchema.userSessions.expires_at));

      logger.info(`Cleaned up expired sessions`);
    } catch (error) {
      logger.error('Session cleanup failed:', error);
    }
  }

  /**
   * Get user's active sessions
   * @param userId - User ID
   */
  async getUserSessions(userId: string): Promise<UserSession[]> {
    try {
      const masterDb = databaseService.getMasterDb();

      return await masterDb
        .select()
        .from(masterSchema.userSessions)
        .where(
          and(
            eq(masterSchema.userSessions.user_id, userId),
            gt(masterSchema.userSessions.expires_at, new Date())
          )
        )
        .orderBy(masterSchema.userSessions.last_used_at);
    } catch (error) {
      logger.error('Get user sessions failed:', error);
      throw error;
    }
  }

  /**
   * Invalidate specific session
   * @param userId - User ID
   * @param sessionId - Session ID to invalidate
   */
  async invalidateSession(userId: string, sessionId: string): Promise<void> {
    try {
      const masterDb = databaseService.getMasterDb();

      await masterDb
        .delete(masterSchema.userSessions)
        .where(
          and(
            eq(masterSchema.userSessions.user_id, userId),
            eq(masterSchema.userSessions.id, sessionId)
          )
        );

      logger.info(`Session invalidated: ${sessionId}`);
    } catch (error) {
      logger.error('Session invalidation failed:', error);
      throw error;
    }
  }
}

export const authService = new AuthService();