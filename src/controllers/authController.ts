import { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { authService } from '@/services/authService';
import { logger } from '@/utils/logger';
import type { ApiResponse } from '@/types/database.types';

/**
 * Authentication Controller
 * Handles user registration, login, logout, and token management
 */
class AuthController {
  /**
   * Register a new user
   */
  async register(req: Request, res: Response): Promise<void> {
    try {
      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
        return;
      }

      const { email, password, name } = req.body;

      // Register user
      const result = await authService.register({ email, password, name });

      // Set secure HTTP-only cookies
      this.setAuthCookies(res, result.tokens);

      const response: ApiResponse = {
        success: true,
        data: {
          user: result.user,
          tokens: result.tokens
        },
        message: 'User registered successfully',
        timestamp: new Date().toISOString()
      };

      res.status(201).json(response);
    } catch (error: any) {
      logger.error('Registration failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Registration failed',
        timestamp: new Date().toISOString()
      };

      res.status(400).json(response);
    }
  }

  /**
   * Login user
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
        return;
      }

      const { email, password } = req.body;
      const sessionInfo = {
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      };

      // Authenticate user
      const result = await authService.login({ email, password }, sessionInfo);

      // Set secure HTTP-only cookies
      this.setAuthCookies(res, result.tokens);

      const response: ApiResponse = {
        success: true,
        data: {
          user: result.user,
          tokens: result.tokens
        },
        message: 'Login successful',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Login failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Login failed',
        timestamp: new Date().toISOString()
      };

      res.status(401).json(response);
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          error: 'Refresh token required',
          timestamp: new Date().toISOString()
        });
        return;
      }

      // Refresh tokens
      const tokens = await authService.refreshToken(refreshToken);

      // Set new cookies
      this.setAuthCookies(res, tokens);

      const response: ApiResponse = {
        success: true,
        data: { tokens },
        message: 'Token refreshed successfully',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Token refresh failed:', error);
      
      // Clear invalid cookies
      this.clearAuthCookies(res);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Token refresh failed',
        timestamp: new Date().toISOString()
      };

      res.status(401).json(response);
    }
  }

  /**
   * Logout user
   */
  async logout(req: Request, res: Response): Promise<void> {
    try {
      const sessionId = req.sessionId;

      if (sessionId) {
        await authService.logout(sessionId);
      }

      // Clear cookies
      this.clearAuthCookies(res);

      const response: ApiResponse = {
        success: true,
        message: 'Logout successful',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Logout failed:', error);
      
      // Clear cookies anyway
      this.clearAuthCookies(res);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Logout failed',
        timestamp: new Date().toISOString()
      };

      res.status(500).json(response);
    }
  }

  /**
   * Get current user profile
   */
  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      const response: ApiResponse = {
        success: true,
        data: { user: req.user },
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Get profile failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Failed to get profile',
        timestamp: new Date().toISOString()
      };

      res.status(500).json(response);
    }
  }

  /**
   * Update user profile
   */
  async updateProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
        return;
      }

      const { name, avatar_url, preferences } = req.body;
      const updates: any = {};

      if (name !== undefined) updates.name = name;
      if (avatar_url !== undefined) updates.avatar_url = avatar_url;
      if (preferences !== undefined) updates.preferences = preferences;

      const updatedUser = await authService.updateProfile(req.user.id, updates);

      const response: ApiResponse = {
        success: true,
        data: { user: updatedUser },
        message: 'Profile updated successfully',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Update profile failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Profile update failed',
        timestamp: new Date().toISOString()
      };

      res.status(500).json(response);
    }
  }

  /**
   * Change user password
   */
  async changePassword(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors.array()
        });
        return;
      }

      const { currentPassword, newPassword } = req.body;

      await authService.changePassword(req.user.id, currentPassword, newPassword);

      const response: ApiResponse = {
        success: true,
        message: 'Password changed successfully',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Change password failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Password change failed',
        timestamp: new Date().toISOString()
      };

      res.status(400).json(response);
    }
  }

  /**
   * Get user's active sessions
   */
  async getSessions(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      const sessions = await authService.getUserSessions(req.user.id);

      // Remove sensitive data
      const safeSessions = sessions.map(session => ({
        id: session.id,
        created_at: session.created_at,
        last_used_at: session.last_used_at,
        expires_at: session.expires_at,
        ip_address: session.ip_address,
        user_agent: session.user_agent
      }));

      const response: ApiResponse = {
        success: true,
        data: { sessions: safeSessions },
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Get sessions failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Failed to get sessions',
        timestamp: new Date().toISOString()
      };

      res.status(500).json(response);
    }
  }

  /**
   * Invalidate a specific session
   */
  async invalidateSession(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'User not authenticated',
          timestamp: new Date().toISOString()
        });
        return;
      }

      const { sessionId } = req.params;

      await authService.invalidateSession(req.user.id, sessionId);

      const response: ApiResponse = {
        success: true,
        message: 'Session invalidated successfully',
        timestamp: new Date().toISOString()
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Invalidate session failed:', error);
      
      const response: ApiResponse = {
        success: false,
        error: error.message || 'Session invalidation failed',
        timestamp: new Date().toISOString()
      };

      res.status(500).json(response);
    }
  }

  /**
   * Set authentication cookies
   * @param res - Express response object
   * @param tokens - Access and refresh tokens
   */
  private setAuthCookies(res: Response, tokens: { accessToken: string; refreshToken: string }): void {
    const isProduction = process.env.NODE_ENV === 'production';

    // Set access token cookie (shorter expiry)
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/'
    });

    // Set refresh token cookie (longer expiry)
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });
  }

  /**
   * Clear authentication cookies
   * @param res - Express response object
   */
  private clearAuthCookies(res: Response): void {
    res.clearCookie('accessToken', { path: '/' });
    res.clearCookie('refreshToken', { path: '/' });
  }
}

export const authController = new AuthController();

// Validation rules for authentication endpoints
export const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters')
];

export const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

export const updateProfileValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('avatar_url')
    .optional()
    .isURL()
    .withMessage('Avatar URL must be a valid URL'),
  body('preferences')
    .optional()
    .isObject()
    .withMessage('Preferences must be an object')
];

export const changePasswordValidation = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];
 