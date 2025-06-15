import { Request, Response } from 'express';
import { body, query, param, validationResult } from 'express-validator';
import { auditService } from '@/services/auditService';
import { logger } from '@/utils/logger';
import { asyncHandler, createError } from '@/middleware/errorHandler';
import type { ApiResponse, ExportOptions, ImportOptions, ExportJobStatus } from '@/types/database.types';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs/promises';
import { config } from '@/config/environment';

/**
 * Export Controller
 * Handles data export and import operations
 */
class ExportController {
  private exportJobs: Map<string, ExportJobStatus> = new Map();
  private readonly STORAGE_PATH = config.storage.path;

  constructor() {
    this.ensureStorageDirectory();
  }

  /**
   * Ensure storage directory exists
   */
  private async ensureStorageDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.STORAGE_PATH, { recursive: true });
      await fs.mkdir(path.join(this.STORAGE_PATH, 'exports'), { recursive: true });
      await fs.mkdir(path.join(this.STORAGE_PATH, 'imports'), { recursive: true });
    } catch (error) {
      logger.error('Failed to create storage directories:', error);
    }
  }

  /**
   * Get user's export/import jobs
   * GET /api/v1/export/jobs
   */
  getExportJobs = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.user!.id;
    const type = req.query.type as 'export' | 'import';
    const status = req.query.status as string;
    const limit = parseInt(req.query.limit as string) || 20;
    const offset = parseInt(req.query.offset as string) || 0;

    try {
      // Filter jobs for current user
      let userJobs = Array.from(this.exportJobs.values())
        .filter(job => job.metadata?.user_id === userId);

      // Apply filters
      if (type) {
        userJobs = userJobs.filter(job => job.metadata?.job_type === type);
      }

      if (status) {
        userJobs = userJobs.filter(job => job.status === status);
      }

      // Sort by creation date (newest first)
      userJobs.sort((a, b) => 
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );

      // Apply pagination
      const total = userJobs.length;
      const paginatedJobs = userJobs.slice(offset, offset + limit);

      const response: ApiResponse = {
        success: true,
        data: {
          jobs: paginatedJobs,
          pagination: {
            total,
            limit,
            offset,
            has_more: offset + limit < total,
          },
        },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Failed to get export jobs:', error);
      throw createError.database('Failed to retrieve export jobs');
    }
  });

  /**
   * Create export job
   * POST /api/v1/export/create
   */
  createExportJob = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    const exportOptions: ExportOptions = {
      format: req.body.format,
      include_projects: req.body.include_projects,
      include_conversations: req.body.include_conversations,
      date_from: req.body.date_from,
      date_to: req.body.date_to,
      include_deleted: req.body.include_deleted || false,
      compress: req.body.compress || false,
      encryption: req.body.encryption || { enabled: false },
    };

    try {
      // Create export job
      const jobId = this.generateJobId();
      const job: ExportJobStatus = {
        id: jobId,
        status: 'pending',
        progress: 0,
        created_at: new Date().toISOString(),
        metadata: {
          user_id: userId,
          job_type: 'export',
          export_options: exportOptions,
        },
      };

      this.exportJobs.set(jobId, job);

      // Start export process asynchronously
      this.processExportJob(jobId, userId, exportOptions).catch(error => {
        logger.error(`Export job ${jobId} failed:`, error);
        job.status = 'failed';
        job.error_message = error.message;
      });

      // Log audit event
      await auditService.logExport({
        user_id: userId,
        action: 'export_create',
        job_id: jobId,
        format: exportOptions.format,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        data: { job },
        message: 'Export job created successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(201).json(response);
    } catch (error: any) {
      logger.error('Failed to create export job:', error);
      throw createError.database('Failed to create export job');
    }
  });

  /**
   * Download exported data
   * GET /api/v1/export/download/:jobId
   */
  downloadExport = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const jobId = req.params.jobId;

    try {
      const job = this.exportJobs.get(jobId);
      
      if (!job) {
        throw createError.notFound('Export job');
      }

      if (job.metadata?.user_id !== userId) {
        throw createError.forbidden('Access denied to this export job');
      }

      if (job.status !== 'completed') {
        throw createError.validation('Export job not completed', []);
      }

      if (!job.file_path) {
        throw createError.validation('Export file not available', []);
      }

      const filePath = path.join(this.STORAGE_PATH, job.file_path);
      
      // Check if file exists
      try {
        await fs.access(filePath);
      } catch {
        throw createError.notFound('Export file not found');
      }

      // Get file stats
      const stats = await fs.stat(filePath);
      const filename = path.basename(job.file_path);

      // Log download
      await auditService.logExport({
        user_id: userId,
        action: 'export_download',
        job_id: jobId,
        file_size: stats.size,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      // Set headers for file download
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', stats.size);

      // Stream file to response
      const fileBuffer = await fs.readFile(filePath);
      res.status(200).send(fileBuffer);

    } catch (error: any) {
      logger.error('Failed to download export:', error);
      if (error.statusCode) {
        throw error;
      }
      throw createError.database('Failed to download export file');
    }
  });

  /**
   * Import data from file
   * POST /api/v1/export/import
   */
  importData = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Validation failed', errors.array());
    }

    const userId = req.user!.id;
    
    // Check if file was uploaded
    if (!req.file) {
      throw createError.validation('Import file is required', []);
    }

    const importOptions: ImportOptions = {
      merge_strategy: req.body.merge_strategy || 'merge',
      validate_data: req.body.validate_data !== 'false',
      dry_run: req.body.dry_run === 'true',
      backup_before_import: req.body.backup_before_import !== 'false',
    };

    try {
      // Create import job
      const jobId = this.generateJobId();
      const job: ExportJobStatus = {
        id: jobId,
        status: 'pending',
        progress: 0,
        created_at: new Date().toISOString(),
        metadata: {
          user_id: userId,
          job_type: 'import',
          import_options: importOptions,
          file_info: {
            original_name: req.file.originalname,
            file_size: req.file.size,
            mime_type: req.file.mimetype,
          },
        },
      };

      this.exportJobs.set(jobId, job);

      // Move uploaded file to imports directory
      const importPath = path.join(this.STORAGE_PATH, 'imports', `${jobId}_${req.file.originalname}`);
      await fs.rename(req.file.path, importPath);

      // Start import process asynchronously
      this.processImportJob(jobId, userId, importPath, importOptions).catch(error => {
        logger.error(`Import job ${jobId} failed:`, error);
        job.status = 'failed';
        job.error_message = error.message;
      });

      // Log audit event
      await auditService.logExport({
        user_id: userId,
        action: 'import_create',
        job_id: jobId,
        file_size: req.file.size,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        data: { job },
        message: 'Import job created successfully',
        timestamp: new Date().toISOString(),
      };

      res.status(201).json(response);
    } catch (error: any) {
      logger.error('Failed to create import job:', error);
      throw createError.database('Failed to create import job');
    }
  });

  /**
   * Get export job status
   * GET /api/v1/export/jobs/:jobId
   */
  getJobStatus = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const jobId = req.params.jobId;

    const job = this.exportJobs.get(jobId);
    
    if (!job) {
      throw createError.notFound('Export job');
    }

    if (job.metadata?.user_id !== userId) {
      throw createError.forbidden('Access denied to this export job');
    }

    const response: ApiResponse = {
      success: true,
      data: { job },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Cancel export job
   * POST /api/v1/export/jobs/:jobId/cancel
   */
  cancelJob = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw createError.validation('Invalid parameters', errors.array());
    }

    const userId = req.user!.id;
    const jobId = req.params.jobId;

    const job = this.exportJobs.get(jobId);
    
    if (!job) {
      throw createError.notFound('Export job');
    }

    if (job.metadata?.user_id !== userId) {
      throw createError.forbidden('Access denied to this export job');
    }

    if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
      throw createError.validation('Cannot cancel job in current status', []);
    }

    // Cancel the job
    job.status = 'cancelled';
    job.completed_at = new Date().toISOString();

    // Clean up any temporary files
    if (job.file_path) {
      try {
        await fs.unlink(path.join(this.STORAGE_PATH, job.file_path));
      } catch (error) {
        logger.warn(`Failed to clean up cancelled job file: ${job.file_path}`);
      }
    }

    const response: ApiResponse = {
      success: true,
      data: { job },
      message: 'Export job cancelled successfully',
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  });

  /**
   * Process export job
   * @param jobId - Job ID
   * @param userId - User ID
   * @param options - Export options
   */
  private async processExportJob(jobId: string, userId: string, options: ExportOptions): Promise<void> {
    const job = this.exportJobs.get(jobId)!;
    
    try {
      job.status = 'processing';
      job.started_at = new Date().toISOString();
      job.progress = 10;

      // Simulate export process
      // In real implementation, this would:
      // 1. Query user's data based on options
      // 2. Format data according to specified format
      // 3. Apply compression/encryption if requested
      // 4. Save to file

      await this.simulateProgress(job, 10, 50, 2000); // Simulate data collection

      const exportData = await this.collectUserData(userId, options);
      
      await this.simulateProgress(job, 50, 80, 1000); // Simulate formatting

      const formattedData = await this.formatExportData(exportData, options);
      
      await this.simulateProgress(job, 80, 90, 500); // Simulate file writing

      const filePath = await this.saveExportFile(jobId, formattedData, options);
      
      job.progress = 100;
      job.status = 'completed';
      job.completed_at = new Date().toISOString();
      job.file_path = filePath;
      job.file_size = (await fs.stat(path.join(this.STORAGE_PATH, filePath))).size;

      logger.info(`Export job ${jobId} completed successfully`);

    } catch (error: any) {
      job.status = 'failed';
      job.error_message = error.message;
      job.completed_at = new Date().toISOString();
      throw error;
    }
  }

  /**
   * Process import job
   * @param jobId - Job ID
   * @param userId - User ID
   * @param filePath - Path to import file
   * @param options - Import options
   */
  private async processImportJob(
    jobId: string, 
    userId: string, 
    filePath: string, 
    options: ImportOptions
  ): Promise<void> {
    const job = this.exportJobs.get(jobId)!;
    
    try {
      job.status = 'processing';
      job.started_at = new Date().toISOString();
      job.progress = 10;

      // Read and validate import file
      const fileContent = await fs.readFile(filePath, 'utf8');
      job.progress = 30;

      // Parse import data
      const importData = JSON.parse(fileContent);
      job.progress = 50;

      // Validate data if requested
      if (options.validate_data) {
        await this.validateImportData(importData);
        job.progress = 70;
      }

      // Create backup if requested
      if (options.backup_before_import) {
        await this.createBackupBeforeImport(userId);
        job.progress = 80;
      }

      // Import data (dry run or actual)
      const importResult = await this.importUserData(userId, importData, options);
      job.progress = 100;

      job.status = 'completed';
      job.completed_at = new Date().toISOString();
      job.metadata!.import_result = importResult;

      logger.info(`Import job ${jobId} completed successfully`);

    } catch (error: any) {
      job.status = 'failed';
      job.error_message = error.message;
      job.completed_at = new Date().toISOString();
      throw error;
    } finally {
      // Clean up import file
      try {
        await fs.unlink(filePath);
      } catch (error) {
        logger.warn(`Failed to clean up import file: ${filePath}`);
      }
    }
  }

  /**
   * Simulate progress for demo purposes
   */
  /**
   * Simulate progress for demo purposes
   */
  private async simulateProgress(job: ExportJobStatus, from: number, to: number, duration: number): Promise<void> {
    const steps = 10;
    const stepDuration = duration / steps;
    const progressStep = (to - from) / steps;

    for (let i = 0; i < steps; i++) {
      await new Promise(resolve => setTimeout(resolve, stepDuration));
      job.progress = Math.min(from + (progressStep * (i + 1)), to);
    }
  }

  /**
   * Collect user data for export
   * @param userId - User ID
   * @param options - Export options
   */
  private async collectUserData(userId: string, options: ExportOptions): Promise<any> {
    // This would implement actual data collection from the database
    // For now, return mock data
    const userData = {
      user_info: {
        id: userId,
        export_date: new Date().toISOString(),
        export_format: options.format,
      },
      projects: [
        {
          id: 'proj_1',
          name: 'Sample Project',
          description: 'This is a sample project for export',
          created_at: new Date().toISOString(),
        },
      ],
      conversations: [
        {
          id: 'conv_1',
          title: 'Sample Conversation',
          project_id: 'proj_1',
          messages: [
            {
              id: 'msg_1',
              role: 'user',
              content: 'Hello, this is a sample message',
              created_at: new Date().toISOString(),
            },
            {
              id: 'msg_2',
              role: 'assistant',
              content: 'Hello! This is a sample response',
              created_at: new Date().toISOString(),
            },
          ],
        },
      ],
      export_metadata: {
        total_projects: 1,
        total_conversations: 1,
        total_messages: 2,
      },
    };

    return userData;
  }

  /**
   * Format export data according to specified format
   * @param data - Raw export data
   * @param options - Export options
   */
  private async formatExportData(data: any, options: ExportOptions): Promise<string> {
    switch (options.format) {
      case 'json':
        return JSON.stringify(data, null, 2);
      
      case 'csv':
        return this.convertToCSV(data);
      
      case 'sql':
        return this.convertToSQL(data);
      
      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }
  }

  /**
   * Convert data to CSV format
   * @param data - Export data
   */
  private convertToCSV(data: any): string {
    const lines = [];
    
    // Projects CSV
    lines.push('# Projects');
    lines.push('id,name,description,created_at');
    data.projects.forEach((project: any) => {
      lines.push(`"${project.id}","${project.name}","${project.description || ''}","${project.created_at}"`);
    });
    lines.push('');

    // Conversations CSV
    lines.push('# Conversations');
    lines.push('id,title,project_id,message_count,created_at');
    data.conversations.forEach((conv: any) => {
      lines.push(`"${conv.id}","${conv.title}","${conv.project_id}",${conv.messages.length},"${conv.created_at}"`);
    });
    lines.push('');

    // Messages CSV
    lines.push('# Messages');
    lines.push('id,conversation_id,role,content,created_at');
    data.conversations.forEach((conv: any) => {
      conv.messages.forEach((msg: any) => {
        lines.push(`"${msg.id}","${conv.id}","${msg.role}","${msg.content}","${msg.created_at}"`);
      });
    });

    return lines.join('\n');
  }

  /**
   * Convert data to SQL format
   * @param data - Export data
   */
  private convertToSQL(data: any): string {
    const lines = [];
    
    lines.push('-- Claude Memory Export');
    lines.push(`-- Generated on: ${new Date().toISOString()}`);
    lines.push('-- Format: SQL');
    lines.push('');

    // Projects
    lines.push('-- Projects');
    data.projects.forEach((project: any) => {
      lines.push(`INSERT INTO projects (id, name, description, created_at) VALUES ('${project.id}', '${project.name}', '${project.description || ''}', '${project.created_at}');`);
    });
    lines.push('');

    // Conversations
    lines.push('-- Conversations');
    data.conversations.forEach((conv: any) => {
      lines.push(`INSERT INTO conversations (id, title, project_id, created_at) VALUES ('${conv.id}', '${conv.title}', '${conv.project_id}', '${conv.created_at}');`);
    });
    lines.push('');

    // Messages
    lines.push('-- Messages');
    data.conversations.forEach((conv: any) => {
      conv.messages.forEach((msg: any) => {
        lines.push(`INSERT INTO messages (id, conversation_id, role, content, created_at) VALUES ('${msg.id}', '${conv.id}', '${msg.role}', '${msg.content.replace(/'/g, "''")}', '${msg.created_at}');`);
      });
    });

    return lines.join('\n');
  }

  /**
   * Save export file to storage
   * @param jobId - Job ID
   * @param content - File content
   * @param options - Export options
   */
  private async saveExportFile(jobId: string, content: string, options: ExportOptions): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const extension = options.format === 'json' ? 'json' : 
                     options.format === 'csv' ? 'csv' : 'sql';
    
    let filename = `export_${jobId}_${timestamp}.${extension}`;
    let finalContent = content;

    // Apply compression if requested
    if (options.compress) {
      const zlib = require('zlib');
      const compressed = zlib.gzipSync(Buffer.from(content));
      finalContent = compressed.toString('base64');
      filename += '.gz';
    }

    // Apply encryption if requested
    if (options.encryption?.enabled) {
      const password = options.encryption.password || this.generateRandomPassword();
      finalContent = this.encryptContent(finalContent, password);
      filename += '.enc';
    }

    const filePath = path.join('exports', filename);
    const fullPath = path.join(this.STORAGE_PATH, filePath);

    await fs.writeFile(fullPath, finalContent);
    
    return filePath;
  }

  /**
   * Validate import data
   * @param data - Import data to validate
   */
  private async validateImportData(data: any): Promise<void> {
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid import data format');
    }

    // Basic validation
    const requiredFields = ['user_info', 'projects', 'conversations'];
    for (const field of requiredFields) {
      if (!data[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Validate data structure
    if (!Array.isArray(data.projects)) {
      throw new Error('Projects must be an array');
    }

    if (!Array.isArray(data.conversations)) {
      throw new Error('Conversations must be an array');
    }

    // Additional validation can be added here
    logger.debug('Import data validation passed');
  }

  /**
   * Create backup before import
   * @param userId - User ID
   */
  private async createBackupBeforeImport(userId: string): Promise<void> {
    // This would create a backup of user's current data
    // For now, just log the operation
    logger.info(`Creating backup for user ${userId} before import`);
    
    // Simulate backup creation
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  /**
   * Import user data
   * @param userId - User ID
   * @param data - Import data
   * @param options - Import options
   */
  private async importUserData(userId: string, data: any, options: ImportOptions): Promise<any> {
    const result = {
      dry_run: options.dry_run,
      imported_projects: 0,
      imported_conversations: 0,
      imported_messages: 0,
      skipped_items: 0,
      errors: [] as string[],
    };

    if (options.dry_run) {
      // Simulate dry run
      result.imported_projects = data.projects?.length || 0;
      result.imported_conversations = data.conversations?.length || 0;
      result.imported_messages = data.conversations?.reduce((total: number, conv: any) => 
        total + (conv.messages?.length || 0), 0) || 0;
    } else {
      // Simulate actual import
      // In real implementation, this would:
      // 1. Import projects
      // 2. Import conversations
      // 3. Import messages
      // 4. Handle conflicts based on merge_strategy
      
      result.imported_projects = data.projects?.length || 0;
      result.imported_conversations = data.conversations?.length || 0;
      result.imported_messages = data.conversations?.reduce((total: number, conv: any) => 
        total + (conv.messages?.length || 0), 0) || 0;
    }

    return result;
  }

  /**
   * Encrypt content
   * @param content - Content to encrypt
   * @param password - Encryption password
   */
  private encryptContent(content: string, password: string): string {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher(algorithm, key);
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  }

  /**
   * Generate random password
   */
  private generateRandomPassword(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate unique job ID
   */
  private generateJobId(): string {
    return `job_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Clean up old export files and jobs
   */
  async cleanupOldExports(retentionDays: number = 7): Promise<{
    cleaned_jobs: number;
    cleaned_files: number;
    errors: string[];
  }> {
    const result = {
      cleaned_jobs: 0,
      cleaned_files: 0,
      errors: [] as string[],
    };

    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      // Clean up old jobs
      for (const [jobId, job] of this.exportJobs.entries()) {
        const jobDate = new Date(job.created_at);
        if (jobDate < cutoffDate) {
          // Clean up associated file
          if (job.file_path) {
            try {
              await fs.unlink(path.join(this.STORAGE_PATH, job.file_path));
              result.cleaned_files++;
            } catch (error: any) {
              result.errors.push(`Failed to delete file ${job.file_path}: ${error.message}`);
            }
          }

          this.exportJobs.delete(jobId);
          result.cleaned_jobs++;
        }
      }

      logger.info(`Cleanup completed: ${result.cleaned_jobs} jobs, ${result.cleaned_files} files removed`);
    } catch (error: any) {
      logger.error('Export cleanup failed:', error);
      result.errors.push(error.message);
    }

    return result;
  }

  /**
   * Get export service statistics
   */
  getExportStats(): {
    total_jobs: number;
    active_jobs: number;
    completed_jobs: number;
    failed_jobs: number;
    storage_used: string;
  } {
    let activeJobs = 0;
    let completedJobs = 0;
    let failedJobs = 0;

    for (const job of this.exportJobs.values()) {
      switch (job.status) {
        case 'pending':
        case 'processing':
          activeJobs++;
          break;
        case 'completed':
          completedJobs++;
          break;
        case 'failed':
        case 'cancelled':
          failedJobs++;
          break;
      }
    }

    return {
      total_jobs: this.exportJobs.size,
      active_jobs: activeJobs,
      completed_jobs: completedJobs,
      failed_jobs: failedJobs,
      storage_used: 'unknown', // Would calculate actual storage usage
    };
  }
}

// Create controller instance
export const exportController = new ExportController();

/**
 * Validation Rules
 */

// Create export validation
export const createExportValidation = [
  body('format')
    .isIn(['json', 'csv', 'sql'])
    .withMessage('Format must be json, csv, or sql'),
  body('include_projects')
    .optional()
    .isArray()
    .withMessage('include_projects must be an array of project IDs'),
  body('include_conversations')
    .optional()
    .isArray()
    .withMessage('include_conversations must be an array of conversation IDs'),
  body('date_from')
    .optional()
    .isISO8601()
    .withMessage('date_from must be a valid ISO 8601 date'),
  body('date_to')
    .optional()
    .isISO8601()
    .withMessage('date_to must be a valid ISO 8601 date'),
  body('include_deleted')
    .optional()
    .isBoolean()
    .withMessage('include_deleted must be a boolean'),
  body('compress')
    .optional()
    .isBoolean()
    .withMessage('compress must be a boolean'),
  body('encryption')
    .optional()
    .isObject()
    .withMessage('encryption must be an object'),
];

// Import validation
export const importValidation = [
  body('merge_strategy')
    .optional()
    .isIn(['replace', 'merge', 'skip_existing'])
    .withMessage('merge_strategy must be replace, merge, or skip_existing'),
  body('validate_data')
    .optional()
    .isBoolean()
    .withMessage('validate_data must be a boolean'),
  body('dry_run')
    .optional()
    .isBoolean()
    .withMessage('dry_run must be a boolean'),
  body('backup_before_import')
    .optional()
    .isBoolean()
    .withMessage('backup_before_import must be a boolean'),
];

// Job ID validation
export const jobIdValidation = [
  param('jobId')
    .matches(/^job_\d+_[a-f0-9]{16}$/)
    .withMessage('Invalid job ID format'),
];

// Export jobs query validation
export const exportJobsValidation = [
  query('type')
    .optional()
    .isIn(['export', 'import'])
    .withMessage('type must be export or import'),
  query('status')
    .optional()
    .isIn(['pending', 'processing', 'completed', 'failed', 'cancelled'])
    .withMessage('Invalid status value'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('limit must be between 1 and 100'),
  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('offset must be 0 or greater'),
];