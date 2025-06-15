import { Router } from 'express';
import { exportController } from '@/controllers/exportController';
import { authMiddleware } from '@/middleware/authMiddleware';

const router = Router();

/**
 * @swagger
 * /api/v1/export/jobs:
 *   get:
 *     summary: Get user's export/import jobs
 *     tags: [Export]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [export, import]
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, processing, completed, failed]
 *     responses:
 *       200:
 *         description: Export jobs retrieved successfully
 */
router.get('/jobs', authMiddleware, exportController.getExportJobs);

/**
 * @swagger
 * /api/v1/export/create:
 *   post:
 *     summary: Create export job
 *     tags: [Export]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - format
 *             properties:
 *               format:
 *                 type: string
 *                 enum: [json, sql, csv]
 *               database_id:
 *                 type: string
 *               include_projects:
 *                 type: array
 *                 items:
 *                   type: string
 *               date_from:
 *                 type: string
 *                 format: date
 *               date_to:
 *                 type: string
 *                 format: date
 *     responses:
 *       201:
 *         description: Export job created successfully
 */
router.post('/create', authMiddleware, exportController.createExportJob);

/**
 * @swagger
 * /api/v1/export/download/{jobId}:
 *   get:
 *     summary: Download exported data
 *     tags: [Export]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: jobId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: File download
 *         content:
 *           application/octet-stream:
 *             schema:
 *               type: string
 *               format: binary
 */
router.get('/download/:jobId', authMiddleware, exportController.downloadExport);

/**
 * @swagger
 * /api/v1/export/import:
 *   post:
 *     summary: Import data from file
 *     tags: [Export]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               database_id:
 *                 type: string
 *               merge_strategy:
 *                 type: string
 *                 enum: [replace, merge, skip_existing]
 *     responses:
 *       201:
 *         description: Import job created successfully
 */
router.post('/import', authMiddleware, exportController.importData);

export default router;