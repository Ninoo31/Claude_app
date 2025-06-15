import { Router } from 'express';
import { databaseController, createDatabaseValidation, updateDatabaseValidation } from '@/controllers/databaseController';
import { authMiddleware } from '@/middleware/authMiddleware';

const router = Router();

/**
 * @swagger
 * /api/v1/database:
 *   get:
 *     summary: Get user's database configurations
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Database configurations retrieved successfully
 */
router.get('/', authMiddleware, databaseController.getDatabases);

/**
 * @swagger
 * /api/v1/database:
 *   post:
 *     summary: Create a new database configuration
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - type
 *               - connection
 *             properties:
 *               name:
 *                 type: string
 *               type:
 *                 type: string
 *                 enum: [local, cloud_postgres, cloud_mysql, cloud_mongodb]
 *               connection:
 *                 type: object
 *                 properties:
 *                   host:
 *                     type: string
 *                   port:
 *                     type: integer
 *                   database:
 *                     type: string
 *                   username:
 *                     type: string
 *                   password:
 *                     type: string
 *                   ssl:
 *                     type: boolean
 *     responses:
 *       201:
 *         description: Database configuration created successfully
 */
router.post('/', authMiddleware, createDatabaseValidation, databaseController.createDatabase);

/**
 * @swagger
 * /api/v1/database/test:
 *   post:
 *     summary: Test database connection
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - type
 *               - connection
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [local, cloud_postgres, cloud_mysql, cloud_mongodb]
 *               connection:
 *                 type: object
 *     responses:
 *       200:
 *         description: Connection test result
 */
router.post('/test', authMiddleware, databaseController.testConnection);

/**
 * @swagger
 * /api/v1/database/{databaseId}:
 *   put:
 *     summary: Update database configuration
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: databaseId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Database configuration updated successfully
 */
router.put('/:databaseId', authMiddleware, updateDatabaseValidation, databaseController.updateDatabase);

/**
 * @swagger
 * /api/v1/database/{databaseId}:
 *   delete:
 *     summary: Delete database configuration
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: databaseId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Database configuration deleted successfully
 */
router.delete('/:databaseId', authMiddleware, databaseController.deleteDatabase);

/**
 * @swagger
 * /api/v1/database/{databaseId}/set-default:
 *   post:
 *     summary: Set database as default
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: databaseId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Default database set successfully
 */
router.post('/:databaseId/set-default', authMiddleware, databaseController.setDefaultDatabase);

/**
 * @swagger
 * /api/v1/database/stats:
 *   get:
 *     summary: Get database statistics
 *     tags: [Database]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Database statistics retrieved successfully
 */
router.get('/stats', authMiddleware, databaseController.getDatabaseStats);

export default router;
