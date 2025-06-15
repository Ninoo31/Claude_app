import { Router } from 'express';
import { conversationController, createConversationValidation, updateConversationValidation, sendMessageValidation } from '@/controllers/conversationController';
import { authMiddleware } from '@/middleware/authMiddleware';

const router = Router();

/**
 * @swagger
 * /api/v1/conversations:
 *   get:
 *     summary: Get user's conversations
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: project_id
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, archived, pinned]
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *     responses:
 *       200:
 *         description: Conversations retrieved successfully
 */
router.get('/', authMiddleware, conversationController.getConversations);

/**
 * @swagger
 * /api/v1/conversations:
 *   post:
 *     summary: Create a new conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *             properties:
 *               project_id:
 *                 type: string
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               importance_level:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 10
 *               tags:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Conversation created successfully
 */
router.post('/', authMiddleware, createConversationValidation, conversationController.createConversation);

/**
 * @swagger
 * /api/v1/conversations/search:
 *   get:
 *     summary: Search conversations and messages
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: project_id
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: Search results retrieved successfully
 */
router.get('/search', authMiddleware, conversationController.searchConversations);

/**
 * @swagger
 * /api/v1/conversations/{conversationId}:
 *   get:
 *     summary: Get conversation by ID
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: conversationId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: includeMessages
 *         schema:
 *           type: boolean
 *           default: true
 *     responses:
 *       200:
 *         description: Conversation retrieved successfully
 *       404:
 *         description: Conversation not found
 */
router.get('/:conversationId', authMiddleware, conversationController.getConversationById);

/**
 * @swagger
 * /api/v1/conversations/{conversationId}:
 *   put:
 *     summary: Update conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: conversationId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               importance_level:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 10
 *               status:
 *                 type: string
 *                 enum: [active, archived, pinned]
 *               tags:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Conversation updated successfully
 */
router.put('/:conversationId', authMiddleware, updateConversationValidation, conversationController.updateConversation);

/**
 * @swagger
 * /api/v1/conversations/{conversationId}:
 *   delete:
 *     summary: Delete conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: conversationId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Conversation deleted successfully
 */
router.delete('/:conversationId', authMiddleware, conversationController.deleteConversation);

/**
 * @swagger
 * /api/v1/conversations/{conversationId}/messages:
 *   post:
 *     summary: Send message to conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: conversationId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - content
 *             properties:
 *               content:
 *                 type: string
 *               message_type:
 *                 type: string
 *                 enum: [text, command]
 *                 default: text
 *     responses:
 *       200:
 *         description: Message sent successfully
 */
router.post('/:conversationId/messages', authMiddleware, sendMessageValidation, conversationController.sendMessage);

/**
 * @swagger
 * /api/v1/conversations/{conversationId}/analytics:
 *   get:
 *     summary: Get conversation analytics
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: conversationId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Analytics retrieved successfully
 */
router.get('/:conversationId/analytics', authMiddleware, conversationController.getConversationAnalytics);

export default router;

