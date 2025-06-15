import { pgTable, uuid, varchar, text, boolean, timestamp, integer, jsonb, index, decimal, serial } from 'drizzle-orm/pg-core';

/**
 * Tenant database schema - Contains all user data
 * Each user gets their own database instance with this schema
 */

// Projects - Top-level containers for conversations
export const projects = pgTable('projects', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  status: varchar('status', { length: 50 }).default('active'), // 'active', 'archived', 'completed', 'paused'
  priority: varchar('priority', { length: 50 }).default('medium'), // 'low', 'medium', 'high', 'critical'
  color: varchar('color', { length: 7 }).default('#3B82F6'), // Hex color for UI
  icon: varchar('icon', { length: 50 }), // Icon identifier
  tags: jsonb('tags').default([]), // Array of string tags
  settings: jsonb('settings').default({}), // Project-specific settings
  collaborators: jsonb('collaborators').default([]), // Array of collaborator info
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  archived_at: timestamp('archived_at'),
  completed_at: timestamp('completed_at'),
  deadline: timestamp('deadline'),
  metadata: jsonb('metadata').default({}), // Additional project data
}, (table) => ({
  statusIdx: index('projects_status_idx').on(table.status),
  priorityIdx: index('projects_priority_idx').on(table.priority),
  createdIdx: index('projects_created_idx').on(table.created_at),
  updatedIdx: index('projects_updated_idx').on(table.updated_at),
  deadlineIdx: index('projects_deadline_idx').on(table.deadline),
  tagsIdx: index('projects_tags_idx').using('gin', table.tags),
}));

// Conversations - Individual chat sessions within projects
export const conversations = pgTable('conversations', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  title: varchar('title', { length: 500 }).notNull(),
  description: text('description'),
  summary: text('summary'), // AI-generated summary
  key_topics: text('key_topics'), // Comma-separated topics
  importance_level: integer('importance_level').default(3), // 1-10 scale
  status: varchar('status', { length: 50 }).default('active'), // 'active', 'archived', 'pinned', 'template'
  conversation_type: varchar('conversation_type', { length: 50 }).default('chat'), // 'chat', 'brainstorm', 'analysis', 'support'
  message_count: integer('message_count').default(0),
  total_tokens: integer('total_tokens').default(0),
  estimated_cost: decimal('estimated_cost', { precision: 10, scale: 4 }).default('0'), // Cost tracking
  tags: jsonb('tags').default([]), // Array of tags
  participants: jsonb('participants').default([]), // For multi-user conversations
  settings: jsonb('settings').default({}), // Conversation-specific settings
  metadata: jsonb('metadata').default({}), // Additional conversation data
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  last_message_at: timestamp('last_message_at'),
  archived_at: timestamp('archived_at'),
  template_data: jsonb('template_data'), // For conversation templates
}, (table) => ({
  projectIdIdx: index('conversations_project_id_idx').on(table.project_id),
  statusIdx: index('conversations_status_idx').on(table.status),
  typeIdx: index('conversations_type_idx').on(table.conversation_type),
  importanceIdx: index('conversations_importance_idx').on(table.importance_level),
  updatedIdx: index('conversations_updated_idx').on(table.updated_at),
  lastMessageIdx: index('conversations_last_message_idx').on(table.last_message_at),
  tagsIdx: index('conversations_tags_idx').using('gin', table.tags),
  createdIdx: index('conversations_created_idx').on(table.created_at),
}));

// Messages - Individual messages within conversations
export const messages = pgTable('messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  conversation_id: uuid('conversation_id').notNull().references(() => conversations.id, { onDelete: 'cascade' }),
  parent_message_id: uuid('parent_message_id').references(() => messages.id), // For threaded conversations
  role: varchar('role', { length: 20 }).notNull(), // 'user', 'assistant', 'system', 'function'
  content: text('content').notNull(),
  content_type: varchar('content_type', { length: 50 }).default('text'), // 'text', 'markdown', 'code', 'json', 'image'
  tokens_used: integer('tokens_used'),
  model_used: varchar('model_used', { length: 100 }), // Claude model version
  processing_time_ms: integer('processing_time_ms'),
  cost: decimal('cost', { precision: 10, scale: 6 }), // Cost for this message
  status: varchar('status', { length: 50 }).default('completed'), // 'pending', 'processing', 'completed', 'failed'
  error_details: text('error_details'), // Error information if failed
  attachments: jsonb('attachments').default([]), // File attachments
  reactions: jsonb('reactions').default({}), // User reactions/ratings
  metadata: jsonb('metadata').default({}), // Additional message data
  edited_at: timestamp('edited_at'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  deleted_at: timestamp('deleted_at'), // Soft delete
}, (table) => ({
  conversationIdIdx: index('messages_conversation_id_idx').on(table.conversation_id),
  parentIdIdx: index('messages_parent_id_idx').on(table.parent_message_id),
  roleIdx: index('messages_role_idx').on(table.role),
  statusIdx: index('messages_status_idx').on(table.status),
  createdIdx: index('messages_created_idx').on(table.created_at),
  deletedIdx: index('messages_deleted_idx').on(table.deleted_at),
  contentTypeIdx: index('messages_content_type_idx').on(table.content_type),
}));

// Custom tables created by users within projects
export const customTables = pgTable('custom_tables', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  display_name: varchar('display_name', { length: 255 }).notNull(),
  description: text('description'),
  table_type: varchar('table_type', { length: 50 }).default('data'), // 'data', 'lookup', 'config'
  schema_definition: jsonb('schema_definition').notNull(), // Table structure
  data_validation: jsonb('data_validation').default({}), // Validation rules
  permissions: jsonb('permissions').default({}), // Access control
  is_active: boolean('is_active').default(true),
  row_count: integer('row_count').default(0), // Cached row count
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  last_accessed_at: timestamp('last_accessed_at'),
}, (table) => ({
  projectIdIdx: index('custom_tables_project_id_idx').on(table.project_id),
  nameIdx: index('custom_tables_name_idx').on(table.name),
  typeIdx: index('custom_tables_type_idx').on(table.table_type),
  activeIdx: index('custom_tables_active_idx').on(table.is_active),
}));

// Conversation analytics and insights
export const conversationAnalytics = pgTable('conversation_analytics', {
  id: uuid('id').primaryKey().defaultRandom(),
  conversation_id: uuid('conversation_id').notNull().references(() => conversations.id, { onDelete: 'cascade' }),
  date: timestamp('date').defaultNow().notNull(),
  period_type: varchar('period_type', { length: 20 }).default('daily'), // 'hourly', 'daily', 'weekly', 'monthly'
  message_count: integer('message_count').default(0),
  user_messages: integer('user_messages').default(0),
  assistant_messages: integer('assistant_messages').default(0),
  tokens_used: integer('tokens_used').default(0),
  total_cost: decimal('total_cost', { precision: 10, scale: 6 }).default('0'),
  average_response_time: integer('average_response_time'), // Milliseconds
  topics_discussed: jsonb('topics_discussed').default([]), // Array of topics
  sentiment_score: varchar('sentiment_score', { length: 20 }), // 'positive', 'negative', 'neutral'
  engagement_score: integer('engagement_score'), // 1-100 engagement rating
  session_count: integer('session_count').default(0), // Number of chat sessions
  average_session_length: integer('average_session_length'), // Minutes
  created_at: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  conversationIdIdx: index('analytics_conversation_id_idx').on(table.conversation_id),
  dateIdx: index('analytics_date_idx').on(table.date),
  periodIdx: index('analytics_period_idx').on(table.period_type, table.date),
}));

// Saved prompts and templates
export const promptTemplates = pgTable('prompt_templates', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  category: varchar('category', { length: 100 }), // 'coding', 'writing', 'analysis', etc.
  prompt_text: text('prompt_text').notNull(),
  variables: jsonb('variables').default([]), // Template variables
  usage_count: integer('usage_count').default(0),
  is_public: boolean('is_public').default(false), // Shareable templates
  tags: jsonb('tags').default([]),
  metadata: jsonb('metadata').default({}),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  last_used_at: timestamp('last_used_at'),
}, (table) => ({
  projectIdIdx: index('prompt_templates_project_id_idx').on(table.project_id),
  categoryIdx: index('prompt_templates_category_idx').on(table.category),
  publicIdx: index('prompt_templates_public_idx').on(table.is_public),
  usageIdx: index('prompt_templates_usage_idx').on(table.usage_count),
  tagsIdx: index('prompt_templates_tags_idx').using('gin', table.tags),
}));

// Knowledge base entries
export const knowledgeBase = pgTable('knowledge_base', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  title: varchar('title', { length: 500 }).notNull(),
  content: text('content').notNull(),
  content_type: varchar('content_type', { length: 50 }).default('markdown'), // 'markdown', 'text', 'json'
  category: varchar('category', { length: 100 }),
  tags: jsonb('tags').default([]),
  is_indexed: boolean('is_indexed').default(false), // For search indexing
  embedding: jsonb('embedding'), // Vector embedding for semantic search
  source_url: text('source_url'), // Original source if imported
  version: integer('version').default(1),
  is_active: boolean('is_active').default(true),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  indexed_at: timestamp('indexed_at'),
}, (table) => ({
  projectIdIdx: index('knowledge_base_project_id_idx').on(table.project_id),
  categoryIdx: index('knowledge_base_category_idx').on(table.category),
  indexedIdx: index('knowledge_base_indexed_idx').on(table.is_indexed),
  activeIdx: index('knowledge_base_active_idx').on(table.is_active),
  tagsIdx: index('knowledge_base_tags_idx').using('gin', table.tags),
}));

// File attachments and uploads
export const fileAttachments = pgTable('file_attachments', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  message_id: uuid('message_id').references(() => messages.id, { onDelete: 'cascade' }),
  filename: varchar('filename', { length: 255 }).notNull(),
  original_filename: varchar('original_filename', { length: 255 }).notNull(),
  file_type: varchar('file_type', { length: 100 }).notNull(), // MIME type
  file_size: integer('file_size').notNull(), // Size in bytes
  file_path: text('file_path').notNull(), // Storage path
  storage_provider: varchar('storage_provider', { length: 50 }).default('local'), // 'local', 's3', 'gcs'
  is_processed: boolean('is_processed').default(false), // For file processing
  processing_status: varchar('processing_status', { length: 50 }).default('pending'), // 'pending', 'processing', 'completed', 'failed'
  metadata: jsonb('metadata').default({}), // File metadata
  created_at: timestamp('created_at').defaultNow().notNull(),
  processed_at: timestamp('processed_at'),
}, (table) => ({
  projectIdIdx: index('file_attachments_project_id_idx').on(table.project_id),
  messageIdIdx: index('file_attachments_message_id_idx').on(table.message_id),
  typeIdx: index('file_attachments_type_idx').on(table.file_type),
  processedIdx: index('file_attachments_processed_idx').on(table.is_processed),
  statusIdx: index('file_attachments_status_idx').on(table.processing_status),
}));

// Webhooks and integrations
export const webhooks = pgTable('webhooks', {
  id: uuid('id').primaryKey().defaultRandom(),
  project_id: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  url: text('url').notNull(),
  secret: varchar('secret', { length: 255 }), // Webhook secret for verification
  events: jsonb('events').default([]), // Array of event types to trigger on
  is_active: boolean('is_active').default(true),
  retry_count: integer('retry_count').default(3),
  timeout_seconds: integer('timeout_seconds').default(30),
  last_triggered_at: timestamp('last_triggered_at'),
  last_status: varchar('last_status', { length: 50 }), // 'success', 'failed', 'timeout'
  failure_count: integer('failure_count').default(0),
  metadata: jsonb('metadata').default({}),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
  projectIdIdx: index('webhooks_project_id_idx').on(table.project_id),
  activeIdx: index('webhooks_active_idx').on(table.is_active),
  statusIdx: index('webhooks_status_idx').on(table.last_status),
  eventsIdx: index('webhooks_events_idx').using('gin', table.events),
}));