import { pgTable, uuid, varchar, text, boolean, timestamp, jsonb, index, serial, integer } from 'drizzle-orm/pg-core';

/**
 * Master database schema
 * Contains user accounts and database connection information
 * Each user can have their own isolated database
 */

 // Users table - Core user management
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  password_hash: varchar('password_hash', { length: 255 }).notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  avatar_url: text('avatar_url'),
  email_verified: boolean('email_verified').default(false),
  is_active: boolean('is_active').default(true),
  role: varchar('role', { length: 50 }).default('user'), // 'user', 'admin', 'super_admin'
  preferences: jsonb('preferences').default({}),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  last_login_at: timestamp('last_login_at'),
  deleted_at: timestamp('deleted_at'), // Soft delete
}, (table) => ({
  emailIdx: index('users_email_idx').on(table.email),
  activeIdx: index('users_active_idx').on(table.is_active),
  roleIdx: index('users_role_idx').on(table.role),
  createdIdx: index('users_created_idx').on(table.created_at),
}));

// User sessions for JWT management
export const userSessions = pgTable('user_sessions', {
  id: varchar('id', { length: 255 }).primaryKey(),
  user_id: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  refresh_token: varchar('refresh_token', { length: 255 }),
  expires_at: timestamp('expires_at').notNull(),
  created_at: timestamp('created_at').defaultNow().notNull(),
  last_used_at: timestamp('last_used_at').defaultNow().notNull(),
  ip_address: varchar('ip_address', { length: 45 }),
  user_agent: text('user_agent'),
  is_active: boolean('is_active').default(true),
}, (table) => ({
  userIdIdx: index('sessions_user_id_idx').on(table.user_id),
  expiresIdx: index('sessions_expires_idx').on(table.expires_at),
  activeIdx: index('sessions_active_idx').on(table.is_active),
}));

// User database configurations - Each user can have multiple databases
export const userDatabases = pgTable('user_databases', {
  id: uuid('id').primaryKey().defaultRandom(),
  user_id: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(), // Display name
  type: varchar('type', { length: 50 }).notNull(), // 'local', 'cloud_postgres', 'cloud_mysql', 'cloud_mongodb'
  connection_config: jsonb('connection_config').notNull(), // Encrypted connection details
  is_active: boolean('is_active').default(true),
  is_default: boolean('is_default').default(false), // One default per user
  health_status: varchar('health_status', { length: 50 }).default('unknown'), // 'healthy', 'unhealthy', 'unknown'
  last_health_check: timestamp('last_health_check'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
  last_backup_at: timestamp('last_backup_at'),
  backup_config: jsonb('backup_config').default({}),
  metadata: jsonb('metadata').default({}), // Additional configuration
}, (table) => ({
  userIdIdx: index('user_databases_user_id_idx').on(table.user_id),
  typeIdx: index('user_databases_type_idx').on(table.type),
  activeIdx: index('user_databases_active_idx').on(table.is_active),
  defaultIdx: index('user_databases_default_idx').on(table.is_default),
  healthIdx: index('user_databases_health_idx').on(table.health_status),
}));

// Export/Import job management
export const exportJobs = pgTable('export_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  user_id: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  database_id: uuid('database_id').references(() => userDatabases.id, { onDelete: 'cascade' }),
  job_type: varchar('job_type', { length: 50 }).notNull(), // 'export', 'import'
  format: varchar('format', { length: 50 }).notNull(), // 'json', 'sql', 'csv'
  status: varchar('status', { length: 50 }).default('pending'), // 'pending', 'processing', 'completed', 'failed', 'cancelled'
  file_path: text('file_path'),
  file_size: integer('file_size'), // Size in bytes
  progress: integer('progress').default(0), // Progress percentage 0-100
  error_message: text('error_message'),
  started_at: timestamp('started_at'),
  completed_at: timestamp('completed_at'),
  metadata: jsonb('metadata').default({}), // Job configuration and results
  created_at: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  userIdIdx: index('export_jobs_user_id_idx').on(table.user_id),
  databaseIdIdx: index('export_jobs_database_id_idx').on(table.database_id),
  statusIdx: index('export_jobs_status_idx').on(table.status),
  typeIdx: index('export_jobs_type_idx').on(table.job_type),
  createdIdx: index('export_jobs_created_idx').on(table.created_at),
}));

// API keys management for external integrations
export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  user_id: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  key_hash: varchar('key_hash', { length: 255 }).notNull(), // Hashed API key
  key_prefix: varchar('key_prefix', { length: 10 }).notNull(), // First 8 chars for identification
  permissions: jsonb('permissions').default([]), // Array of permissions
  is_active: boolean('is_active').default(true),
  last_used_at: timestamp('last_used_at'),
  expires_at: timestamp('expires_at'),
  created_at: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  userIdIdx: index('api_keys_user_id_idx').on(table.user_id),
  keyHashIdx: index('api_keys_hash_idx').on(table.key_hash),
  prefixIdx: index('api_keys_prefix_idx').on(table.key_prefix),
  activeIdx: index('api_keys_active_idx').on(table.is_active),
}));

// System-wide audit logs
export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  user_id: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
  action: varchar('action', { length: 100 }).notNull(), // 'create', 'update', 'delete', 'login', etc.
  resource_type: varchar('resource_type', { length: 50 }).notNull(), // 'user', 'database', 'project', etc.
  resource_id: varchar('resource_id', { length: 255 }), // ID of the affected resource
  details: jsonb('details').default({}), // Additional context
  ip_address: varchar('ip_address', { length: 45 }),
  user_agent: text('user_agent'),
  created_at: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  userIdIdx: index('audit_logs_user_id_idx').on(table.user_id),
  actionIdx: index('audit_logs_action_idx').on(table.action),
  resourceIdx: index('audit_logs_resource_idx').on(table.resource_type, table.resource_id),
  createdIdx: index('audit_logs_created_idx').on(table.created_at),
}));

// System configurations and feature flags
export const systemConfig = pgTable('system_config', {
  id: serial('id').primaryKey(),
  config_key: varchar('config_key', { length: 255 }).notNull().unique(),
  config_value: jsonb('config_value').notNull(),
  description: text('description'),
  is_active: boolean('is_active').default(true),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
  keyIdx: index('system_config_key_idx').on(table.config_key),
  activeIdx: index('system_config_active_idx').on(table.is_active),
}));