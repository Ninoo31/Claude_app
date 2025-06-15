/**
 * Database Schemas Index
 * Central export point for all database schemas and types
 */

// Master Database Schema (User management and configurations)
export * as masterSchema from './master.schema';
export {
  users,
  userSessions,
  userDatabases,
  exportJobs,
  apiKeys,
  auditLogs,
  systemConfig
} from './master.schema';

// Tenant Database Schema (User data and conversations)
export * as tenantSchema from './tenant.schema';
export {
  projects,
  conversations,
  messages,
  customTables,
  conversationAnalytics,
  promptTemplates,
  knowledgeBase,
  fileAttachments,
  webhooks
} from './tenant.schema';

// Schema type definitions for external use
export type {
  // Master schema types
  User,
  NewUser,
  UserSession,
  NewUserSession,
  UserDatabase,
  NewUserDatabase,
  ExportJob,
  NewExportJob,
  ApiKey,
  NewApiKey,
  AuditLog,
  NewAuditLog,
} from '@/types/database.types';

export type {
  // Tenant schema types
  Project,
  NewProject,
  Conversation,
  NewConversation,
  Message,
  NewMessage,
  CustomTable,
  NewCustomTable,
  ConversationAnalytics,
  NewConversationAnalytics,
  PromptTemplate,
  NewPromptTemplate,
  KnowledgeBase,
  NewKnowledgeBase,
  FileAttachment,
  NewFileAttachment,
  Webhook,
  NewWebhook,
} from '@/types/database.types';

/**
 * Schema registry for dynamic access
 */
export const schemaRegistry = {
  master: {
    users,
    userSessions,
    userDatabases,
    exportJobs,
    apiKeys,
    auditLogs,
    systemConfig,
  },
  tenant: {
    projects,
    conversations,
    messages,
    customTables,
    conversationAnalytics,
    promptTemplates,
    knowledgeBase,
    fileAttachments,
    webhooks,
  },
} as const;

/**
 * Get all tables for a specific schema
 */
export function getMasterTables() {
  return schemaRegistry.master;
}

export function getTenantTables() {
  return schemaRegistry.tenant;
}

/**
 * Get table by name from master schema
 */
export function getMasterTable(tableName: keyof typeof schemaRegistry.master) {
  return schemaRegistry.master[tableName];
}

/**
 * Get table by name from tenant schema
 */
export function getTenantTable(tableName: keyof typeof schemaRegistry.tenant) {
  return schemaRegistry.tenant[tableName];
}

/**
 * List all master table names
 */
export function listMasterTables(): string[] {
  return Object.keys(schemaRegistry.master);
}

/**
 * List all tenant table names
 */
export function listTenantTables(): string[] {
  return Object.keys(schemaRegistry.tenant);
}

/**
 * Schema validation utilities
 */
export const schemaUtils = {
  /**
   * Validate if a table exists in master schema
   */
  isMasterTable: (tableName: string): tableName is keyof typeof schemaRegistry.master => {
    return tableName in schemaRegistry.master;
  },

  /**
   * Validate if a table exists in tenant schema
   */
  isTenantTable: (tableName: string): tableName is keyof typeof schemaRegistry.tenant => {
    return tableName in schemaRegistry.tenant;
  },

  /**
   * Get schema type (master or tenant) for a table
   */
  getSchemaType: (tableName: string): 'master' | 'tenant' | null => {
    if (schemaUtils.isMasterTable(tableName)) return 'master';
    if (schemaUtils.isTenantTable(tableName)) return 'tenant';
    return null;
  },

  /**
   * Get all available table names
   */
  getAllTables: () => ({
    master: listMasterTables(),
    tenant: listTenantTables(),
  }),
};

/**
 * Schema configuration for migrations
 */
export const migrationConfig = {
  master: {
    schema: 'public',
    tables: listMasterTables(),
    dependencies: [
      // Define table dependencies for migration order
      'users',
      'userSessions',
      'userDatabases',
      'apiKeys',
      'auditLogs',
      'exportJobs',
      'systemConfig',
    ],
  },
  tenant: {
    schema: 'public', // or dynamic schema name
    tables: listTenantTables(),
    dependencies: [
      // Define table dependencies for migration order
      'projects',
      'conversations',
      'messages',
      'customTables',
      'promptTemplates',
      'knowledgeBase',
      'fileAttachments',
      'webhooks',
      'conversationAnalytics',
    ],
  },
};

/**
 * Database relationship mappings
 */
export const relationships = {
  master: {
    // User -> UserSessions (one-to-many)
    'users.id': ['userSessions.user_id'],
    // User -> UserDatabases (one-to-many)
    'users.id': ['userDatabases.user_id'],
    // User -> ApiKeys (one-to-many)
    'users.id': ['apiKeys.user_id'],
    // User -> AuditLogs (one-to-many)
    'users.id': ['auditLogs.user_id'],
    // User -> ExportJobs (one-to-many)
    'users.id': ['exportJobs.user_id'],
    // UserDatabase -> ExportJobs (one-to-many)
    'userDatabases.id': ['exportJobs.database_id'],
  },
  tenant: {
    // Project -> Conversations (one-to-many)
    'projects.id': ['conversations.project_id'],
    // Project -> CustomTables (one-to-many)
    'projects.id': ['customTables.project_id'],
    // Project -> PromptTemplates (one-to-many)
    'projects.id': ['promptTemplates.project_id'],
    // Project -> KnowledgeBase (one-to-many)
    'projects.id': ['knowledgeBase.project_id'],
    // Project -> FileAttachments (one-to-many)
    'projects.id': ['fileAttachments.project_id'],
    // Project -> Webhooks (one-to-many)
    'projects.id': ['webhooks.project_id'],
    
    // Conversation -> Messages (one-to-many)
    'conversations.id': ['messages.conversation_id'],
    // Conversation -> ConversationAnalytics (one-to-many)
    'conversations.id': ['conversationAnalytics.conversation_id'],
    // Conversation -> FileAttachments (one-to-many)
    'conversations.id': ['fileAttachments.message_id'],
    
    // Message -> Message (self-referencing, parent-child)
    'messages.id': ['messages.parent_message_id'],
  },
};

/**
 * Export schema metadata for tooling
 */
export const schemaMetadata = {
  version: '1.0.0',
  generated: new Date().toISOString(),
  tables: {
    master: {
      count: listMasterTables().length,
      names: listMasterTables(),
    },
    tenant: {
      count: listTenantTables().length,
      names: listTenantTables(),
    },
  },
  relationships: {
    master: Object.keys(relationships.master).length,
    tenant: Object.keys(relationships.tenant).length,
  },
};