/**
 * Controllers Index
 * Central export point for all API controllers
 */

// Authentication & User Management
export { authController } from './authController';
export { 
  registerValidation,
  loginValidation,
  updateProfileValidation,
  changePasswordValidation
} from './authController';

// Project Management
export { projectController } from './projectController';
export {
  createProjectValidation,
  updateProjectValidation,
  projectIdValidation,
  getProjectsValidation,
  collaboratorValidation,
  bulkProjectOperationsValidation,
  createFromTemplateValidation
} from './projectController';

// Conversation Management
export { conversationController } from './conversationController';
export {
  createConversationValidation,
  updateConversationValidation,
  sendMessageValidation,
  getConversationsValidation,
  searchConversationsValidation,
  conversationIdValidation,
  bulkOperationsValidation,
  createFromTemplateValidation as createConversationFromTemplateValidation
} from './conversationController';

// Database Configuration
export { databaseController } from './databaseController';
export {
  createDatabaseValidation,
  updateDatabaseValidation,
  testConnectionValidation,
  databaseIdValidation,
  backupValidation
} from './databaseController';

// Export & Import
export { exportController } from './exportController';
export {
  createExportValidation,
  importValidation,
  jobIdValidation,
  exportJobsValidation
} from './exportController';

// Health & Monitoring
export { healthController } from './healthController';

// Type exports for external use
export type {
  ApiResponse,
  PaginatedResponse,
  ProjectFilters,
  ConversationFilters,
  DatabaseConfig,
  ExportOptions,
  ImportOptions
} from '@/types/database.types';

/**
 * Controller registry for dynamic route binding
 */
export const controllerRegistry = {
  auth: authController,
  project: projectController,
  conversation: conversationController,
  database: databaseController,
  export: exportController,
  health: healthController,
} as const;

/**
 * Validation registry for middleware binding
 */
export const validationRegistry = {
  auth: {
    register: registerValidation,
    login: loginValidation,
    updateProfile: updateProfileValidation,
    changePassword: changePasswordValidation,
  },
  project: {
    create: createProjectValidation,
    update: updateProjectValidation,
    getId: projectIdValidation,
    getList: getProjectsValidation,
    collaborator: collaboratorValidation,
    bulk: bulkProjectOperationsValidation,
    fromTemplate: createFromTemplateValidation,
  },
  conversation: {
    create: createConversationValidation,
    update: updateConversationValidation,
    sendMessage: sendMessageValidation,
    getList: getConversationsValidation,
    search: searchConversationsValidation,
    getId: conversationIdValidation,
    bulk: bulkOperationsValidation,
    fromTemplate: createConversationFromTemplateValidation,
  },
  database: {
    create: createDatabaseValidation,
    update: updateDatabaseValidation,
    test: testConnectionValidation,
    getId: databaseIdValidation,
    backup: backupValidation,
  },
  export: {
    create: createExportValidation,
    import: importValidation,
    jobId: jobIdValidation,
    jobs: exportJobsValidation,
  },
} as const;

/**
 * Get controller by name
 */
export function getController(name: keyof typeof controllerRegistry) {
  return controllerRegistry[name];
}

/**
 * Get validation rules by controller and action
 */
export function getValidation(
  controller: keyof typeof validationRegistry,
  action: string
) {
  const controllerValidations = validationRegistry[controller];
  return (controllerValidations as any)[action];
}

/**
 * List all available controllers
 */
export function listControllers(): string[] {
  return Object.keys(controllerRegistry);
}

/**
 * List all available validations for a controller
 */
export function listValidations(controller: keyof typeof validationRegistry): string[] {
  return Object.keys(validationRegistry[controller]);
}