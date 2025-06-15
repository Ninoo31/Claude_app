-- Migration: Initial Master Database Schema
-- Created: 2024-01-01
-- Description: Creates master database tables for user management and system configuration

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ===========================================
-- USERS TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'super_admin')),
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP,
    deleted_at TIMESTAMP,
    
    -- Constraints
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT users_name_length CHECK (char_length(name) >= 2 AND char_length(name) <= 100)
);

-- Users indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_verified ON users(email, email_verified);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;

-- Users full-text search
CREATE INDEX idx_users_search ON users USING gin(to_tsvector('english', name || ' ' || email));

-- ===========================================
-- USER SESSIONS TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP DEFAULT NOW(),
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Constraints
    CONSTRAINT user_sessions_expires_future CHECK (expires_at > created_at)
);

-- Sessions indexes
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_user_sessions_active ON user_sessions(user_id, expires_at) WHERE is_active = TRUE AND expires_at > NOW();
CREATE INDEX idx_user_sessions_cleanup ON user_sessions(expires_at) WHERE expires_at <= NOW();

-- ===========================================
-- USER DATABASES TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS user_databases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('local', 'cloud_postgres', 'cloud_mysql', 'cloud_mongodb')),
    connection_config JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    health_status VARCHAR(50) DEFAULT 'unknown' CHECK (health_status IN ('healthy', 'unhealthy', 'unknown')),
    last_health_check TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_backup_at TIMESTAMP,
    backup_config JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT user_databases_name_length CHECK (char_length(name) >= 1 AND char_length(name) <= 255)
);

-- User databases indexes
CREATE INDEX idx_user_databases_user_id ON user_databases(user_id);
CREATE INDEX idx_user_databases_type ON user_databases(type);
CREATE INDEX idx_user_databases_active ON user_databases(user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_user_databases_default ON user_databases(user_id, is_default) WHERE is_default = TRUE;
CREATE INDEX idx_user_databases_health ON user_databases(health_status, last_health_check);
CREATE INDEX idx_user_databases_backup ON user_databases(last_backup_at) WHERE last_backup_at IS NOT NULL;

-- Unique constraint: one default database per user
CREATE UNIQUE INDEX idx_user_databases_one_default ON user_databases(user_id) WHERE is_default = TRUE;

-- ===========================================
-- EXPORT JOBS TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS export_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    database_id UUID REFERENCES user_databases(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL CHECK (job_type IN ('export', 'import')),
    format VARCHAR(50) NOT NULL CHECK (format IN ('json', 'sql', 'csv')),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    file_path TEXT,
    file_size INTEGER CHECK (file_size >= 0),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT export_jobs_completion_order CHECK (
        (started_at IS NULL AND completed_at IS NULL) OR
        (started_at IS NOT NULL AND completed_at IS NULL) OR
        (started_at IS NOT NULL AND completed_at IS NOT NULL AND completed_at >= started_at)
    )
);

-- Export jobs indexes
CREATE INDEX idx_export_jobs_user_id ON export_jobs(user_id);
CREATE INDEX idx_export_jobs_database_id ON export_jobs(database_id);
CREATE INDEX idx_export_jobs_status ON export_jobs(status);
CREATE INDEX idx_export_jobs_type ON export_jobs(job_type);
CREATE INDEX idx_export_jobs_created_at ON export_jobs(created_at);
CREATE INDEX idx_export_jobs_active ON export_jobs(status, created_at) WHERE status IN ('pending', 'processing');

-- ===========================================
-- API KEYS TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL,
    permissions JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT api_keys_name_length CHECK (char_length(name) >= 1 AND char_length(name) <= 255),
    CONSTRAINT api_keys_prefix_length CHECK (char_length(key_prefix) = 8),
    CONSTRAINT api_keys_expires_future CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- API keys indexes
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_active ON api_keys(user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- ===========================================
-- AUDIT LOGS TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT audit_logs_action_length CHECK (char_length(action) >= 1 AND char_length(action) <= 100),
    CONSTRAINT audit_logs_resource_type_length CHECK (char_length(resource_type) >= 1 AND char_length(resource_type) <= 50)
);

-- Audit logs indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_user_action ON audit_logs(user_id, action, created_at);

-- Audit logs partitioning by date (for large installations)
-- CREATE INDEX idx_audit_logs_created_at_hash ON audit_logs USING hash(date_trunc('month', created_at));

-- ===========================================
-- SYSTEM CONFIG TABLE
-- ===========================================
CREATE TABLE IF NOT EXISTS system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(255) NOT NULL UNIQUE,
    config_value JSONB NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT system_config_key_length CHECK (char_length(config_key) >= 1 AND char_length(config_key) <= 255)
);

-- System config indexes
CREATE INDEX idx_system_config_key ON system_config(config_key);
CREATE INDEX idx_system_config_active ON system_config(is_active) WHERE is_active = TRUE;

-- ===========================================
-- TRIGGERS
-- ===========================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_databases_updated_at BEFORE UPDATE ON user_databases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Session cleanup trigger
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at <= NOW();
    RETURN NULL;
END;
$$ language 'plpgsql';

-- Cleanup trigger (runs on session inserts)
CREATE TRIGGER cleanup_sessions_trigger
    AFTER INSERT ON user_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION cleanup_expired_sessions();

-- ===========================================
-- FUNCTIONS
-- ===========================================

-- Function to get user by email
CREATE OR REPLACE FUNCTION get_user_by_email(p_email VARCHAR)
RETURNS TABLE(
    id UUID,
    email VARCHAR,
    name VARCHAR,
    role VARCHAR,
    is_active BOOLEAN,
    email_verified BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.email, u.name, u.role, u.is_active, u.email_verified
    FROM users u
    WHERE u.email = p_email AND u.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to get active user sessions
CREATE OR REPLACE FUNCTION get_active_user_sessions(p_user_id UUID)
RETURNS TABLE(
    session_id VARCHAR,
    created_at TIMESTAMP,
    last_used_at TIMESTAMP,
    ip_address VARCHAR,
    user_agent TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT s.id, s.created_at, s.last_used_at, s.ip_address, s.user_agent
    FROM user_sessions s
    WHERE s.user_id = p_user_id 
      AND s.is_active = TRUE 
      AND s.expires_at > NOW()
    ORDER BY s.last_used_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old audit logs
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '1 day' * retention_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get system configuration
CREATE OR REPLACE FUNCTION get_system_config(p_config_key VARCHAR)
RETURNS JSONB AS $$
DECLARE
    config_value JSONB;
BEGIN
    SELECT sc.config_value INTO config_value
    FROM system_config sc
    WHERE sc.config_key = p_config_key AND sc.is_active = TRUE;
    
    RETURN COALESCE(config_value, 'null'::jsonb);
END;
$$ LANGUAGE plpgsql;

-- ===========================================
-- INITIAL DATA
-- ===========================================

-- Insert default system configuration
INSERT INTO system_config (config_key, config_value, description) VALUES
('app_version', '"1.0.0"', 'Application version'),
('maintenance_mode', 'false', 'Enable maintenance mode'),
('max_connections_per_user', '5', 'Maximum WebSocket connections per user'),
('export_retention_days', '7', 'How long to keep export files (days)'),
('audit_retention_days', '90', 'How long to keep audit logs (days)'),
('max_file_size', '10485760', 'Maximum file upload size in bytes (10MB)'),
('rate_limit_per_minute', '60', 'API rate limit per minute per user'),
('jwt_expiry_minutes', '15', 'JWT access token expiry in minutes'),
('jwt_refresh_expiry_days', '7', 'JWT refresh token expiry in days'),
('password_min_length', '8', 'Minimum password length'),
('session_timeout_minutes', '60', 'User session timeout in minutes')
ON CONFLICT (config_key) DO NOTHING;

-- ===========================================
-- VIEWS
-- ===========================================

-- Active users view
CREATE OR REPLACE VIEW active_users AS
SELECT 
    id,
    email,
    name,
    role,
    avatar_url,
    email_verified,
    preferences,
    created_at,
    last_login_at,
    (SELECT COUNT(*) FROM user_sessions s WHERE s.user_id = u.id AND s.is_active = TRUE AND s.expires_at > NOW()) as active_sessions
FROM users u
WHERE u.is_active = TRUE AND u.deleted_at IS NULL;

-- User statistics view
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    COUNT(*) as total_users,
    COUNT(*) FILTER (WHERE is_active = TRUE) as active_users,
    COUNT(*) FILTER (WHERE email_verified = TRUE) as verified_users,
    COUNT(*) FILTER (WHERE role = 'admin') as admin_users,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '30 days') as new_users_30d,
    COUNT(*) FILTER (WHERE last_login_at >= CURRENT_DATE - INTERVAL '30 days') as active_users_30d
FROM users
WHERE deleted_at IS NULL;

-- ===========================================
-- PERMISSIONS
-- ===========================================

-- Grant necessary permissions (adjust based on your user setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO claude_memory_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO claude_memory_app;

-- ===========================================
-- COMMENTS
-- ===========================================

COMMENT ON TABLE users IS 'Main users table with authentication and profile information';
COMMENT ON TABLE user_sessions IS 'JWT session management for authenticated users';
COMMENT ON TABLE user_databases IS 'Database configurations for multi-tenant setup';
COMMENT ON TABLE export_jobs IS 'Background jobs for data export and import operations';
COMMENT ON TABLE api_keys IS 'API keys for programmatic access';
COMMENT ON TABLE audit_logs IS 'Security and compliance audit trail';
COMMENT ON TABLE system_config IS 'System-wide configuration parameters';

COMMENT ON COLUMN users.role IS 'User role: user, admin, or super_admin';
COMMENT ON COLUMN users.preferences IS 'JSON object containing user preferences and settings';
COMMENT ON COLUMN user_databases.connection_config IS 'Encrypted database connection parameters';
COMMENT ON COLUMN export_jobs.metadata IS 'Job-specific metadata and options';
COMMENT ON COLUMN api_keys.permissions IS 'Array of permission strings for API access control';

-- Migration completed successfully
SELECT 'Master database initial migration completed successfully' as status;