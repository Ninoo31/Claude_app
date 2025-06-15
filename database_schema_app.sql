-- Extension de votre schéma existant pour l'application web
-- À exécuter sur votre PostgreSQL dans le namespace "databases"

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) DEFAULT 'email', -- 'email', 'google', 'github'
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table des sessions utilisateur
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Mise à jour de la table conversations pour lier aux utilisateurs
ALTER TABLE conversations 
ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- Mise à jour de custom_tables pour lier aux utilisateurs
ALTER TABLE custom_tables 
ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- Mise à jour de projects pour lier aux utilisateurs
ALTER TABLE projects 
ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- Index pour les nouvelles colonnes
CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_tables_user ON custom_tables(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);

-- Fonction pour créer un utilisateur par défaut
CREATE OR REPLACE FUNCTION create_default_user()
RETURNS UUID AS 
$$
DECLARE
    new_user_id UUID;
BEGIN
    INSERT INTO users (email, name, password_hash, email_verified)
    VALUES ('admin@localhost', 'Admin', '$argon2id$v=19$m=65536,t=3,p=4$random_salt_here', TRUE)
    ON CONFLICT (email) DO NOTHING
    RETURNING id INTO new_user_id;
    
    IF new_user_id IS NULL THEN
        SELECT id INTO new_user_id FROM users WHERE email = 'admin@localhost';
    END IF;
    
    RETURN new_user_id;
END;
$$
LANGUAGE plpgsql;

-- Vue pour les conversations avec informations utilisateur
CREATE OR REPLACE VIEW user_conversations AS
SELECT 
    c.*,
    u.name as user_name,
    u.email as user_email,
    COUNT(cm.id) as actual_message_count,
    MAX(cm.created_at) as last_message_at
FROM conversations c
JOIN users u ON c.user_id = u.id
LEFT JOIN conversation_messages cm ON c.conversation_id = cm.conversation_id
GROUP BY c.id, u.id, u.name, u.email
ORDER BY c.updated_at DESC;

-- Mise à jour des politiques de sécurité (Row Level Security)
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversation_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_tables ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

-- Policies pour les conversations (utilisateurs ne voient que leurs données)
CREATE POLICY conversations_user_policy ON conversations
    FOR ALL USING (user_id = current_setting('app.current_user_id')::UUID);

CREATE POLICY messages_user_policy ON conversation_messages
    FOR ALL USING (
        conversation_id IN (
            SELECT conversation_id FROM conversations 
            WHERE user_id = current_setting('app.current_user_id')::UUID
        )
    );

-- Fonction pour définir l'utilisateur actuel dans la session
CREATE OR REPLACE FUNCTION set_current_user(p_user_id UUID)
RETURNS VOID AS 
$$
BEGIN
    PERFORM set_config('app.current_user_id', p_user_id::TEXT, TRUE);
END;
$$
LANGUAGE plpgsql;

-- Fonction pour obtenir les conversations d'un utilisateur
CREATE OR REPLACE FUNCTION get_user_conversations(p_user_id UUID, p_limit INTEGER DEFAULT 50)
RETURNS TABLE(
    conversation_id VARCHAR(255),
    title VARCHAR(500),
    summary TEXT,
    importance_level INTEGER,
    message_count INTEGER,
    last_message_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
) AS 
$$
BEGIN
    RETURN QUERY
    SELECT 
        c.conversation_id,
        c.title,
        c.summary,
        c.importance_level,
        c.message_count,
        MAX(cm.created_at) as last_message_at,
        c.created_at,
        c.updated_at
    FROM conversations c
    LEFT JOIN conversation_messages cm ON c.conversation_id = cm.conversation_id
    WHERE c.user_id = p_user_id 
      AND c.is_archived = FALSE
    GROUP BY c.id, c.conversation_id, c.title, c.summary, c.importance_level, c.message_count, c.created_at, c.updated_at
    ORDER BY c.updated_at DESC
    LIMIT p_limit;
END;
$$
LANGUAGE plpgsql;

-- Fonction pour rechercher dans les conversations d'un utilisateur
CREATE OR REPLACE FUNCTION search_user_conversations(
    p_user_id UUID,
    search_term TEXT, 
    limit_results INTEGER DEFAULT 10
)
RETURNS TABLE(
    conversation_id VARCHAR(255),
    title VARCHAR(500),
    content_match TEXT,
    importance_level INTEGER,
    match_type VARCHAR(20)
) AS 
$$
BEGIN
    RETURN QUERY
    SELECT 
        c.conversation_id,
        c.title,
        LEFT(COALESCE(c.summary, ''), 200) as content_match,
        c.importance_level,
        'conversation'::VARCHAR(20) as match_type
    FROM conversations c
    WHERE c.user_id = p_user_id
      AND (
          c.title ILIKE '%' || search_term || '%'
          OR c.summary ILIKE '%' || search_term || '%'
          OR c.key_topics ILIKE '%' || search_term || '%'
      )
      AND c.is_archived = FALSE
    
    UNION ALL
    
    SELECT DISTINCT
        cm.conversation_id,
        c.title,
        LEFT(cm.content, 200) as content_match,
        c.importance_level,
        'message'::VARCHAR(20) as match_type
    FROM conversation_messages cm
    JOIN conversations c ON cm.conversation_id = c.conversation_id
    WHERE c.user_id = p_user_id
      AND cm.content ILIKE '%' || search_term || '%'
      AND c.is_archived = FALSE
    
    ORDER BY importance_level DESC
    LIMIT limit_results;
END;
$$
LANGUAGE plpgsql;

-- Créer un utilisateur admin par défaut
SELECT create_default_user();

-- Test de la configuration
SELECT 'Extension utilisateurs créée avec succès !' as status;

-- Vérification des tables
SELECT 
    table_name,
    column_name,
    data_type
FROM information_schema.columns 
WHERE table_name IN ('users', 'user_sessions') 
ORDER BY table_name, ordinal_position;