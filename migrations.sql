-- Add missing columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(64) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);

-- Create sessions table if it doesn't exist
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512),
    refresh_token VARCHAR(512),
    device_info VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- PostgreSQL syntax for indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);

-- Add missing column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS rating DECIMAL(3,2);

-- Health check endpoint fix - not a DB issue but let's add a simple health check table
CREATE TABLE IF NOT EXISTS health_check (
    id INTEGER PRIMARY KEY DEFAULT 1,
    status VARCHAR(50) DEFAULT 'healthy',
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO health_check (id, status) VALUES (1, 'healthy') ON CONFLICT (id) DO NOTHING; 