-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- Enable PostGIS extension for geography type
CREATE EXTENSION IF NOT EXISTS postgis;

-- User table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(32) UNIQUE,
    username VARCHAR(64) UNIQUE, -- new
    full_name VARCHAR(255),      -- new
    password_hash VARCHAR(255),
    google_id VARCHAR(255),
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_phone_verified BOOLEAN DEFAULT FALSE,
    role VARCHAR(32) DEFAULT 'general',
    willing_to_provide_services BOOLEAN DEFAULT FALSE,
    level INTEGER DEFAULT 0,
    services_offered UUID[],
    location GEOGRAPHY(Point, 4326),
    rating FLOAT,                -- new
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Profile table
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    full_name VARCHAR(255),
    bio TEXT,
    avatar_url TEXT,
    phone_number VARCHAR(32),
    rating FLOAT,                -- new
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Email verification codes
CREATE TABLE IF NOT EXISTS email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255),
    code VARCHAR(16),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Phone OTPs
CREATE TABLE IF NOT EXISTS phone_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone VARCHAR(32),
    otp VARCHAR(8),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Password reset codes
CREATE TABLE IF NOT EXISTS password_resets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(16),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Google OAuth identities
CREATE TABLE IF NOT EXISTS oauth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32),
    provider_id VARCHAR(255),
    email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Session table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token TEXT,
    refresh_token TEXT,          -- new
    device_info TEXT,            -- new
    is_active BOOLEAN DEFAULT TRUE, -- new
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updating updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE users IS 'Users table storing core user information';
COMMENT ON TABLE profiles IS 'Extended user profile information';
COMMENT ON TABLE sessions IS 'User session management'; -- Removed, table does not exist


-- Add comments on columns
COMMENT ON COLUMN users.id IS 'Unique identifier for the user';
COMMENT ON COLUMN users.email IS 'User email address, must be unique';
COMMENT ON COLUMN users.username IS 'Username for the user, must be unique';
COMMENT ON COLUMN users.password IS 'Hashed password for the user';
COMMENT ON COLUMN users.is_creator IS 'Flag indicating if the user is a creator';

COMMENT ON COLUMN profiles.user_id IS 'Reference to the users table';
COMMENT ON COLUMN profiles.full_name IS 'Full name of the user';
COMMENT ON COLUMN profiles.bio IS 'User biography or description';
COMMENT ON COLUMN profiles.avatar_url IS 'URL to the user avatar image';
COMMENT ON COLUMN profiles.phone_number IS 'User contact phone number';

COMMENT ON COLUMN sessions.id IS 'Unique identifier for the session';
COMMENT ON COLUMN sessions.user_id IS 'Reference to the users table';
COMMENT ON COLUMN sessions.token IS 'JWT token for the session';
COMMENT ON COLUMN sessions.expires_at IS 'Session expiration timestamp';

