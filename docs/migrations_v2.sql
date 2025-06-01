-- Migration V2: Add missing fields and constraints for production readiness
-- Run after initial schema creation

-- Add missing columns to users table if they don't exist
ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS username VARCHAR(64) UNIQUE,
  ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
  ADD COLUMN IF NOT EXISTS rating FLOAT DEFAULT NULL;

-- Add missing columns to sessions table for refresh token support
ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS refresh_token TEXT,
  ADD COLUMN IF NOT EXISTS device_info TEXT,
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- Add rating to profiles table for user ratings
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS rating FLOAT DEFAULT NULL;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_location ON users USING GIST(location);
CREATE INDEX IF NOT EXISTS idx_users_services_offered ON users USING GIN(services_offered);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);

-- Add constraints for data integrity
ALTER TABLE users 
  ADD CONSTRAINT chk_rating_range CHECK (rating >= 0 AND rating <= 5),
  ADD CONSTRAINT chk_level_positive CHECK (level >= 0);

ALTER TABLE profiles
  ADD CONSTRAINT chk_profile_rating_range CHECK (rating >= 0 AND rating <= 5);

-- Create function to generate unique usernames
CREATE OR REPLACE FUNCTION generate_username(base_name TEXT)
RETURNS TEXT AS $$
DECLARE
    username_candidate TEXT;
    counter INTEGER := 1;
BEGIN
    -- Clean the base name: remove special characters, spaces, convert to lowercase
    base_name := lower(regexp_replace(base_name, '[^a-zA-Z0-9]', '', 'g'));
    
    -- Ensure minimum length
    IF length(base_name) < 3 THEN
        base_name := 'user' || base_name;
    END IF;
    
    -- Try the base name first
    username_candidate := base_name;
    
    -- If it exists, append numbers until we find a unique one
    WHILE EXISTS (SELECT 1 FROM users WHERE username = username_candidate) LOOP
        username_candidate := base_name || counter;
        counter := counter + 1;
    END LOOP;
    
    RETURN username_candidate;
END;
$$ LANGUAGE plpgsql;

-- Backfill usernames for existing users
UPDATE users 
SET username = generate_username(
    CASE 
        WHEN full_name IS NOT NULL AND full_name != '' THEN full_name
        ELSE split_part(email, '@', 1)
    END
)
WHERE username IS NULL;

-- Make username NOT NULL after backfill
ALTER TABLE users ALTER COLUMN username SET NOT NULL;

-- Create trigger to auto-generate username if not provided
CREATE OR REPLACE FUNCTION auto_generate_username()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.username IS NULL THEN
        NEW.username := generate_username(
            CASE 
                WHEN NEW.full_name IS NOT NULL AND NEW.full_name != '' THEN NEW.full_name
                ELSE split_part(NEW.email, '@', 1)
            END
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tr_auto_generate_username
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION auto_generate_username();

-- Add comments for new fields
COMMENT ON COLUMN users.username IS 'Unique username for the user, auto-generated if not provided';
COMMENT ON COLUMN users.full_name IS 'Full display name of the user';
COMMENT ON COLUMN users.rating IS 'Average rating of the user (0-5 scale)';
COMMENT ON COLUMN sessions.refresh_token IS 'Refresh token for session renewal';
COMMENT ON COLUMN sessions.device_info IS 'Information about the device/client';
COMMENT ON COLUMN sessions.is_active IS 'Whether the session is currently active'; 