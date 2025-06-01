-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    username VARCHAR(64) UNIQUE,
    full_name VARCHAR(255),
    password_hash VARCHAR(255),
    google_id VARCHAR(255),
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_phone_verified BOOLEAN DEFAULT FALSE,
    role VARCHAR(50) DEFAULT 'user',
    willing_to_provide_services BOOLEAN DEFAULT FALSE,
    level INTEGER DEFAULT 1,
    services_offered TEXT[],
    location VARCHAR(255),
    rating DECIMAL(3,2),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    full_name VARCHAR(255),
    bio TEXT,
    avatar_url VARCHAR(500),
    phone_number VARCHAR(20),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(500),
    device_info VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- Create email_verifications table
CREATE TABLE IF NOT EXISTS email_verifications (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL
);

-- Create phone_otps table
CREATE TABLE IF NOT EXISTS phone_otps (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    phone VARCHAR(20) NOT NULL,
    otp VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL
);

-- Create password_resets table
CREATE TABLE IF NOT EXISTS password_resets (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL
);

-- Create oauth_identities table
CREATE TABLE IF NOT EXISTS oauth_identities (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    UNIQUE(provider, provider_id)
);

-- Create services table
CREATE TABLE IF NOT EXISTS services (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    duration INTEGER NOT NULL,
    category VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create locations table
CREATE TABLE IF NOT EXISTS locations (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    address VARCHAR(500) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    country VARCHAR(100) NOT NULL,
    latitude DECIMAL(10,8) NOT NULL,
    longitude DECIMAL(11,8) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create availabilities table
CREATE TABLE IF NOT EXISTS availabilities (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    schedule JSONB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_email_verifications_email ON email_verifications(email);
CREATE INDEX idx_phone_otps_phone ON phone_otps(phone); 