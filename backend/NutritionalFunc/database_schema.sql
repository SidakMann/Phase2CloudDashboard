-- Phase 3: Database Schema for User Management
-- Azure SQL Database Schema

-- Users table to store user profiles
CREATE TABLE Users (
    user_id INT IDENTITY(1,1) PRIMARY KEY,
    email NVARCHAR(255) UNIQUE NOT NULL,
    password_hash NVARCHAR(255) NULL, -- NULL for OAuth-only users
    full_name NVARCHAR(255),
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    is_active BIT DEFAULT 1,
    CONSTRAINT chk_email_format CHECK (email LIKE '%_@__%.__%')
);

-- OAuth providers table to track third-party authentication
CREATE TABLE OAuthProviders (
    oauth_id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    provider NVARCHAR(50) NOT NULL, -- 'github', 'google', etc.
    provider_user_id NVARCHAR(255) NOT NULL, -- ID from OAuth provider
    provider_username NVARCHAR(255),
    access_token NVARCHAR(MAX), -- Encrypted token (optional for future use)
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    CONSTRAINT uq_provider_user UNIQUE (provider, provider_user_id)
);

-- User sessions table (optional - for tracking active sessions)
CREATE TABLE UserSessions (
    session_id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    jwt_token_hash NVARCHAR(255) NOT NULL,
    created_at DATETIME2 DEFAULT GETDATE(),
    expires_at DATETIME2 NOT NULL,
    is_revoked BIT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_users_email ON Users(email);
CREATE INDEX idx_oauth_provider_userid ON OAuthProviders(provider, provider_user_id);
CREATE INDEX idx_sessions_token ON UserSessions(jwt_token_hash);
CREATE INDEX idx_sessions_user ON UserSessions(user_id);

-- Trigger to update updated_at timestamp
GO
CREATE TRIGGER trg_Users_UpdateTimestamp
ON Users
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE Users
    SET updated_at = GETDATE()
    FROM Users u
    INNER JOIN inserted i ON u.user_id = i.user_id;
END;
GO

CREATE TRIGGER trg_OAuthProviders_UpdateTimestamp
ON OAuthProviders
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE OAuthProviders
    SET updated_at = GETDATE()
    FROM OAuthProviders o
    INNER JOIN inserted i ON o.oauth_id = i.oauth_id;
END;
GO

-- Sample queries for testing
-- INSERT INTO Users (email, password_hash, full_name) VALUES ('test@example.com', 'hashed_password_here', 'Test User');
-- SELECT * FROM Users WHERE email = 'test@example.com';
-- SELECT u.*, o.provider, o.provider_username FROM Users u LEFT JOIN OAuthProviders o ON u.user_id = o.user_id;
