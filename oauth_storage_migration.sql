-- Migration: Add Google OAuth token storage to users table
-- Created: 2026-02-07
-- Purpose: Store Google Calendar refresh tokens for OAuth 2.0 integration

-- Add columns for Google OAuth refresh token
ALTER TABLE users
ADD COLUMN IF NOT EXISTS google_refresh_token TEXT,
ADD COLUMN IF NOT EXISTS google_token_expires_at TIMESTAMPTZ;

-- Add index for token lookup performance
CREATE INDEX IF NOT EXISTS idx_users_google_refresh_token 
ON users (google_refresh_token) 
WHERE google_refresh_token IS NOT NULL;

-- Comment for documentation
COMMENT ON COLUMN users.google_refresh_token IS 'Google OAuth 2.0 refresh token for Calendar API access';
COMMENT ON COLUMN users.google_token_expires_at IS 'Expiration timestamp for the Google access token (not refresh token)';
