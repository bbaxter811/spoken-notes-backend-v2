-- Migration: Add storage quota tracking to users table
-- Created: 2026-02-07
-- Purpose: Track file storage usage against subscription tier limits

-- Add columns for storage quota tracking
ALTER TABLE users
ADD COLUMN IF NOT EXISTS storage_used_bytes BIGINT DEFAULT 0,
ADD COLUMN IF NOT EXISTS storage_limit_bytes BIGINT DEFAULT 107374182400; -- 100MB free tier default

-- Add check constraint to prevent negative storage
ALTER TABLE users
ADD CONSTRAINT chk_storage_used_bytes_positive CHECK (storage_used_bytes >= 0);

-- Add indexes for quota queries
CREATE INDEX IF NOT EXISTS idx_users_storage_used ON users (storage_used_bytes);
CREATE INDEX IF NOT EXISTS idx_users_storage_quota ON users (storage_used_bytes, storage_limit_bytes) 
WHERE storage_used_bytes >= storage_limit_bytes;

-- Create function to increment storage usage atomically
CREATE OR REPLACE FUNCTION increment_storage_usage(user_id_param UUID, bytes BIGINT)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET storage_used_bytes = storage_used_bytes + bytes
  WHERE id = user_id_param;
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'User not found: %', user_id_param;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to decrement storage usage (for deletions)
CREATE OR REPLACE FUNCTION decrement_storage_usage(user_id_param UUID, bytes BIGINT)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET storage_used_bytes = GREATEST(0, storage_used_bytes - bytes)
  WHERE id = user_id_param;
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'User not found: %', user_id_param;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check if user has storage quota available
CREATE OR REPLACE FUNCTION check_storage_quota(user_id_param UUID, required_bytes BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
  user_record RECORD;
BEGIN
  SELECT storage_used_bytes, storage_limit_bytes
  INTO user_record
  FROM users
  WHERE id = user_id_param;
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'User not found: %', user_id_param;
  END IF;
  
  RETURN (user_record.storage_used_bytes + required_bytes) <= user_record.storage_limit_bytes;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions to authenticated users
GRANT EXECUTE ON FUNCTION increment_storage_usage(UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION decrement_storage_usage(UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION check_storage_quota(UUID, BIGINT) TO authenticated;

-- Add comments for documentation
COMMENT ON COLUMN users.storage_used_bytes IS 'Total bytes of files stored in cloud storage (Supabase Storage or GCS)';
COMMENT ON COLUMN users.storage_limit_bytes IS 'Storage quota limit based on subscription tier (100MB free, 10GB pro, 100GB business)';
COMMENT ON FUNCTION increment_storage_usage IS 'Atomically increment storage usage when files are uploaded';
COMMENT ON FUNCTION decrement_storage_usage IS 'Atomically decrement storage usage when files are deleted';
COMMENT ON FUNCTION check_storage_quota IS 'Check if user has enough quota for a new file upload';
