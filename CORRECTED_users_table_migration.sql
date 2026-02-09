-- CORRECTED Migration 1: Create public.users table with all required columns
-- Run this in Supabase SQL Editor
-- This table extends auth.users with app-specific data

CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- OAuth tokens (stored separately from auth.users)
  google_refresh_token TEXT,
  google_token_expires_at TIMESTAMPTZ,
  
  -- Storage quota tracking
  storage_used_bytes BIGINT DEFAULT 0,
  storage_limit_bytes BIGINT DEFAULT 104857600, -- 100MB default
  
  -- Subscription info (for future use)
  subscription_tier TEXT DEFAULT 'free' CHECK (subscription_tier IN ('free', 'pro', 'business', 'enterprise')),
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  -- Constraints
  CONSTRAINT chk_storage_used_bytes_positive CHECK (storage_used_bytes >= 0)
);

-- Create index for fast lookups
CREATE INDEX IF NOT EXISTS idx_users_id ON public.users(id);
CREATE INDEX IF NOT EXISTS idx_users_storage_quota 
  ON public.users(storage_used_bytes, storage_limit_bytes) 
  WHERE storage_used_bytes >= storage_limit_bytes;

-- Enable RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- RLS Policies: Users can read their own data (except OAuth tokens)
DROP POLICY IF EXISTS "Users can read own profile" ON public.users;
CREATE POLICY "Users can read own profile"
  ON public.users FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

-- Users can update their own subscription tier (but NOT oauth tokens)
DROP POLICY IF EXISTS "Users can update own profile" ON public.users;
CREATE POLICY "Users can update own profile"
  ON public.users FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- Storage quota functions
CREATE OR REPLACE FUNCTION increment_storage_usage(user_id_param UUID, bytes BIGINT)
RETURNS void AS $$
BEGIN
  -- Insert if user doesn't exist in public.users yet
  INSERT INTO public.users (id, storage_used_bytes)
  VALUES (user_id_param, bytes)
  ON CONFLICT (id) DO UPDATE
  SET storage_used_bytes = public.users.storage_used_bytes + bytes;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrement_storage_usage(user_id_param UUID, bytes BIGINT)
RETURNS void AS $$
BEGIN
  UPDATE public.users
  SET storage_used_bytes = GREATEST(0, storage_used_bytes - bytes)
  WHERE id = user_id_param;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION check_storage_quota(user_id_param UUID, required_bytes BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
  user_record RECORD;
BEGIN
  SELECT storage_used_bytes, storage_limit_bytes
  INTO user_record
  FROM public.users
  WHERE id = user_id_param;
  
  IF NOT FOUND THEN
    -- User doesn't exist in public.users yet, allow (will be created on first use)
    RETURN TRUE;
  END IF;
  
  RETURN (user_record.storage_used_bytes + required_bytes) <= user_record.storage_limit_bytes;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION increment_storage_usage(UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION decrement_storage_usage(UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION check_storage_quota(UUID, BIGINT) TO authenticated;

-- Trigger to auto-create public.users entry when auth.users is created
CREATE OR REPLACE FUNCTION create_public_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.users (id, created_at)
  VALUES (NEW.id, NOW())
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION create_public_user();

-- Comments for documentation
COMMENT ON TABLE public.users IS 'Extended user profile data (supplements auth.users)';
COMMENT ON COLUMN public.users.google_refresh_token IS 'Google OAuth refresh token (backend access only)';
COMMENT ON COLUMN public.users.storage_used_bytes IS 'Total bytes stored in Supabase Storage';
COMMENT ON COLUMN public.users.storage_limit_bytes IS 'Storage quota based on subscription tier';
