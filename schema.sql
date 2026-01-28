-- Spoken Notes V2 - Simplified Database Schema
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- RECORDINGS TABLE (simplified from V1's memory_files + transcripts + summaries)
-- ============================================================================
CREATE TABLE IF NOT EXISTS recordings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Audio file info
  audio_url TEXT NOT NULL,
  filename TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  file_size_bytes BIGINT,
  
  -- Transcription data
  transcription TEXT,
  summary TEXT,
  
  -- Metadata
  status TEXT NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'processing', 'completed', 'error')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- USER PREFERENCES TABLE (for settings sync - Priority 4)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_preferences (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Voice personalization
  assistant_name TEXT DEFAULT 'Assistant',
  voice_gender TEXT DEFAULT 'female' CHECK (voice_gender IN ('male', 'female')),
  voice_attitude TEXT DEFAULT 'helpful' CHECK (voice_attitude IN ('helpful', 'friendly', 'formal')),
  
  -- Chat intelligence mode
  retrieval_mode TEXT DEFAULT 'hybrid' CHECK (retrieval_mode IN ('hybrid', 'memory', 'web')),
  
  -- Tap detection settings
  tap_detection_enabled BOOLEAN DEFAULT true,
  tap_sensitivity TEXT DEFAULT 'medium' CHECK (tap_sensitivity IN ('low', 'medium', 'high')),
  double_tap_action TEXT DEFAULT 'record',
  triple_tap_action TEXT DEFAULT 'pause',
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_recordings_user_id ON recordings(user_id);
CREATE INDEX IF NOT EXISTS idx_recordings_created_at ON recordings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recordings_status ON recordings(status);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================
ALTER TABLE recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_preferences ENABLE ROW LEVEL SECURITY;

-- Recordings policies
CREATE POLICY "Users can view their own recordings"
  ON recordings FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own recordings"
  ON recordings FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own recordings"
  ON recordings FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own recordings"
  ON recordings FOR DELETE
  USING (auth.uid() = user_id);

-- User preferences policies
CREATE POLICY "Users can view their own preferences"
  ON user_preferences FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own preferences"
  ON user_preferences FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own preferences"
  ON user_preferences FOR UPDATE
  USING (auth.uid() = user_id);

-- ============================================================================
-- STORAGE BUCKET FOR AUDIO FILES
-- ============================================================================
-- Run these separately in Supabase Dashboard > Storage

-- Create bucket:
-- insert into storage.buckets (id, name, public) values ('recordings', 'recordings', false);

-- Storage policies:
-- CREATE POLICY "Users can upload their own recordings"
--   ON storage.objects FOR INSERT
--   WITH CHECK (bucket_id = 'recordings' AND auth.uid()::text = (storage.foldername(name))[1]);
-- 
-- CREATE POLICY "Users can view their own recordings"
--   ON storage.objects FOR SELECT
--   USING (bucket_id = 'recordings' AND auth.uid()::text = (storage.foldername(name))[1]);
-- 
-- CREATE POLICY "Users can delete their own recordings"
--   ON storage.objects FOR DELETE
--   USING (bucket_id = 'recordings' AND auth.uid()::text = (storage.foldername(name))[1]);

-- ============================================================================
-- STORAGE METERING VIEWS (for billing/alerting)
-- ============================================================================

-- View 1: Audio bytes per user (from Supabase Storage)
CREATE OR REPLACE VIEW public.user_audio_usage AS
SELECT 
  (regexp_match(name, '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.*'))[1]::uuid AS user_id,
  SUM((metadata->>'size')::bigint) AS audio_bytes
FROM storage.objects
WHERE 
  bucket_id = 'recordings'
  AND name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.*'
GROUP BY user_id;

-- View 2: Text bytes per user (transcriptions + summaries in DB)
CREATE OR REPLACE VIEW public.user_text_usage AS
SELECT 
  user_id,
  SUM(
    COALESCE(octet_length(transcription), 0) + 
    COALESCE(octet_length(summary), 0)
  ) AS text_bytes
FROM recordings
WHERE status = 'completed'
GROUP BY user_id;

-- View 3: Combined storage (single source of truth)
CREATE OR REPLACE VIEW public.user_storage_usage AS
SELECT 
  COALESCE(a.user_id, t.user_id) AS user_id,
  COALESCE(a.audio_bytes, 0) AS audio_bytes,
  COALESCE(t.text_bytes, 0) AS text_bytes,
  COALESCE(a.audio_bytes, 0) + COALESCE(t.text_bytes, 0) AS total_bytes
FROM user_audio_usage a
FULL OUTER JOIN user_text_usage t ON a.user_id = t.user_id;

-- Grant select access to authenticated users (for /api/billing/usage endpoint)
GRANT SELECT ON public.user_audio_usage TO authenticated;
GRANT SELECT ON public.user_text_usage TO authenticated;
GRANT SELECT ON public.user_storage_usage TO authenticated;

-- ============================================================================
-- USER SUBSCRIPTIONS TABLE (for Stripe webhook writes)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_subscriptions (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Stripe identifiers
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT UNIQUE,
  
  -- Subscription details
  status TEXT NOT NULL DEFAULT 'free' CHECK (status IN ('free', 'active', 'past_due', 'canceled', 'trialing')),
  tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'premium')),
  
  -- Billing period
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for lookups by Stripe IDs
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe_customer ON user_subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe_subscription ON user_subscriptions(stripe_subscription_id);

-- RLS policies
ALTER TABLE user_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own subscription"
  ON user_subscriptions FOR SELECT
  USING (auth.uid() = user_id);

-- Note: Only backend (service role) can INSERT/UPDATE subscriptions (from webhooks)
