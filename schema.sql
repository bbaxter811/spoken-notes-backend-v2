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
