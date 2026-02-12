-- ============================================
-- PHASE 1: FILE ARCHIVE FOUNDATION
-- user_files table for per-file metadata tracking
-- ============================================

CREATE TABLE user_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  request_id TEXT NOT NULL, -- Links to action_logs for traceability
  
  -- File identity
  file_name TEXT NOT NULL,
  file_type VARCHAR(50) NOT NULL, -- 'audio', 'transcript', 'docx', 'xlsx', 'calendar', 'pdf'
  file_size_bytes BIGINT NOT NULL,
  storage_path TEXT NOT NULL, -- Supabase Storage path or URL
  
  -- Archive & deletion
  archived BOOLEAN DEFAULT false,
  deleted BOOLEAN DEFAULT false, -- Soft delete for recovery
  
  -- Metadata (calculated on creation)
  word_count INTEGER, -- For text documents
  duration_seconds INTEGER, -- For audio files
  ai_minutes_used DECIMAL(10,2), -- AI minutes consumed generating this file
  
  -- Flexible metadata storage
  metadata_json JSONB DEFAULT '{}'::jsonb,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE, -- When soft-deleted
  archived_at TIMESTAMP WITH TIME ZONE -- When archived
);

-- Performance indexes
CREATE INDEX idx_user_files_user_id ON user_files(user_id) WHERE deleted = false;
CREATE INDEX idx_user_files_type ON user_files(file_type) WHERE deleted = false;
CREATE INDEX idx_user_files_archived ON user_files(archived) WHERE deleted = false;
CREATE INDEX idx_user_files_request_id ON user_files(request_id);
CREATE INDEX idx_user_files_created ON user_files(created_at DESC) WHERE deleted = false;

-- Composite index for common queries (user's active files)
CREATE INDEX idx_user_files_active ON user_files(user_id, deleted, archived, created_at DESC);

-- Metadata search index (GIN for JSONB queries)
CREATE INDEX idx_user_files_metadata ON user_files USING GIN (metadata_json);

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_user_files_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_user_files_updated_at
  BEFORE UPDATE ON user_files
  FOR EACH ROW
  EXECUTE FUNCTION update_user_files_updated_at();

-- RPC function to safely increment file-specific metadata
CREATE OR REPLACE FUNCTION log_user_file(
  p_user_id UUID,
  p_request_id TEXT,
  p_file_name TEXT,
  p_file_type VARCHAR(50),
  p_file_size_bytes BIGINT,
  p_storage_path TEXT,
  p_word_count INTEGER DEFAULT NULL,
  p_duration_seconds INTEGER DEFAULT NULL,
  p_ai_minutes_used DECIMAL(10,2) DEFAULT NULL,
  p_metadata_json JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID AS $$
DECLARE
  v_file_id UUID;
BEGIN
  INSERT INTO user_files (
    user_id,
    request_id,
    file_name,
    file_type,
    file_size_bytes,
    storage_path,
    word_count,
    duration_seconds,
    ai_minutes_used,
    metadata_json
  ) VALUES (
    p_user_id,
    p_request_id,
    p_file_name,
    p_file_type,
    p_file_size_bytes,
    p_storage_path,
    p_word_count,
    p_duration_seconds,
    p_ai_minutes_used,
    p_metadata_json
  )
  RETURNING id INTO v_file_id;
  
  RETURN v_file_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Comment documentation
COMMENT ON TABLE user_files IS 'Per-file metadata for archiving, billing, and user file management';
COMMENT ON COLUMN user_files.ai_minutes_used IS 'AI minutes consumed to generate this file (for billing transparency)';
COMMENT ON COLUMN user_files.archived IS 'User-toggled archive flag (removes from main view but keeps accessible)';
COMMENT ON COLUMN user_files.deleted IS 'Soft delete flag (30-day recovery window before permanent deletion)';
COMMENT ON COLUMN user_files.metadata_json IS 'Flexible storage for file-specific data (tags, custom fields, etc)';
