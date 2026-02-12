-- ============================================
-- PHASE 2: AI MINUTES METERING
-- Per-request AI usage tracking + monthly aggregation
-- ============================================

-- ai_usage_logs: Per-request tracking
CREATE TABLE ai_usage_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  request_id TEXT NOT NULL, -- Links to action_logs, user_files
  
  -- Request type
  kind VARCHAR(50) NOT NULL, -- 'transcribe', 'chat', 'docx', 'xlsx', 'pdf', 'email', 'sms'
  
  -- Audio-based usage (authoritative for transcription)
  audio_seconds DECIMAL(10,2), -- Duration of audio file transcribed
  
  -- LLM token usage (estimated server-side)
  llm_input_tokens_est INTEGER, -- Input tokens (prompt)
  llm_output_tokens_est INTEGER, -- Output tokens (completion)
  
  -- Converted to "AI minutes" for billing
  ai_minutes DECIMAL(10,4) NOT NULL, -- Total AI minutes consumed (audio + LLM combined)
  
  -- Metadata
  model_used VARCHAR(100), -- 'whisper-1', 'gpt-4', etc.
  metadata_json JSONB DEFAULT '{}'::jsonb,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_ai_usage_logs_user_id ON ai_usage_logs(user_id);
CREATE INDEX idx_ai_usage_logs_request_id ON ai_usage_logs(request_id);
CREATE INDEX idx_ai_usage_logs_kind ON ai_usage_logs(kind);
CREATE INDEX idx_ai_usage_logs_created ON ai_usage_logs(created_at DESC);

-- Composite index for user's recent usage
CREATE INDEX idx_ai_usage_logs_user_created ON ai_usage_logs(user_id, created_at DESC);

-- user_ai_usage_monthly: Aggregated monthly usage
CREATE TABLE user_ai_usage_monthly (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  month DATE NOT NULL, -- First day of month (e.g., '2026-02-01')
  
  ai_minutes_used DECIMAL(10,2) NOT NULL DEFAULT 0, -- Total AI minutes this month
  
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  PRIMARY KEY (user_id, month)
);

-- Index for fast lookups
CREATE INDEX idx_ai_usage_monthly_month ON user_ai_usage_monthly(month);

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_ai_usage_monthly_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_ai_usage_monthly_updated_at
  BEFORE UPDATE ON user_ai_usage_monthly
  FOR EACH ROW
  EXECUTE FUNCTION update_ai_usage_monthly_updated_at();

-- RPC function: Log AI usage and increment monthly counter
CREATE OR REPLACE FUNCTION log_ai_usage(
  p_user_id UUID,
  p_request_id TEXT,
  p_kind VARCHAR(50),
  p_ai_minutes DECIMAL(10,4),
  p_audio_seconds DECIMAL(10,2) DEFAULT NULL,
  p_llm_input_tokens_est INTEGER DEFAULT NULL,
  p_llm_output_tokens_est INTEGER DEFAULT NULL,
  p_model_used VARCHAR(100) DEFAULT NULL,
  p_metadata_json JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID AS $$
DECLARE
  v_log_id UUID;
  v_current_month DATE;
BEGIN
  -- Insert usage log
  INSERT INTO ai_usage_logs (
    user_id,
    request_id,
    kind,
    audio_seconds,
    llm_input_tokens_est,
    llm_output_tokens_est,
    ai_minutes,
    model_used,
    metadata_json
  ) VALUES (
    p_user_id,
    p_request_id,
    p_kind,
    p_audio_seconds,
    p_llm_input_tokens_est,
    p_llm_output_tokens_est,
    p_ai_minutes,
    p_model_used,
    p_metadata_json
  )
  RETURNING id INTO v_log_id;
  
  -- Calculate current month (first day)
  v_current_month := DATE_TRUNC('month', NOW());
  
  -- Upsert monthly usage
  INSERT INTO user_ai_usage_monthly (user_id, month, ai_minutes_used)
  VALUES (p_user_id, v_current_month, p_ai_minutes)
  ON CONFLICT (user_id, month)
  DO UPDATE SET
    ai_minutes_used = user_ai_usage_monthly.ai_minutes_used + p_ai_minutes,
    updated_at = NOW();
  
  RETURN v_log_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- RPC function: Get current month's AI usage
CREATE OR REPLACE FUNCTION get_ai_usage_this_month(p_user_id UUID)
RETURNS DECIMAL(10,2) AS $$
DECLARE
  v_minutes DECIMAL(10,2);
  v_current_month DATE;
BEGIN
  v_current_month := DATE_TRUNC('month', NOW());
  
  SELECT ai_minutes_used INTO v_minutes
  FROM user_ai_usage_monthly
  WHERE user_id = p_user_id AND month = v_current_month;
  
  RETURN COALESCE(v_minutes, 0);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Comment documentation
COMMENT ON TABLE ai_usage_logs IS 'Per-request AI usage tracking for transcription, LLM, and document generation';
COMMENT ON TABLE user_ai_usage_monthly IS 'Monthly AI minutes aggregation for billing and quota enforcement';
COMMENT ON COLUMN ai_usage_logs.audio_seconds IS 'Audio duration for transcription (authoritative source for transcription minutes)';
COMMENT ON COLUMN ai_usage_logs.llm_input_tokens_est IS 'Estimated input tokens (server-side tokenizer, not from API response)';
COMMENT ON COLUMN ai_usage_logs.llm_output_tokens_est IS 'Estimated output tokens (server-side tokenizer)';
COMMENT ON COLUMN ai_usage_logs.ai_minutes IS 'Total AI minutes: (audio_seconds/60) + (tokens converted via formula)';
COMMENT ON COLUMN user_ai_usage_monthly.month IS 'First day of month for aggregation period';
