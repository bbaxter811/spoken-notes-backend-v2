-- Email logs table for tracking all outbound emails
-- Run this in Supabase SQL Editor

CREATE TABLE IF NOT EXISTS email_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  to_email TEXT NOT NULL,
  from_email TEXT NOT NULL,
  reply_to TEXT,
  subject TEXT,
  body TEXT,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
  provider TEXT DEFAULT 'sendgrid',
  provider_message_id TEXT,
  error_message TEXT,
  sent_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for user lookup
CREATE INDEX IF NOT EXISTS idx_email_logs_user_id ON email_logs(user_id);

-- Index for status filtering
CREATE INDEX IF NOT EXISTS idx_email_logs_status ON email_logs(status);

-- Index for date range queries
CREATE INDEX IF NOT EXISTS idx_email_logs_sent_at ON email_logs(sent_at DESC);

-- RLS policies
ALTER TABLE email_logs ENABLE ROW LEVEL SECURITY;

-- Users can only view their own email logs
CREATE POLICY "Users can view own email logs"
  ON email_logs
  FOR SELECT
  USING (auth.uid() = user_id);

-- Service role (backend) can insert email logs
CREATE POLICY "Service role can insert email logs"
  ON email_logs
  FOR INSERT
  WITH CHECK (true);

-- Grant permissions
GRANT SELECT, INSERT ON email_logs TO authenticated;
GRANT ALL ON email_logs TO service_role;
