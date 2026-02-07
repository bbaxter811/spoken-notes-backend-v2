-- Unified action logs table for all assistant actions
-- Tracks: SMS, Docs, Excel, Calendar, Reminders, Email
-- Run this in Supabase SQL Editor

CREATE TABLE IF NOT EXISTS action_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  request_id TEXT NOT NULL UNIQUE, -- Frontend-generated UUID for tracking
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Action metadata
  action_type TEXT NOT NULL CHECK (action_type IN (
    'send_email',
    'send_sms', 
    'create_docx',
    'create_xlsx',
    'create_calendar_event',
    'create_reminder'
  )),
  
  -- Payload (JSON) - action-specific data
  -- SMS: { to_phone, message }
  -- Email: { to_email, subject, body }
  -- Docs/Sheets: { title, content }
  -- Calendar: { title, start_time, end_time, timezone }
  -- Reminder: { text, remind_at }
  payload_json JSONB NOT NULL,
  
  -- Status tracking
  status TEXT NOT NULL CHECK (status IN ('queued', 'sent', 'completed', 'failed')),
  
  -- Provider info
  provider TEXT, -- 'sendgrid', 'twilio', 'google_calendar', 'internal', etc.
  provider_id TEXT, -- Twilio message SID, Google event ID, etc.
  provider_url TEXT, -- Download link for docs/sheets, event link for calendar
  
  -- Error handling
  error_message TEXT,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_action_logs_request_id ON action_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_user_id ON action_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_action_type ON action_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_action_logs_status ON action_logs(status);
CREATE INDEX IF NOT EXISTS idx_action_logs_created_at ON action_logs(created_at DESC);

-- RLS policies
ALTER TABLE action_logs ENABLE ROW LEVEL SECURITY;

-- Users can only view their own action logs
CREATE POLICY "Users can view own action logs"
  ON action_logs
  FOR SELECT
  USING (auth.uid() = user_id);

-- Service role (backend) can insert/update action logs
CREATE POLICY "Service role can manage action logs"
  ON action_logs
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- Grant permissions
GRANT SELECT ON action_logs TO authenticated;
GRANT ALL ON action_logs TO service_role;
