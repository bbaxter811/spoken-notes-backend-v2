-- SMS Consent Source Tracking Migration
-- Purpose: Add detailed consent tracking for TCPA compliance
-- Created: February 11, 2026
-- Required by: Telephone Consumer Protection Act (TCPA) and carrier audits

-- 1. Create user consent data table (cannot alter auth.users due to Supabase permissions)
CREATE TABLE IF NOT EXISTS user_consent_data (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
  consent_method VARCHAR(50), -- 'voice_command' or 'web_signup'
  consent_ip INET, -- IP address when consent was given
  consent_user_agent TEXT, -- Browser/app user agent string
  plan VARCHAR(20) DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'plus')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_consent_data_user_id ON user_consent_data(user_id);
CREATE INDEX IF NOT EXISTS idx_user_consent_data_plan ON user_consent_data(plan);

COMMENT ON TABLE user_consent_data IS 'SMS consent tracking and subscription plan data (extends auth.users)';
COMMENT ON COLUMN user_consent_data.consent_method IS 'How user consented to SMS: voice_command (said "send me") or web_signup (provided phone during registration)';
COMMENT ON COLUMN user_consent_data.consent_ip IS 'IP address at time of SMS consent (for fraud prevention and compliance audits)';
COMMENT ON COLUMN user_consent_data.consent_user_agent IS 'User agent string at time of consent (helps identify app version during audits)';
COMMENT ON COLUMN user_consent_data.plan IS 'User subscription plan: free ($0), pro ($13/month), or plus ($29/month)';

-- 2. Add SMS rate limiting tracking table
CREATE TABLE IF NOT EXISTS sms_rate_limits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
  minute_count INT DEFAULT 0,
  minute_reset_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  hour_count INT DEFAULT 0,
  hour_reset_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  day_count INT DEFAULT 0,
  day_reset_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_sms_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sms_rate_limits_user_id ON sms_rate_limits(user_id);
CREATE INDEX IF NOT EXISTS idx_sms_rate_limits_last_sms_at ON sms_rate_limits(last_sms_at);

COMMENT ON TABLE sms_rate_limits IS 'Tracks SMS rate limits per user to prevent abuse';

-- 3. Create action_logs table with delivery tracking
CREATE TABLE IF NOT EXISTS action_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id TEXT NOT NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  action_type VARCHAR(50) NOT NULL,
  payload_json JSONB,
  status VARCHAR(50) NOT NULL,
  provider VARCHAR(50),
  provider_id TEXT,
  error_message TEXT,
  delivery_status VARCHAR(50), -- 'delivered', 'failed', 'undelivered', 'queued'
  carrier_status_code VARCHAR(10), -- Twilio error code (e.g., 30034 for A2P block)
  consent_confirmed BOOLEAN DEFAULT false, -- Whether user confirmed opt-in
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_action_logs_user_id ON action_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_request_id ON action_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_provider_id ON action_logs(provider_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_created_at ON action_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_logs_action_type ON action_logs(action_type);

COMMENT ON TABLE action_logs IS 'Logs all SMS/email actions with delivery tracking and compliance data';
COMMENT ON COLUMN action_logs.delivery_status IS 'Final delivery status from Twilio (delivered/failed/undelivered)';
COMMENT ON COLUMN action_logs.carrier_status_code IS 'Twilio status code for failed deliveries (for debugging and compliance)';
COMMENT ON COLUMN action_logs.consent_confirmed IS 'Whether user had confirmed SMS opt-in at time of this message';

-- Verification queries
-- Check user consent data table
SELECT 
  ucd.user_id,
  u.email,
  u.phone,
  ucd.consent_method,
  ucd.consent_ip,
  ucd.plan,
  ucd.created_at
FROM user_consent_data ucd
JOIN auth.users u ON u.id = ucd.user_id
ORDER BY ucd.created_at DESC
LIMIT 5; 
LIMIT 5;

-- Check rate limits table
SELECT COUNT(*) as total_users FROM sms_rate_limits;
