-- SMS Consent Tracking Migration
-- Purpose: Add SMS opt-in tracking for A2P 10DLC compliance
-- Created: Feb 11, 2026
-- Required by: TCPA (Telephone Consumer Protection Act) and carrier regulations

-- Add SMS consent fields to auth.users table
ALTER TABLE auth.users 
ADD COLUMN IF NOT EXISTS sms_opted_in BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS sms_consent_timestamp TIMESTAMP WITH TIME ZONE;

-- Add index for quick opt-in status lookups (used in SMS endpoint)
CREATE INDEX IF NOT EXISTS idx_users_sms_opted_in ON auth.users(sms_opted_in);

-- Add comment explaining these fields
COMMENT ON COLUMN auth.users.sms_opted_in IS 'Whether user has confirmed SMS opt-in (required for A2P 10DLC compliance)';
COMMENT ON COLUMN auth.users.sms_consent_timestamp IS 'When user confirmed SMS opt-in (for compliance audit trail)';

-- Verification query (run after migration)
-- SELECT id, email, phone, sms_opted_in, sms_consent_timestamp 
-- FROM auth.users 
-- WHERE phone IS NOT NULL 
-- ORDER BY created_at DESC 
-- LIMIT 10;
