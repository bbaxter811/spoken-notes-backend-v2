-- Quick verification queries for SMS compliance tables
-- Run these in Supabase SQL Editor to verify tables are accessible

-- 1. Verify all 3 tables exist
SELECT table_name, table_type 
FROM information_schema.tables 
WHERE table_name IN ('action_logs', 'sms_rate_limits', 'user_consent_data')
ORDER BY table_name;
-- Expected: 3 rows

-- 2. Check action_logs structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'action_logs' 
  AND column_name IN ('delivery_status', 'carrier_status_code', 'consent_confirmed')
ORDER BY column_name;
-- Expected: 3 rows

-- 3. Check sms_rate_limits structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'sms_rate_limits' 
  AND column_name IN ('minute_count', 'hour_count', 'day_count')
ORDER BY column_name;
-- Expected: 3 rows

-- 4. Check user_consent_data structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'user_consent_data' 
  AND column_name IN ('consent_method', 'consent_ip', 'plan')
ORDER BY column_name;
-- Expected: 3 rows

-- 5. Test write to action_logs (should succeed)
INSERT INTO action_logs (
  request_id,
  action_type,
  status,
  delivery_status,
  consent_confirmed
) VALUES (
  'verification-test-001',
  'test',
  'test',
  'queued',
  false
);
-- Expected: Success

-- 6. Verify test write
SELECT request_id, action_type, delivery_status, consent_confirmed, created_at
FROM action_logs
WHERE request_id = 'verification-test-001';
-- Expected: 1 row

-- 7. Clean up test data
DELETE FROM action_logs WHERE request_id = 'verification-test-001';
-- Expected: 1 row deleted

-- 8. Check current user consent data
SELECT ucd.user_id, u.email, ucd.plan, ucd.consent_method, ucd.created_at
FROM user_consent_data ucd
LEFT JOIN auth.users u ON u.id = ucd.user_id
ORDER BY ucd.created_at DESC
LIMIT 5;
-- Expected: 0 rows (until first signup with phone or SMS send)

-- ✅ All queries should run without errors
