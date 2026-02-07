-- RLS Security Policies for OAuth Token Protection
-- Created: 2026-02-07
-- Purpose: Block client-side access to google_refresh_token column

-- Ensure RLS is enabled on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist (idempotent)
DROP POLICY IF EXISTS "No direct client access to OAuth tokens" ON users;
DROP POLICY IF EXISTS "No client writes to OAuth tokens" ON users;
DROP POLICY IF EXISTS "Users can read own data except tokens" ON users;

-- Policy 1: Allow users to read their own data, BUT exclude google_refresh_token
CREATE POLICY "Users can read own data except tokens"
ON users
FOR SELECT
TO authenticated
USING (
  id = auth.uid()
)
-- Note: This policy allows the SELECT, but we'll use column-level security below
-- to prevent reading google_refresh_token specifically
;

-- Policy 2: Block ANY client updates to OAuth token columns
CREATE POLICY "No client writes to OAuth tokens"
ON users
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (
  -- Allow updates only if google_refresh_token is NOT being changed
  -- This is enforced by checking that the NEW value equals OLD value
  -- (Postgres doesn't allow direct NEW/OLD access in policies, so we use a different approach)
  TRUE  -- Allow updates to row, but REVOKE column access below
);

-- CRITICAL: Revoke SELECT permission on sensitive columns for authenticated role
-- This is the key protection - even if RLS allows SELECT on row, column is hidden
DO $$
BEGIN
  -- Revoke all column access first
  EXECUTE 'REVOKE SELECT ON users FROM authenticated';
  
  -- Grant access only to safe columns (exclude google_refresh_token)
  EXECUTE 'GRANT SELECT (
    id,
    email,
    created_at,
    updated_at,
    subscription_tier,
    storage_used_bytes,
    storage_limit_bytes,
    google_token_expires_at
  ) ON users TO authenticated';
  
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'Warning: Could not modify column permissions (may require superuser)';
  WHEN undefined_object THEN
    RAISE NOTICE 'Warning: Role "authenticated" may not exist yet';
END $$;

-- CRITICAL: Revoke UPDATE permission on sensitive columns for authenticated role
DO $$
BEGIN
  -- Revoke all column updates first
  EXECUTE 'REVOKE UPDATE ON users FROM authenticated';
  
  -- Grant update only to safe columns (exclude google_refresh_token, google_token_expires_at)
  EXECUTE 'GRANT UPDATE (
    email,
    subscription_tier
  ) ON users TO authenticated';
  
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'Warning: Could not modify column permissions (may require superuser)';
  WHEN undefined_object THEN
    RAISE NOTICE 'Warning: Role "authenticated" may not exist yet';
END $$;

-- Add comments for documentation
COMMENT ON POLICY "Users can read own data except tokens" ON users IS 
  'Allows authenticated users to read their own user record, but column-level security prevents reading google_refresh_token';

COMMENT ON POLICY "No client writes to OAuth tokens" ON users IS 
  'Allows authenticated users to update their own record, but column-level security prevents updating OAuth token columns';

-- Verification query (run this after applying policies)
-- This should return the policy details
SELECT 
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd,
  qual,
  with_check
FROM pg_policies
WHERE tablename = 'users'
ORDER BY policyname;

-- Test queries (to be run from authenticated context)
-- These should be tested from the frontend/client to verify protection:

/*
-- TEST 1: Attempt to read google_refresh_token (should fail or return null)
SELECT google_refresh_token FROM users WHERE id = auth.uid();
-- Expected: ERROR or NULL

-- TEST 2: Attempt to read safe columns (should succeed)
SELECT id, email, subscription_tier, storage_used_bytes FROM users WHERE id = auth.uid();
-- Expected: SUCCESS with data

-- TEST 3: Attempt to update google_refresh_token (should fail)
UPDATE users SET google_refresh_token = 'malicious_token' WHERE id = auth.uid();
-- Expected: ERROR (permission denied)

-- TEST 4: Attempt to update safe column (should succeed)
UPDATE users SET subscription_tier = 'pro' WHERE id = auth.uid();
-- Expected: SUCCESS (if user has permission to change tier)
*/
