-- CORRECTED Migration 2: Block client access to OAuth tokens
-- Run this AFTER CORRECTED_users_table_migration.sql
-- Uses column-level security to hide google_refresh_token from clients

-- First, ensure RLS is enabled (already done in migration 1, but safe to repeat)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if present (idempotent)
DROP POLICY IF EXISTS "Users can read own profile" ON public.users;
DROP POLICY IF EXISTS "Users can update own profile" ON public.users;

-- Recreate SELECT policy (users can read their own row)
CREATE POLICY "Users can read own profile"
  ON public.users FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

-- Recreate UPDATE policy (users can update their own row)
CREATE POLICY "Users can update own profile"
  ON public.users FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- CRITICAL: Column-level security (hide OAuth tokens from authenticated role)
-- This prevents clients from reading google_refresh_token even if RLS allows row access

-- Revoke ALL column access first
REVOKE SELECT ON public.users FROM authenticated;

-- Grant SELECT only on safe columns (explicitly exclude google_refresh_token)
GRANT SELECT (
  id,
  storage_used_bytes,
  storage_limit_bytes,
  subscription_tier,
  created_at,
  updated_at
) ON public.users TO authenticated;

-- Revoke ALL column updates
REVOKE UPDATE ON public.users FROM authenticated;

-- Grant UPDATE only on safe columns (exclude OAuth tokens and storage tracking)
GRANT UPDATE (
  subscription_tier
) ON public.users TO authenticated;

-- Note: google_refresh_token and google_token_expires_at are NOT in the grants above
-- This means authenticated users (frontend) CANNOT read or write these columns
-- Only the backend (using service_role key) can access them

-- Verify column permissions (run this to check)
-- SELECT grantee, table_name, privilege_type, column_name
-- FROM information_schema.column_privileges
-- WHERE table_name = 'users' AND grantee = 'authenticated'
-- ORDER BY column_name;

-- Comments
COMMENT ON POLICY "Users can read own profile" ON public.users IS 
  'Row-level security: users can read their own profile (column grants control what fields)';
COMMENT ON POLICY "Users can update own profile" ON public.users IS 
  'Row-level security: users can update their own profile (column grants control what fields)';
