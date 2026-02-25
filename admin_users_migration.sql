-- ============================================
-- ADMIN DASHBOARD: Admin Users Migration
-- Purpose: Define who can access admin dashboard
-- ============================================

-- Admin users table (allowlist)
CREATE TABLE IF NOT EXISTS admin_users (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  
  -- Admin level (for future role-based access control)
  admin_level VARCHAR(20) NOT NULL DEFAULT 'admin' CHECK (admin_level IN ('super_admin', 'admin', 'viewer')),
  
  -- Status
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  
  -- Metadata
  granted_by UUID REFERENCES auth.users(id), -- Who granted admin access
  granted_at TIMESTAMPTZ DEFAULT NOW(),
  notes TEXT, -- Optional notes about why this person is an admin
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_admin_users_email ON admin_users(email);
CREATE INDEX idx_admin_users_active ON admin_users(is_active) WHERE is_active = TRUE;

-- Update trigger
CREATE OR REPLACE FUNCTION update_admin_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_admin_users_updated_at
  BEFORE UPDATE ON admin_users
  FOR EACH ROW
  EXECUTE FUNCTION update_admin_users_updated_at();

-- RLS: Only allow admins to view other admins
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins can view all admin users"
  ON admin_users FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE user_id = auth.uid() AND is_active = TRUE
    )
  );

-- Function: Check if a user is an admin
CREATE OR REPLACE FUNCTION is_admin(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_is_admin BOOLEAN;
BEGIN
  SELECT EXISTS(
    SELECT 1
    FROM admin_users
    WHERE user_id = p_user_id
      AND is_active = TRUE
  ) INTO v_is_admin;
  
  RETURN v_is_admin;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Check if an email is an admin
CREATE OR REPLACE FUNCTION is_admin_email(p_email TEXT)
RETURNS BOOLEAN AS $$
DECLARE
  v_is_admin BOOLEAN;
BEGIN
  SELECT EXISTS(
    SELECT 1
    FROM admin_users
    WHERE email = p_email
      AND is_active = TRUE
  ) INTO v_is_admin;
  
  RETURN v_is_admin;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users
GRANT EXECUTE ON FUNCTION is_admin(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION is_admin_email(TEXT) TO authenticated;

-- Comments
COMMENT ON TABLE admin_users IS 'Allowlist of users who can access the admin dashboard';
COMMENT ON COLUMN admin_users.admin_level IS 'Admin permission level: super_admin (full access), admin (most actions), viewer (read-only)';
COMMENT ON COLUMN admin_users.is_active IS 'Whether this admin account is currently active';
COMMENT ON FUNCTION is_admin IS 'Check if a user_id is an active admin';
COMMENT ON FUNCTION is_admin_email IS 'Check if an email is an active admin';

-- TODO: Insert your admin email here after deployment
-- Example:
-- INSERT INTO admin_users (user_id, email, admin_level, notes)
-- SELECT id, email, 'super_admin', 'Initial admin account'
-- FROM auth.users
-- WHERE email = 'your-email@example.com'
-- ON CONFLICT (email) DO NOTHING;
