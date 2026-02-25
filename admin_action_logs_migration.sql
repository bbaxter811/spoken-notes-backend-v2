-- ============================================
-- ADMIN DASHBOARD: Admin Action Logs Migration
-- Purpose: Audit trail for all admin actions
-- ============================================

-- Admin action logs table
CREATE TABLE IF NOT EXISTS admin_action_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Admin who performed the action
  admin_user_id UUID NOT NULL REFERENCES auth.users(id),
  admin_email TEXT NOT NULL, -- Denormalized for easier searching
  
  -- Target of the action
  target_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL, -- NULL if action affects multiple users
  target_user_email TEXT, -- Denormalized for easier searching
  
  -- Action details
  action_type VARCHAR(100) NOT NULL, -- e.g., 'ADJUST_QUOTA', 'GRANT_CREDIT', 'OVERRIDE_ENTITLEMENT'
  action_category VARCHAR(50) NOT NULL CHECK (action_category IN ('QUOTA', 'CREDIT', 'ENTITLEMENT', 'SUBSCRIPTION', 'SYSTEM')),
  
  -- Payload (JSONB for flexibility)
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  
  -- Before/After state (for auditing changes)
  before_state JSONB DEFAULT '{}'::jsonb,
  after_state JSONB DEFAULT '{}'::jsonb,
  
  -- Required reason
  reason TEXT NOT NULL,
  
  -- Request metadata
  ip_address INET,
  user_agent TEXT,
  
  -- Timestamp
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_admin_action_logs_admin_user ON admin_action_logs(admin_user_id);
CREATE INDEX idx_admin_action_logs_target_user ON admin_action_logs(target_user_id);
CREATE INDEX idx_admin_action_logs_action_type ON admin_action_logs(action_type);
CREATE INDEX idx_admin_action_logs_category ON admin_action_logs(action_category);
CREATE INDEX idx_admin_action_logs_created ON admin_action_logs(created_at DESC);
CREATE INDEX idx_admin_action_logs_admin_email ON admin_action_logs(admin_email);
CREATE INDEX idx_admin_action_logs_target_email ON admin_action_logs(target_user_email);

-- GIN index for JSONB payload searching
CREATE INDEX idx_admin_action_logs_payload ON admin_action_logs USING GIN (payload_json);

-- Composite indexes for common queries
CREATE INDEX idx_admin_action_logs_user_time ON admin_action_logs(target_user_id, created_at DESC);
CREATE INDEX idx_admin_action_logs_admin_time ON admin_action_logs(admin_user_id, created_at DESC);

-- RLS: Only admins can view logs
ALTER TABLE admin_action_logs ENABLE ROW LEVEL SECURITY;

-- Note: Access control is enforced at API level - only users in admin_users table can query this

-- Function: Log an admin action
CREATE OR REPLACE FUNCTION log_admin_action(
  p_admin_user_id UUID,
  p_admin_email TEXT,
  p_target_user_id UUID,
  p_target_user_email TEXT,
  p_action_type VARCHAR(100),
  p_action_category VARCHAR(50),
  p_payload_json JSONB,
  p_before_state JSONB,
  p_after_state JSONB,
  p_reason TEXT,
  p_ip_address INET DEFAULT NULL,
  p_user_agent TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_log_id UUID;
BEGIN
  INSERT INTO admin_action_logs (
    admin_user_id,
    admin_email,
    target_user_id,
    target_user_email,
    action_type,
    action_category,
    payload_json,
    before_state,
    after_state,
    reason,
    ip_address,
    user_agent
  ) VALUES (
    p_admin_user_id,
    p_admin_email,
    p_target_user_id,
    p_target_user_email,
    p_action_type,
    p_action_category,
    p_payload_json,
    p_before_state,
    p_after_state,
    p_reason,
    p_ip_address,
    p_user_agent
  )
  RETURNING id INTO v_log_id;
  
  RETURN v_log_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users (API will enforce admin check)
GRANT EXECUTE ON FUNCTION log_admin_action(UUID, TEXT, UUID, TEXT, VARCHAR, VARCHAR, JSONB, JSONB, JSONB, TEXT, INET, TEXT) TO authenticated;

-- Comments for documentation
COMMENT ON TABLE admin_action_logs IS 'Audit trail of all admin actions performed in the dashboard';
COMMENT ON COLUMN admin_action_logs.action_type IS 'Specific action performed (e.g., ADJUST_QUOTA, GRANT_CREDIT)';
COMMENT ON COLUMN admin_action_logs.action_category IS 'Category of action: QUOTA, CREDIT, ENTITLEMENT, SUBSCRIPTION, or SYSTEM';
COMMENT ON COLUMN admin_action_logs.payload_json IS 'Full payload of the action (what was changed)';
COMMENT ON COLUMN admin_action_logs.before_state IS 'State before the action (for audit)';
COMMENT ON COLUMN admin_action_logs.after_state IS 'State after the action (for audit)';
COMMENT ON COLUMN admin_action_logs.reason IS 'Required explanation for why the action was performed';
COMMENT ON FUNCTION log_admin_action IS 'Log an admin action to the audit trail';
