-- ============================================
-- ADMIN DASHBOARD: Entitlement Overrides Migration
-- Purpose: Allow admins to override subscription state without affecting Stripe
-- ============================================

-- Entitlement overrides table
CREATE TABLE IF NOT EXISTS entitlement_overrides (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Override details
  override_type VARCHAR(50) NOT NULL CHECK (override_type IN ('PLAN', 'STATE', 'GRACE_PERIOD', 'QUOTAS')),
  
  -- Plan override (if override_type = 'PLAN')
  plan VARCHAR(20) CHECK (plan IN ('free', 'pro', 'plus', 'business', 'enterprise')),
  
  -- State override (if override_type = 'STATE')
  state VARCHAR(20) CHECK (state IN ('ACTIVE', 'TRIAL', 'PAST_DUE', 'TERMINATED', 'GRACE')),
  
  -- Grace period override (if override_type = 'GRACE_PERIOD')
  grace_enabled BOOLEAN,
  grace_ends_at TIMESTAMPTZ,
  
  -- Quota overrides (if override_type = 'QUOTAS')
  quota_overrides JSONB DEFAULT '{}'::jsonb, -- e.g., {"ai_minutes_limit": 1000, "storage_cap_bytes": 10737418240}
  
  -- Admin metadata
  granted_by UUID NOT NULL REFERENCES auth.users(id),
  reason TEXT NOT NULL,
  
  -- Expiry
  expires_at TIMESTAMPTZ, -- When this override expires (required for safety)
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_entitlement_overrides_user ON entitlement_overrides(user_id);
CREATE INDEX idx_entitlement_overrides_type ON entitlement_overrides(override_type);
CREATE INDEX idx_entitlement_overrides_active ON entitlement_overrides(user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_entitlement_overrides_expires ON entitlement_overrides(expires_at) WHERE expires_at IS NOT NULL;

-- GIN index for quota_overrides JSONB
CREATE INDEX idx_entitlement_overrides_quotas ON entitlement_overrides USING GIN (quota_overrides);

-- Update trigger
CREATE OR REPLACE FUNCTION update_entitlement_overrides_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_entitlement_overrides_updated_at
  BEFORE UPDATE ON entitlement_overrides
  FOR EACH ROW
  EXECUTE FUNCTION update_entitlement_overrides_updated_at();

-- RLS: Only visible to the user themselves (API enforces admin check)
ALTER TABLE entitlement_overrides ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own overrides"
  ON entitlement_overrides FOR SELECT
  USING (auth.uid() = user_id);

-- Function: Get active overrides for a user
CREATE OR REPLACE FUNCTION get_active_overrides(p_user_id UUID)
RETURNS TABLE(
  override_type VARCHAR(50),
  plan VARCHAR(20),
  state VARCHAR(20),
  grace_enabled BOOLEAN,
  grace_ends_at TIMESTAMPTZ,
  quota_overrides JSONB,
  expires_at TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    eo.override_type,
    eo.plan,
    eo.state,
    eo.grace_enabled,
    eo.grace_ends_at,
    eo.quota_overrides,
    eo.expires_at
  FROM entitlement_overrides eo
  WHERE eo.user_id = p_user_id
    AND eo.is_active = TRUE
    AND (eo.expires_at IS NULL OR eo.expires_at > NOW())
  ORDER BY eo.created_at DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Apply entitlement override
CREATE OR REPLACE FUNCTION apply_entitlement_override(
  p_user_id UUID,
  p_override_type VARCHAR(50),
  p_plan VARCHAR(20) DEFAULT NULL,
  p_state VARCHAR(20) DEFAULT NULL,
  p_grace_enabled BOOLEAN DEFAULT NULL,
  p_grace_ends_at TIMESTAMPTZ DEFAULT NULL,
  p_quota_overrides JSONB DEFAULT NULL,
  p_granted_by UUID DEFAULT NULL,
  p_reason TEXT DEFAULT NULL,
  p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_override_id UUID;
BEGIN
  -- Deactivate any existing overrides of the same type for this user
  UPDATE entitlement_overrides
  SET is_active = FALSE,
      updated_at = NOW()
  WHERE user_id = p_user_id
    AND override_type = p_override_type
    AND is_active = TRUE;
  
  -- Insert new override
  INSERT INTO entitlement_overrides (
    user_id,
    override_type,
    plan,
    state,
    grace_enabled,
    grace_ends_at,
    quota_overrides,
    granted_by,
    reason,
    expires_at
  ) VALUES (
    p_user_id,
    p_override_type,
    p_plan,
    p_state,
    p_grace_enabled,
    p_grace_ends_at,
    p_quota_overrides,
    p_granted_by,
    p_reason,
    p_expires_at
  )
  RETURNING id INTO v_override_id;
  
  RETURN v_override_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Deactivate override
CREATE OR REPLACE FUNCTION deactivate_entitlement_override(p_override_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
  UPDATE entitlement_overrides
  SET is_active = FALSE,
      updated_at = NOW()
  WHERE id = p_override_id;
  
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users
GRANT EXECUTE ON FUNCTION get_active_overrides(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION apply_entitlement_override(UUID, VARCHAR, VARCHAR, VARCHAR, BOOLEAN, TIMESTAMPTZ, JSONB, UUID, TEXT, TIMESTAMPTZ) TO authenticated;
GRANT EXECUTE ON FUNCTION deactivate_entitlement_override(UUID) TO authenticated;

-- Comments
COMMENT ON TABLE entitlement_overrides IS 'Admin overrides for user entitlements (plan, state, quotas) without affecting Stripe';
COMMENT ON COLUMN entitlement_overrides.override_type IS 'Type of override: PLAN, STATE, GRACE_PERIOD, or QUOTAS';
COMMENT ON COLUMN entitlement_overrides.expires_at IS 'When this override expires (required for safety)';
COMMENT ON COLUMN entitlement_overrides.is_active IS 'Whether this override is currently active';
COMMENT ON FUNCTION get_active_overrides IS 'Get all active (non-expired) overrides for a user';
COMMENT ON FUNCTION apply_entitlement_override IS 'Apply a new entitlement override (deactivates existing ones of same type)';
COMMENT ON FUNCTION deactivate_entitlement_override IS 'Deactivate an entitlement override';
