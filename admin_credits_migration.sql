-- ============================================
-- ADMIN DASHBOARD: Credits System Migration
-- Purpose: Allow admins to grant credits/comp users
-- ============================================

-- Credits table: Track manual credits granted by admins
CREATE TABLE IF NOT EXISTS user_credits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Credit details
  credit_type VARCHAR(50) NOT NULL CHECK (credit_type IN ('AI_MINUTES', 'SMS', 'STORAGE')),
  amount DECIMAL(10,2) NOT NULL, -- Amount of credit granted
  consumed DECIMAL(10,2) NOT NULL DEFAULT 0, -- Amount already consumed
  
  -- Admin metadata
  granted_by UUID NOT NULL REFERENCES auth.users(id), -- Admin who granted this
  reason TEXT NOT NULL, -- Required audit trail
  
  -- Expiry
  expires_at TIMESTAMPTZ, -- Optional expiration date
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_user_credits_user_id ON user_credits(user_id);
CREATE INDEX idx_user_credits_type ON user_credits(credit_type);
CREATE INDEX idx_user_credits_granted_by ON user_credits(granted_by);
CREATE INDEX idx_user_credits_expires ON user_credits(expires_at) WHERE expires_at IS NOT NULL;

-- Composite index for active credits lookup
CREATE INDEX idx_user_credits_active ON user_credits(user_id, credit_type, expires_at) 
  WHERE consumed < amount AND (expires_at IS NULL OR expires_at > NOW());

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_user_credits_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_user_credits_updated_at
  BEFORE UPDATE ON user_credits
  FOR EACH ROW
  EXECUTE FUNCTION update_user_credits_updated_at();

-- Function: Get available credits for a user (excluding expired)
CREATE OR REPLACE FUNCTION get_available_credits(
  p_user_id UUID,
  p_credit_type VARCHAR(50)
)
RETURNS DECIMAL(10,2) AS $$
DECLARE
  v_total_available DECIMAL(10,2);
BEGIN
  SELECT COALESCE(SUM(amount - consumed), 0)
  INTO v_total_available
  FROM user_credits
  WHERE user_id = p_user_id
    AND credit_type = p_credit_type
    AND consumed < amount
    AND (expires_at IS NULL OR expires_at > NOW());
  
  RETURN v_total_available;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Consume credits (use oldest first, FIFO)
CREATE OR REPLACE FUNCTION consume_credits(
  p_user_id UUID,
  p_credit_type VARCHAR(50),
  p_amount DECIMAL(10,2)
)
RETURNS BOOLEAN AS $$
DECLARE
  v_credit_record RECORD;
  v_remaining_to_consume DECIMAL(10,2);
  v_consumable DECIMAL(10,2);
BEGIN
  v_remaining_to_consume := p_amount;
  
  -- Loop through credits oldest first
  FOR v_credit_record IN
    SELECT id, amount, consumed
    FROM user_credits
    WHERE user_id = p_user_id
      AND credit_type = p_credit_type
      AND consumed < amount
      AND (expires_at IS NULL OR expires_at > NOW())
    ORDER BY created_at ASC
    FOR UPDATE
  LOOP
    -- Calculate how much we can consume from this credit
    v_consumable := LEAST(v_credit_record.amount - v_credit_record.consumed, v_remaining_to_consume);
    
    -- Update the credit
    UPDATE user_credits
    SET consumed = consumed + v_consumable,
        updated_at = NOW()
    WHERE id = v_credit_record.id;
    
    -- Reduce remaining amount
    v_remaining_to_consume := v_remaining_to_consume - v_consumable;
    
    -- Exit if fully consumed
    EXIT WHEN v_remaining_to_consume <= 0;
  END LOOP;
  
  -- Return true if we consumed the full amount, false otherwise
  RETURN v_remaining_to_consume <= 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Grant credits (admin action)
CREATE OR REPLACE FUNCTION grant_user_credit(
  p_user_id UUID,
  p_credit_type VARCHAR(50),
  p_amount DECIMAL(10,2),
  p_granted_by UUID,
  p_reason TEXT,
  p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_credit_id UUID;
BEGIN
  INSERT INTO user_credits (
    user_id,
    credit_type,
    amount,
    granted_by,
    reason,
    expires_at
  ) VALUES (
    p_user_id,
    p_credit_type,
    p_amount,
    p_granted_by,
    p_reason,
    p_expires_at
  )
  RETURNING id INTO v_credit_id;
  
  RETURN v_credit_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users
GRANT EXECUTE ON FUNCTION get_available_credits(UUID, VARCHAR) TO authenticated;
GRANT EXECUTE ON FUNCTION consume_credits(UUID, VARCHAR, DECIMAL) TO authenticated;
GRANT EXECUTE ON FUNCTION grant_user_credit(UUID, VARCHAR, DECIMAL, UUID, TEXT, TIMESTAMPTZ) TO authenticated;

-- Comments for documentation
COMMENT ON TABLE user_credits IS 'Manual credits granted by admins for AI minutes, SMS, or storage';
COMMENT ON COLUMN user_credits.credit_type IS 'Type of credit: AI_MINUTES, SMS, or STORAGE';
COMMENT ON COLUMN user_credits.amount IS 'Total amount of credit granted';
COMMENT ON COLUMN user_credits.consumed IS 'Amount of credit already consumed';
COMMENT ON COLUMN user_credits.granted_by IS 'UUID of admin user who granted this credit';
COMMENT ON COLUMN user_credits.reason IS 'Required audit trail explaining why credit was granted';
COMMENT ON COLUMN user_credits.expires_at IS 'Optional expiration date for the credit';
COMMENT ON FUNCTION get_available_credits IS 'Get total available (unconsumed, non-expired) credits for a user';
COMMENT ON FUNCTION consume_credits IS 'Consume credits using FIFO order (oldest first)';
COMMENT ON FUNCTION grant_user_credit IS 'Grant credits to a user (admin action)';
