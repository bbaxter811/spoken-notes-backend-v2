-- ============================================
-- ADMIN DASHBOARD: Metrics Views & Queries
-- Purpose: Provide aggregated metrics for admin dashboard
-- ============================================

-- ============================================
-- VIEW: Admin Metrics Overview
-- ============================================
CREATE OR REPLACE VIEW admin_metrics_overview AS
WITH 
  -- Total users
  total_users AS (
    SELECT COUNT(DISTINCT id) as total_count
    FROM auth.users
    WHERE deleted_at IS NULL
  ),
  
  -- Daily Active Users (last 24 hours)
  dau AS (
    SELECT COUNT(DISTINCT user_id) as dau_count
    FROM action_logs
    WHERE created_at >= NOW() - INTERVAL '24 hours'
  ),
  
  -- Weekly Active Users (last 7 days)
  wau AS (
    SELECT COUNT(DISTINCT user_id) as wau_count
    FROM action_logs
    WHERE created_at >= NOW() - INTERVAL '7 days'
  ),
  
  -- Trial users (no subscription or status = 'trialing')
  trial_users AS (
    SELECT COUNT(*) as trial_count
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.deleted_at IS NULL
      AND (s.status IS NULL OR s.status = 'trialing' OR s.status = 'free')
  ),
  
  -- Paid users (active subscriptions)
  paid_users AS (
    SELECT COUNT(DISTINCT user_id) as paid_count
    FROM subscriptions
    WHERE status = 'active'
      AND tier != 'free'
  ),
  
  -- Conversion rate
  conversion AS (
    SELECT 
      CASE 
        WHEN total_count > 0 THEN ROUND((paid_count::DECIMAL / total_count::DECIMAL) * 100, 2)
        ELSE 0
      END as conversion_rate
    FROM total_users, paid_users
  ),
  
  -- MRR (Monthly Recurring Revenue) - estimated from Stripe price IDs
  -- This is a simplified calculation, adjust based on your pricing
  mrr AS (
    SELECT 
      SUM(
        CASE 
          WHEN s.tier = 'pro' THEN 9.99
          WHEN s.tier = 'premium' THEN 19.99
          ELSE 0
        END
      ) as mrr_total
    FROM subscriptions s
    WHERE s.status = 'active'
  )
  
SELECT 
  tu.total_count as total_users,
  dau.dau_count as daily_active_users,
  wau.wau_count as weekly_active_users,
  trial.trial_count as trial_users,
  paid.paid_count as paid_users,
  conv.conversion_rate as conversion_rate_pct,
  mrr.mrr_total as mrr_usd
FROM total_users tu, dau, wau, trial_users trial, paid_users paid, conversion conv, mrr;

-- ============================================
-- VIEW: User Detail Summary (for user list/search)
-- ============================================
CREATE OR REPLACE VIEW admin_user_summary AS
SELECT 
  u.id as user_id,
  u.email,
  u.created_at as user_created_at,
  
  -- Subscription info
  s.tier as subscription_tier,
  s.status as subscription_status,
  s.current_period_end as subscription_period_end,
  
  -- Usage stats (current month)
  COALESCE(ai.ai_minutes_used, 0) as ai_minutes_used_this_month,
  COALESCE(pub.storage_used_bytes, 0) as storage_used_bytes,
  COALESCE(pub.storage_limit_bytes, 104857600) as storage_limit_bytes,
  
  -- SMS usage (if SMS tables exist)
  0 as sms_sent_this_month, -- TODO: Update if you have SMS tracking
  
  -- Activity
  (
    SELECT MAX(created_at)
    FROM action_logs
    WHERE user_id = u.id
  ) as last_active_at,
  
  -- Device info (from latest action log)
  (
    SELECT metadata_json->>'device'
    FROM action_logs
    WHERE user_id = u.id
    ORDER BY created_at DESC
    LIMIT 1
  ) as device_info

FROM auth.users u
LEFT JOIN subscriptions s ON u.id = s.user_id
LEFT JOIN public.users pub ON u.id = pub.id
LEFT JOIN user_ai_usage_monthly ai ON u.id = ai.user_id 
  AND ai.month = DATE_TRUNC('month', NOW())
WHERE u.deleted_at IS NULL
ORDER BY u.created_at DESC;

-- ============================================
-- VIEW: Top AI Users (by usage this month)
-- ============================================
CREATE OR REPLACE VIEW admin_top_ai_users AS
SELECT 
  u.id as user_id,
  u.email,
  ai.ai_minutes_used,
  ai.month,
  s.tier as subscription_tier,
  s.status as subscription_status
FROM user_ai_usage_monthly ai
JOIN auth.users u ON ai.user_id = u.id
LEFT JOIN subscriptions s ON u.id = s.user_id
WHERE ai.month = DATE_TRUNC('month', NOW())
  AND u.deleted_at IS NULL
ORDER BY ai.ai_minutes_used DESC
LIMIT 100;

-- ============================================
-- VIEW: Top Storage Users
-- ============================================
CREATE OR REPLACE VIEW admin_top_storage_users AS
SELECT 
  u.id as user_id,
  u.email,
  pub.storage_used_bytes,
  pub.storage_limit_bytes,
  ROUND((pub.storage_used_bytes::DECIMAL / pub.storage_limit_bytes::DECIMAL) * 100, 2) as storage_usage_pct,
  s.tier as subscription_tier,
  s.status as subscription_status
FROM public.users pub
JOIN auth.users u ON pub.id = u.id
LEFT JOIN subscriptions s ON u.id = s.user_id
WHERE u.deleted_at IS NULL
  AND pub.storage_used_bytes > 0
ORDER BY pub.storage_used_bytes DESC
LIMIT 100;

-- ============================================
-- VIEW: Subscription State Summary
-- ============================================
CREATE OR REPLACE VIEW admin_subscription_summary AS
SELECT 
  s.status,
  s.tier,
  COUNT(*) as user_count,
  SUM(
    CASE 
      WHEN s.tier = 'pro' THEN 9.99
      WHEN s.tier = 'premium' THEN 19.99
      ELSE 0
    END
  ) as total_mrr
FROM subscriptions s
WHERE s.status != 'canceled'
GROUP BY s.status, s.tier
ORDER BY user_count DESC;

-- ============================================
-- VIEW: Admin Actions Summary (recent activity)
-- ============================================
CREATE OR REPLACE VIEW admin_recent_actions AS
SELECT 
  aal.id,
  aal.admin_email,
  aal.target_user_email,
  aal.action_type,
  aal.action_category,
  aal.reason,
  aal.created_at
FROM admin_action_logs aal
ORDER BY aal.created_at DESC
LIMIT 100;

-- ============================================
-- FUNCTION: Get User Detail (for user detail page)
-- ============================================
CREATE OR REPLACE FUNCTION admin_get_user_detail(p_user_id UUID)
RETURNS JSON AS $$
DECLARE
  v_result JSON;
BEGIN
  SELECT json_build_object(
    'user_id', u.id,
    'email', u.email,
    'created_at', u.created_at,
    'last_active_at', (
      SELECT MAX(created_at)
      FROM action_logs
      WHERE user_id = u.id
    ),
    
    -- Subscription
    'subscription', json_build_object(
      'tier', s.tier,
      'status', s.status,
      'stripe_customer_id', s.stripe_customer_id,
      'stripe_subscription_id', s.stripe_subscription_id,
      'current_period_start', s.current_period_start,
      'current_period_end', s.current_period_end
    ),
    
    -- Usage (current month)
    'usage', json_build_object(
      'ai_minutes_used', COALESCE(ai.ai_minutes_used, 0),
      'storage_used_bytes', COALESCE(pub.storage_used_bytes, 0),
      'storage_limit_bytes', COALESCE(pub.storage_limit_bytes, 104857600),
      'sms_sent', 0
    ),
    
    -- Credits
    'credits', (
      SELECT json_agg(json_build_object(
        'id', uc.id,
        'credit_type', uc.credit_type,
        'amount', uc.amount,
        'consumed', uc.consumed,
        'remaining', uc.amount - uc.consumed,
        'expires_at', uc.expires_at,
        'granted_by', uc.granted_by,
        'reason', uc.reason,
        'created_at', uc.created_at
      ))
      FROM user_credits uc
      WHERE uc.user_id = u.id
        AND uc.consumed < uc.amount
        AND (uc.expires_at IS NULL OR uc.expires_at > NOW())
    ),
    
    -- Entitlement overrides
    'overrides', (
      SELECT json_agg(json_build_object(
        'id', eo.id,
        'override_type', eo.override_type,
        'plan', eo.plan,
        'state', eo.state,
        'expires_at', eo.expires_at,
        'reason', eo.reason,
        'created_at', eo.created_at
      ))
      FROM entitlement_overrides eo
      WHERE eo.user_id = u.id
        AND eo.is_active = TRUE
        AND (eo.expires_at IS NULL OR eo.expires_at > NOW())
    ),
    
    -- Recent activity (last 10 actions)
    'recent_activity', (
      SELECT json_agg(json_build_object(
        'action', al.action,
        'metadata', al.metadata_json,
        'created_at', al.created_at
      ))
      FROM (
        SELECT action, metadata_json, created_at
        FROM action_logs
        WHERE user_id = u.id
        ORDER BY created_at DESC
        LIMIT 10
      ) al
    )
  )
  INTO v_result
  FROM auth.users u
  LEFT JOIN subscriptions s ON u.id = s.user_id
  LEFT JOIN public.users pub ON u.id = pub.id
  LEFT JOIN user_ai_usage_monthly ai ON u.id = ai.user_id 
    AND ai.month = DATE_TRUNC('month', NOW())
  WHERE u.id = p_user_id;
  
  RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users (API will enforce admin check)
GRANT EXECUTE ON FUNCTION admin_get_user_detail(UUID) TO authenticated;

-- ============================================
-- FUNCTION: Search Users (for user search)
-- ============================================
CREATE OR REPLACE FUNCTION admin_search_users(p_search_term TEXT, p_limit INTEGER DEFAULT 50)
RETURNS TABLE(
  user_id UUID,
  email TEXT,
  subscription_tier TEXT,
  subscription_status TEXT,
  ai_minutes_used DECIMAL,
  storage_used_bytes BIGINT,
  last_active_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id,
    u.email,
    s.tier,
    s.status,
    COALESCE(ai.ai_minutes_used, 0),
    COALESCE(pub.storage_used_bytes, 0),
    (SELECT MAX(created_at) FROM action_logs WHERE user_id = u.id),
    u.created_at
  FROM auth.users u
  LEFT JOIN subscriptions s ON u.id = s.user_id
  LEFT JOIN public.users pub ON u.id = pub.id
  LEFT JOIN user_ai_usage_monthly ai ON u.id = ai.user_id 
    AND ai.month = DATE_TRUNC('month', NOW())
  WHERE u.deleted_at IS NULL
    AND (
      u.email ILIKE '%' || p_search_term || '%'
      OR u.id::TEXT = p_search_term
    )
  ORDER BY u.created_at DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to authenticated users
GRANT EXECUTE ON FUNCTION admin_search_users(TEXT, INTEGER) TO authenticated;

-- Comments
COMMENT ON VIEW admin_metrics_overview IS 'High-level metrics for admin dashboard overview page';
COMMENT ON VIEW admin_user_summary IS 'User list with subscription and usage summary';
COMMENT ON VIEW admin_top_ai_users IS 'Top 100 users by AI minutes usage this month';
COMMENT ON VIEW admin_top_storage_users IS 'Top 100 users by storage usage';
COMMENT ON VIEW admin_subscription_summary IS 'Subscription status breakdown';
COMMENT ON VIEW admin_recent_actions IS 'Recent admin actions (last 100)';
COMMENT ON FUNCTION admin_get_user_detail IS 'Get complete user detail for admin user detail page';
COMMENT ON FUNCTION admin_search_users IS 'Search users by email or user_id';
