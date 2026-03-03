-- ============================================
-- ADMIN DASHBOARD: Metrics Views (FIXED for missing columns)
-- Run this version if you get "column does not exist" errors
-- ============================================

-- First, ensure subscriptions table has correct schema
-- This is safe to run multiple times (IF NOT EXISTS)
CREATE TABLE IF NOT EXISTS subscriptions (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'free' CHECK (status IN ('free', 'active', 'past_due', 'canceled', 'trialing')),
  tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'premium')),
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add tier column if it's missing (safe to run)
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name='subscriptions' AND column_name='tier'
  ) THEN
    ALTER TABLE subscriptions ADD COLUMN tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'premium'));
  END IF;
END $$;

-- Ensure indexes exist
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer ON subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription ON subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);

-- ============================================
-- VIEW: Admin Metrics Overview (SIMPLIFIED)
-- ============================================
-- Drop existing view if it has wrong column types
DROP VIEW IF EXISTS admin_metrics_overview CASCADE;

CREATE VIEW admin_metrics_overview AS
WITH 
  -- Total users
  total_users AS (
    SELECT COUNT(DISTINCT id) as total_count
    FROM auth.users
    WHERE deleted_at IS NULL
  ),
  
  -- Daily Active Users (use auth.users for now if action_logs doesn't exist)
  dau AS (
    SELECT 
      CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'action_logs')
        THEN (SELECT COUNT(DISTINCT user_id) FROM action_logs WHERE created_at >= NOW() - INTERVAL '24 hours')
        ELSE 0
      END as dau_count
  ),
  
  -- Trial users (no subscription or status = 'trialing')
  trial_users AS (
    SELECT COUNT(*) as trial_count
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.deleted_at IS NULL
      AND (s.status IS NULL OR s.status = 'trialing' OR s.status = 'free')
  ),
  
  -- Paid users (active subscriptions, not on free tier)
  paid_users AS (
    SELECT COUNT(DISTINCT user_id) as paid_count
    FROM subscriptions
    WHERE status = 'active'
      AND (tier IS NULL OR tier != 'free')
  ),
  
  -- MRR (Monthly Recurring Revenue)
  mrr AS (
    SELECT 
      COALESCE(SUM(
        CASE 
          WHEN tier = 'pro' THEN 9.99
          WHEN tier = 'premium' THEN 19.99
          ELSE 0
        END
      ), 0) as mrr_total
    FROM subscriptions
    WHERE status = 'active'
  )
  
SELECT 
  COALESCE(tu.total_count, 0) as total_users,
  COALESCE(dau.dau_count, 0) as daily_active_users,
  0 as weekly_active_users, -- Simplified
  COALESCE(trial.trial_count, 0) as trial_users,
  COALESCE(paid.paid_count, 0) as paid_users,
  CASE 
    WHEN tu.total_count > 0 THEN ROUND((paid.paid_count::DECIMAL / tu.total_count::DECIMAL) * 100, 2)
    ELSE 0
  END as conversion_rate_pct,
  COALESCE(mrr.mrr_total, 0) as mrr_usd,
  NOW() as generated_at
FROM total_users tu, dau, trial_users trial, paid_users paid, mrr;

-- Grant select on view
GRANT SELECT ON admin_metrics_overview TO authenticated;

-- ============================================
-- VIEW: Subscription Summary (SIMPLIFIED)
-- ============================================
DROP VIEW IF EXISTS admin_subscription_summary CASCADE;

CREATE VIEW admin_subscription_summary AS
SELECT 
  COALESCE(status, 'free') as status,
  COALESCE(tier, 'free') as tier,
  COUNT(*) as user_count,
  SUM(
    CASE 
      WHEN tier = 'pro' THEN 9.99
      WHEN tier = 'premium' THEN 19.99
      ELSE 0
    END
  ) as total_mrr
FROM subscriptions
WHERE status != 'canceled'
GROUP BY status, tier
ORDER BY user_count DESC;

GRANT SELECT ON admin_subscription_summary TO authenticated;

-- ============================================
-- Comments
-- ============================================
COMMENT ON VIEW admin_metrics_overview IS 'Admin dashboard metrics - simplified version for initial setup';
COMMENT ON VIEW admin_subscription_summary IS 'Subscription breakdown by status and tier';
