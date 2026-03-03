-- ============================================
-- ADMIN DASHBOARD PHASE 2: ANALYTICS & INSIGHTS
-- Database views and functions for advanced analytics
-- ============================================

-- ============================================
-- 1. TREND ANALYSIS - Time-series data for metrics
-- ============================================

DROP FUNCTION IF EXISTS admin_get_metric_trends(TEXT, TIMESTAMPTZ, TIMESTAMPTZ) CASCADE;

CREATE OR REPLACE FUNCTION admin_get_metric_trends(
  p_metric TEXT,
  p_start_date TIMESTAMPTZ,
  p_end_date TIMESTAMPTZ
)
RETURNS TABLE(
  date DATE,
  value NUMERIC,
  change_from_previous NUMERIC,
  change_pct NUMERIC
) AS $$
BEGIN
  IF p_metric = 'dau' THEN
    RETURN QUERY
    WITH daily_counts AS (
      SELECT 
        DATE(last_sign_in_at) as date,
        COUNT(DISTINCT id) as value
      FROM auth.users
      WHERE last_sign_in_at BETWEEN p_start_date AND p_end_date
        AND deleted_at IS NULL
      GROUP BY DATE(last_sign_in_at)
      ORDER BY date
    ),
    with_changes AS (
      SELECT 
        dc.date,
        dc.value,
        dc.value - LAG(dc.value) OVER (ORDER BY dc.date) as change_from_previous
      FROM daily_counts dc
    )
    SELECT 
      wc.date,
      wc.value,
      COALESCE(wc.change_from_previous, 0) as change_from_previous,
      CASE 
        WHEN LAG(wc.value) OVER (ORDER BY wc.date) > 0 
        THEN ROUND((wc.change_from_previous / LAG(wc.value) OVER (ORDER BY wc.date)) * 100, 2)
        ELSE 0
      END as change_pct
    FROM with_changes wc;

  ELSIF p_metric = 'mrr' THEN
    RETURN QUERY
    WITH daily_mrr AS (
      SELECT 
        DATE(created_at) as date,
        SUM(
          CASE 
            WHEN tier = 'pro' THEN 9.99
            WHEN tier = 'premium' THEN 19.99
            ELSE 0
          END
        ) as value
      FROM subscriptions
      WHERE created_at BETWEEN p_start_date AND p_end_date
        AND status = 'active'
      GROUP BY DATE(created_at)
      ORDER BY date
    ),
    with_changes AS (
      SELECT 
        dm.date,
        dm.value,
        dm.value - LAG(dm.value) OVER (ORDER BY dm.date) as change_from_previous
      FROM daily_mrr dm
    )
    SELECT 
      wc.date,
      wc.value,
      COALESCE(wc.change_from_previous, 0) as change_from_previous,
      CASE 
        WHEN LAG(wc.value) OVER (ORDER BY wc.date) > 0 
        THEN ROUND((wc.change_from_previous / LAG(wc.value) OVER (ORDER BY wc.date)) * 100, 2)
        ELSE 0
      END as change_pct
    FROM with_changes wc;

  ELSIF p_metric = 'signups' THEN
    RETURN QUERY
    WITH daily_signups AS (
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as value
      FROM auth.users
      WHERE created_at BETWEEN p_start_date AND p_end_date
        AND deleted_at IS NULL
      GROUP BY DATE(created_at)
      ORDER BY date
    ),
    with_changes AS (
      SELECT 
        ds.date,
        ds.value,
        ds.value - LAG(ds.value) OVER (ORDER BY ds.date) as change_from_previous
      FROM daily_signups ds
    )
    SELECT 
      wc.date,
      wc.value,
      COALESCE(wc.change_from_previous, 0) as change_from_previous,
      CASE 
        WHEN LAG(wc.value) OVER (ORDER BY wc.date) > 0 
        THEN ROUND((wc.change_from_previous / LAG(wc.value) OVER (ORDER BY wc.date)) * 100, 2)
        ELSE 0
      END as change_pct
    FROM with_changes wc;

  ELSIF p_metric = 'churn' THEN
    RETURN QUERY
    WITH daily_cancellations AS (
      SELECT 
        DATE(updated_at) as date,
        COUNT(*) as value
      FROM subscriptions
      WHERE updated_at BETWEEN p_start_date AND p_end_date
        AND status = 'canceled'
      GROUP BY DATE(updated_at)
      ORDER BY date
    ),
    with_changes AS (
      SELECT 
        dc.date,
        dc.value,
        dc.value - LAG(dc.value) OVER (ORDER BY dc.date) as change_from_previous
      FROM daily_cancellations dc
    )
    SELECT 
      wc.date,
      wc.value,
      COALESCE(wc.change_from_previous, 0) as change_from_previous,
      CASE 
        WHEN LAG(wc.value) OVER (ORDER BY wc.date) > 0 
        THEN ROUND((wc.change_from_previous / LAG(wc.value) OVER (ORDER BY wc.date)) * 100, 2)
        ELSE 0
      END as change_pct
    FROM with_changes wc;

  ELSE
    RAISE EXCEPTION 'Unknown metric: %. Valid options: dau, mrr, signups, churn', p_metric;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 2. CHURN PREDICTION - Risk scoring for users
-- ============================================

DROP FUNCTION IF EXISTS admin_get_churn_risk_users(INT, INT) CASCADE;

CREATE OR REPLACE FUNCTION admin_get_churn_risk_users(
  p_min_risk_score INT DEFAULT 50,
  p_limit INT DEFAULT 50
)
RETURNS TABLE(
  user_id UUID,
  email TEXT,
  risk_score INT,
  risk_factors JSONB,
  last_login TIMESTAMPTZ,
  subscription_tier TEXT,
  ai_usage_trend TEXT,
  recommended_action TEXT
) AS $$
BEGIN
  RETURN QUERY
  WITH user_activity AS (
    SELECT 
      u.id,
      u.email::TEXT,
      u.last_sign_in_at,
      s.tier,
      s.status,
      pub.storage_used_bytes,
      pub.storage_limit_bytes,
      -- Days since last login
      EXTRACT(DAY FROM NOW() - COALESCE(u.last_sign_in_at, u.created_at)) as days_inactive,
      -- Storage utilization
      CASE 
        WHEN pub.storage_limit_bytes > 0 
        THEN (pub.storage_used_bytes::FLOAT / pub.storage_limit_bytes::FLOAT) * 100
        ELSE 0
      END as storage_pct
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    LEFT JOIN users pub ON u.id = pub.id
    WHERE u.deleted_at IS NULL
  ),
  risk_scores AS (
    SELECT 
      ua.id,
      ua.email,
      ua.last_sign_in_at,
      COALESCE(ua.tier, 'free') as tier,
      -- Calculate risk score (0-100)
      LEAST(100, 
        -- Inactivity score (max 40 points)
        CASE 
          WHEN ua.days_inactive > 30 THEN 40
          WHEN ua.days_inactive > 14 THEN 30
          WHEN ua.days_inactive > 7 THEN 20
          ELSE 0
        END +
        -- Storage at capacity (max 30 points)
        CASE 
          WHEN ua.storage_pct >= 100 THEN 30
          WHEN ua.storage_pct >= 90 THEN 20
          WHEN ua.storage_pct >= 80 THEN 10
          ELSE 0
        END +
        -- Subscription status (max 30 points)
        CASE 
          WHEN ua.status = 'past_due' THEN 30
          WHEN ua.status = 'canceled' THEN 25
          WHEN ua.status IS NULL THEN 15
          ELSE 0
        END
      ) as risk_score,
      -- Build risk factors JSON
      JSONB_BUILD_OBJECT(
        'days_inactive', ua.days_inactive,
        'storage_pct', ROUND(ua.storage_pct::NUMERIC, 2),
        'subscription_status', COALESCE(ua.status, 'none'),
        'tier', COALESCE(ua.tier, 'free')
      ) as risk_factors,
      -- AI usage trend (placeholder - enhance with actual data)
      CASE 
        WHEN ua.days_inactive > 14 THEN 'declining'
        WHEN ua.days_inactive > 7 THEN 'stable'
        ELSE 'active'
      END as ai_usage_trend,
      -- Recommended action
      CASE 
        WHEN ua.storage_pct >= 90 THEN 'Offer additional storage'
        WHEN ua.days_inactive > 14 THEN 'Send re-engagement email'
        WHEN ua.status = 'past_due' THEN 'Payment reminder + support'
        WHEN ua.status IS NULL THEN 'Promote paid features'
        ELSE 'Monitor closely'
      END as recommended_action
    FROM user_activity ua
  )
  SELECT 
    rs.id,
    rs.email,
    rs.risk_score::INT,
    rs.risk_factors,
    rs.last_sign_in_at,
    rs.tier,
    rs.ai_usage_trend,
    rs.recommended_action
  FROM risk_scores rs
  WHERE rs.risk_score >= p_min_risk_score
  ORDER BY rs.risk_score DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 3. REVENUE FORECASTING - Predict future MRR
-- ============================================

DROP FUNCTION IF EXISTS admin_get_revenue_forecast(INT) CASCADE;

CREATE OR REPLACE FUNCTION admin_get_revenue_forecast(
  p_months_ahead INT DEFAULT 6
)
RETURNS TABLE(
  forecast_month DATE,
  projected_mrr NUMERIC,
  projected_new_subs INT,
  projected_churn INT,
  confidence_level TEXT
) AS $$
DECLARE
  current_mrr NUMERIC;
  avg_monthly_growth NUMERIC;
  avg_new_subs NUMERIC;
  avg_churn NUMERIC;
BEGIN
  -- Calculate current MRR
  SELECT COALESCE(SUM(
    CASE 
      WHEN tier = 'pro' THEN 9.99
      WHEN tier = 'premium' THEN 19.99
      ELSE 0
    END
  ), 0) INTO current_mrr
  FROM subscriptions
  WHERE status = 'active';

  -- Calculate average monthly growth from last 3 months
  WITH monthly_mrr AS (
    SELECT 
      DATE_TRUNC('month', created_at) as month,
      SUM(
        CASE 
          WHEN tier = 'pro' THEN 9.99
          WHEN tier = 'premium' THEN 19.99
          ELSE 0
        END
      ) as mrr
    FROM subscriptions
    WHERE created_at >= NOW() - INTERVAL '3 months'
      AND status = 'active'
    GROUP BY DATE_TRUNC('month', created_at)
    ORDER BY month
  ),
  growth_rates AS (
    SELECT 
      (mrr - LAG(mrr) OVER (ORDER BY month)) / NULLIF(LAG(mrr) OVER (ORDER BY month), 0) as growth_rate
    FROM monthly_mrr
  )
  SELECT COALESCE(AVG(growth_rate), 0.05) INTO avg_monthly_growth
  FROM growth_rates
  WHERE growth_rate IS NOT NULL;

  -- Calculate average new subscriptions per month
  SELECT COALESCE(COUNT(*) / 3.0, 10) INTO avg_new_subs
  FROM subscriptions
  WHERE created_at >= NOW() - INTERVAL '3 months'
    AND status = 'active';

  -- Calculate average churn per month
  SELECT COALESCE(COUNT(*) / 3.0, 2) INTO avg_churn
  FROM subscriptions
  WHERE updated_at >= NOW() - INTERVAL '3 months'
    AND status = 'canceled';

  -- Generate forecast
  RETURN QUERY
  WITH RECURSIVE forecast_cte AS (
    -- Base case: current month
    SELECT 
      1 as month_num,
      DATE_TRUNC('month', NOW() + INTERVAL '1 month')::DATE as forecast_month,
      current_mrr * (1 + avg_monthly_growth) as projected_mrr,
      avg_new_subs::INT as projected_new_subs,
      avg_churn::INT as projected_churn,
      'high'::TEXT as confidence_level

    UNION ALL

    -- Recursive case: subsequent months
    SELECT 
      fc.month_num + 1,
      (fc.forecast_month + INTERVAL '1 month')::DATE,
      fc.projected_mrr * (1 + avg_monthly_growth),
      avg_new_subs::INT,
      avg_churn::INT,
      CASE 
        WHEN fc.month_num < 3 THEN 'high'
        WHEN fc.month_num < 6 THEN 'medium'
        ELSE 'low'
      END::TEXT
    FROM forecast_cte fc
    WHERE fc.month_num < p_months_ahead
  )
  SELECT 
    fc.forecast_month,
    ROUND(fc.projected_mrr, 2) as projected_mrr,
    fc.projected_new_subs,
    fc.projected_churn,
    fc.confidence_level
  FROM forecast_cte fc;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 4. COHORT ANALYSIS - User behavior by signup period
-- ============================================

DROP FUNCTION IF EXISTS admin_get_cohort_analysis(INT, TEXT) CASCADE;

CREATE OR REPLACE FUNCTION admin_get_cohort_analysis(
  p_months_back INT DEFAULT 6,
  p_granularity TEXT DEFAULT 'month'
)
RETURNS TABLE(
  cohort_period TEXT,
  total_users INT,
  retained_30d INT,
  retained_60d INT,
  retained_90d INT,
  retention_30d_pct NUMERIC,
  retention_60d_pct NUMERIC,
  retention_90d_pct NUMERIC,
  avg_mrr_per_user NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  WITH cohorts AS (
    SELECT 
      DATE_TRUNC(p_granularity, u.created_at) as cohort_period,
      u.id,
      u.created_at,
      COALESCE(s.tier, 'free') as tier
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.created_at >= NOW() - (p_months_back || ' months')::INTERVAL
      AND u.deleted_at IS NULL
  ),
  cohort_stats AS (
    SELECT 
      TO_CHAR(c.cohort_period, 'YYYY-MM') as cohort_period,
      COUNT(DISTINCT c.id) as total_users,
      -- Users still active after 30 days
      COUNT(DISTINCT CASE 
        WHEN EXISTS (
          SELECT 1 FROM auth.users u2 
          WHERE u2.id = c.id 
            AND u2.last_sign_in_at >= c.created_at + INTERVAL '30 days'
        ) THEN c.id 
      END) as retained_30d,
      -- Users still active after 60 days
      COUNT(DISTINCT CASE 
        WHEN EXISTS (
          SELECT 1 FROM auth.users u2 
          WHERE u2.id = c.id 
            AND u2.last_sign_in_at >= c.created_at + INTERVAL '60 days'
        ) THEN c.id 
      END) as retained_60d,
      -- Users still active after 90 days
      COUNT(DISTINCT CASE 
        WHEN EXISTS (
          SELECT 1 FROM auth.users u2 
          WHERE u2.id = c.id 
            AND u2.last_sign_in_at >= c.created_at + INTERVAL '90 days'
        ) THEN c.id 
      END) as retained_90d,
      -- Average MRR per user in cohort
      AVG(
        CASE 
          WHEN c.tier = 'pro' THEN 9.99
          WHEN c.tier = 'premium' THEN 19.99
          ELSE 0
        END
      ) as avg_mrr_per_user
    FROM cohorts c
    GROUP BY TO_CHAR(c.cohort_period, 'YYYY-MM')
    ORDER BY cohort_period DESC
  )
  SELECT 
    cs.cohort_period,
    cs.total_users::INT,
    cs.retained_30d::INT,
    cs.retained_60d::INT,
    cs.retained_90d::INT,
    ROUND((cs.retained_30d::NUMERIC / NULLIF(cs.total_users, 0)) * 100, 2) as retention_30d_pct,
    ROUND((cs.retained_60d::NUMERIC / NULLIF(cs.total_users, 0)) * 100, 2) as retention_60d_pct,
    ROUND((cs.retained_90d::NUMERIC / NULLIF(cs.total_users, 0)) * 100, 2) as retention_90d_pct,
    ROUND(cs.avg_mrr_per_user, 2) as avg_mrr_per_user
  FROM cohort_stats cs;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 5. ANOMALY DETECTION - Alert on unusual patterns
-- ============================================

DROP FUNCTION IF EXISTS admin_detect_anomalies() CASCADE;

CREATE OR REPLACE FUNCTION admin_detect_anomalies()
RETURNS TABLE(
  alert_id TEXT,
  metric_name TEXT,
  current_value NUMERIC,
  baseline_value NUMERIC,
  deviation_pct NUMERIC,
  severity TEXT,
  status TEXT,
  detected_at TIMESTAMPTZ,
  message TEXT
) AS $$
DECLARE
  current_dau INT;
  baseline_dau NUMERIC;
  dau_deviation NUMERIC;
  current_signups INT;
  baseline_signups NUMERIC;
  signup_deviation NUMERIC;
BEGIN
  -- Check DAU anomaly
  SELECT COUNT(DISTINCT id) INTO current_dau
  FROM auth.users
  WHERE last_sign_in_at >= NOW() - INTERVAL '24 hours'
    AND deleted_at IS NULL;

  SELECT AVG(daily_count) INTO baseline_dau
  FROM (
    SELECT DATE(last_sign_in_at) as date, COUNT(DISTINCT id) as daily_count
    FROM auth.users
    WHERE last_sign_in_at >= NOW() - INTERVAL '7 days'
      AND last_sign_in_at < NOW() - INTERVAL '1 day'
      AND deleted_at IS NULL
    GROUP BY DATE(last_sign_in_at)
  ) avg_dau;

  dau_deviation := ((current_dau - COALESCE(baseline_dau, current_dau)) / NULLIF(baseline_dau, 0)) * 100;

  -- Check signups anomaly
  SELECT COUNT(*) INTO current_signups
  FROM auth.users
  WHERE created_at >= NOW() - INTERVAL '24 hours'
    AND deleted_at IS NULL;

  SELECT AVG(daily_count) INTO baseline_signups
  FROM (
    SELECT DATE(created_at) as date, COUNT(*) as daily_count
    FROM auth.users
    WHERE created_at >= NOW() - INTERVAL '7 days'
      AND created_at < NOW() - INTERVAL '1 day'
      AND deleted_at IS NULL
    GROUP BY DATE(created_at)
  ) avg_signups;

  signup_deviation := ((current_signups - COALESCE(baseline_signups, current_signups)) / NULLIF(baseline_signups, 0)) * 100;

  -- Return alerts for significant deviations
  RETURN QUERY
  SELECT 
    'dau_' || TO_CHAR(NOW(), 'YYYYMMDD') as alert_id,
    'daily_active_users' as metric_name,
    current_dau::NUMERIC as current_value,
    COALESCE(baseline_dau, 0) as baseline_value,
    ROUND(dau_deviation, 2) as deviation_pct,
    CASE 
      WHEN ABS(dau_deviation) >= 50 THEN 'critical'
      WHEN ABS(dau_deviation) >= 25 THEN 'high'
      ELSE 'medium'
    END as severity,
    'active' as status,
    NOW() as detected_at,
    CASE 
      WHEN dau_deviation < 0 THEN 'DAU dropped ' || ABS(ROUND(dau_deviation, 0))::TEXT || '% - investigate immediately'
      ELSE 'DAU spiked ' || ROUND(dau_deviation, 0)::TEXT || '% - verify legitimate traffic'
    END as message
  WHERE ABS(dau_deviation) >= 25

  UNION ALL

  SELECT 
    'signups_' || TO_CHAR(NOW(), 'YYYYMMDD') as alert_id,
    'new_signups' as metric_name,
    current_signups::NUMERIC as current_value,
    COALESCE(baseline_signups, 0) as baseline_value,
    ROUND(signup_deviation, 2) as deviation_pct,
    CASE 
      WHEN ABS(signup_deviation) >= 50 THEN 'critical'
      WHEN ABS(signup_deviation) >= 25 THEN 'high'
      ELSE 'medium'
    END as severity,
    'active' as status,
    NOW() as detected_at,
    CASE 
      WHEN signup_deviation < -50 THEN 'Signups dropped ' || ABS(ROUND(signup_deviation, 0))::TEXT || '% - check signup flow'
      WHEN signup_deviation < 0 THEN 'Signups declining ' || ABS(ROUND(signup_deviation, 0))::TEXT || '%'
      ELSE 'Signups increased ' || ROUND(signup_deviation, 0)::TEXT || '%'
    END as message
  WHERE ABS(signup_deviation) >= 25;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 6. USER SEGMENTATION - View for user segments
-- ============================================

DROP VIEW IF EXISTS admin_user_segments CASCADE;

CREATE VIEW admin_user_segments AS
WITH segment_data AS (
  SELECT 
    u.id,
    u.email::TEXT,
    u.created_at,
    u.last_sign_in_at,
    COALESCE(s.tier, 'free') as tier,
    s.status as sub_status,
    pub.storage_used_bytes,
    pub.storage_limit_bytes,
    -- Days since signup
    EXTRACT(DAY FROM NOW() - u.created_at) as days_since_signup,
    -- Days since last login
    EXTRACT(DAY FROM NOW() - COALESCE(u.last_sign_in_at, u.created_at)) as days_inactive,
    -- Storage percentage
    CASE 
      WHEN pub.storage_limit_bytes > 0 
      THEN (pub.storage_used_bytes::FLOAT / pub.storage_limit_bytes::FLOAT) * 100
      ELSE 0
    END as storage_pct
  FROM auth.users u
  LEFT JOIN subscriptions s ON u.id = s.user_id
  LEFT JOIN users pub ON u.id = pub.id
  WHERE u.deleted_at IS NULL
)
SELECT 
  'power_users' as segment_name,
  'Top 10% by engagement' as description,
  COUNT(*) as user_count,
  ROUND(AVG(
    CASE 
      WHEN tier = 'pro' THEN 9.99
      WHEN tier = 'premium' THEN 19.99
      ELSE 0
    END
  ), 2) as avg_revenue_per_user
FROM segment_data
WHERE days_inactive <= 1 AND tier IN ('pro', 'premium')

UNION ALL

SELECT 
  'at_risk' as segment_name,
  'Low usage + nearing storage limit' as description,
  COUNT(*) as user_count,
  ROUND(AVG(
    CASE 
      WHEN tier = 'pro' THEN 9.99
      WHEN tier = 'premium' THEN 19.99
      ELSE 0
    END
  ), 2) as avg_revenue_per_user
FROM segment_data
WHERE days_inactive > 7 AND storage_pct >= 80

UNION ALL

SELECT 
  'free_riders' as segment_name,
  'Free tier for 90+ days' as description,
  COUNT(*) as user_count,
  0 as avg_revenue_per_user
FROM segment_data
WHERE tier = 'free' AND days_since_signup >= 90

UNION ALL

SELECT 
  'advocates' as segment_name,
  'High usage + long tenure (180+ days)' as description,
  COUNT(*) as user_count,
  ROUND(AVG(
    CASE 
      WHEN tier = 'pro' THEN 9.99
      WHEN tier = 'premium' THEN 19.99
      ELSE 0
    END
  ), 2) as avg_revenue_per_user
FROM segment_data
WHERE days_since_signup >= 180 AND days_inactive <= 7;

GRANT SELECT ON admin_user_segments TO authenticated;

-- ============================================
-- Helper function to get users in a segment
-- ============================================

DROP FUNCTION IF EXISTS admin_get_segment_users(TEXT) CASCADE;

CREATE OR REPLACE FUNCTION admin_get_segment_users(
  p_segment_name TEXT
)
RETURNS TABLE(
  user_id UUID,
  email TEXT,
  created_at TIMESTAMPTZ,
  subscription_tier TEXT
) AS $$
BEGIN
  IF p_segment_name = 'power_users' THEN
    RETURN QUERY
    SELECT 
      u.id,
      u.email::TEXT,
      u.created_at,
      COALESCE(s.tier, 'free')
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.deleted_at IS NULL
      AND EXTRACT(DAY FROM NOW() - COALESCE(u.last_sign_in_at, u.created_at)) <= 1
      AND COALESCE(s.tier, 'free') IN ('pro', 'premium');

  ELSIF p_segment_name = 'at_risk' THEN
    RETURN QUERY
    SELECT 
      u.id,
      u.email::TEXT,
      u.created_at,
      COALESCE(s.tier, 'free')
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    LEFT JOIN users pub ON u.id = pub.id
    WHERE u.deleted_at IS NULL
      AND EXTRACT(DAY FROM NOW() - COALESCE(u.last_sign_in_at, u.created_at)) > 7
      AND (pub.storage_used_bytes::FLOAT / NULLIF(pub.storage_limit_bytes, 1)) >= 0.8;

  ELSIF p_segment_name = 'free_riders' THEN
    RETURN QUERY
    SELECT 
      u.id,
      u.email::TEXT,
      u.created_at,
      'free' as subscription_tier
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.deleted_at IS NULL
      AND COALESCE(s.tier, 'free') = 'free'
      AND EXTRACT(DAY FROM NOW() - u.created_at) >= 90;

  ELSIF p_segment_name = 'advocates' THEN
    RETURN QUERY
    SELECT 
      u.id,
      u.email::TEXT,
      u.created_at,
      COALESCE(s.tier, 'free')
    FROM auth.users u
    LEFT JOIN subscriptions s ON u.id = s.user_id
    WHERE u.deleted_at IS NULL
      AND EXTRACT(DAY FROM NOW() - u.created_at) >= 180
      AND EXTRACT(DAY FROM NOW() - COALESCE(u.last_sign_in_at, u.created_at)) <= 7;

  ELSE
    RAISE EXCEPTION 'Unknown segment: %', p_segment_name;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 7. COMPARATIVE BENCHMARKING - Compare periods
-- ============================================

DROP FUNCTION IF EXISTS admin_compare_metric(TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ) CASCADE;

CREATE OR REPLACE FUNCTION admin_compare_metric(
  p_metric_name TEXT,
  p_current_start TIMESTAMPTZ,
  p_current_end TIMESTAMPTZ,
  p_previous_start TIMESTAMPTZ,
  p_previous_end TIMESTAMPTZ
)
RETURNS TABLE(
  current_value NUMERIC,
  previous_value NUMERIC,
  absolute_change NUMERIC,
  percent_change NUMERIC,
  trend TEXT
) AS $$
DECLARE
  v_current NUMERIC;
  v_previous NUMERIC;
  v_change NUMERIC;
  v_pct NUMERIC;
BEGIN
  IF p_metric_name = 'users' THEN
    SELECT COUNT(*) INTO v_current
    FROM auth.users
    WHERE created_at BETWEEN p_current_start AND p_current_end
      AND deleted_at IS NULL;

    SELECT COUNT(*) INTO v_previous
    FROM auth.users
    WHERE created_at BETWEEN p_previous_start AND p_previous_end
      AND deleted_at IS NULL;

  ELSIF p_metric_name = 'mrr' THEN
    SELECT COALESCE(SUM(
      CASE 
        WHEN tier = 'pro' THEN 9.99
        WHEN tier = 'premium' THEN 19.99
        ELSE 0
      END
    ), 0) INTO v_current
    FROM subscriptions
    WHERE created_at BETWEEN p_current_start AND p_current_end
      AND status = 'active';

    SELECT COALESCE(SUM(
      CASE 
        WHEN tier = 'pro' THEN 9.99
        WHEN tier = 'premium' THEN 19.99
        ELSE 0
      END
    ), 0) INTO v_previous
    FROM subscriptions
    WHERE created_at BETWEEN p_previous_start AND p_previous_end
      AND status = 'active';

  ELSIF p_metric_name = 'dau' THEN
    SELECT COUNT(DISTINCT id) INTO v_current
    FROM auth.users
    WHERE last_sign_in_at BETWEEN p_current_start AND p_current_end
      AND deleted_at IS NULL;

    SELECT COUNT(DISTINCT id) INTO v_previous
    FROM auth.users
    WHERE last_sign_in_at BETWEEN p_previous_start AND p_previous_end
      AND deleted_at IS NULL;

  ELSE
    RAISE EXCEPTION 'Unknown metric: %', p_metric_name;
  END IF;

  v_change := v_current - v_previous;
  v_pct := CASE 
    WHEN v_previous > 0 THEN (v_change / v_previous) * 100
    ELSE 0
  END;

  RETURN QUERY
  SELECT 
    v_current as current_value,
    v_previous as previous_value,
    v_change as absolute_change,
    ROUND(v_pct, 2) as percent_change,
    CASE 
      WHEN v_change > 0 THEN 'up'
      WHEN v_change < 0 THEN 'down'
      ELSE 'stable'
    END::TEXT as trend;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- Grant permissions
-- ============================================

GRANT EXECUTE ON FUNCTION admin_get_metric_trends(TEXT, TIMESTAMPTZ, TIMESTAMPTZ) TO authenticated;
GRANT EXECUTE ON FUNCTION admin_get_churn_risk_users(INT, INT) TO authenticated;
GRANT EXECUTE ON FUNCTION admin_get_revenue_forecast(INT) TO authenticated;
GRANT EXECUTE ON FUNCTION admin_get_cohort_analysis(INT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION admin_detect_anomalies() TO authenticated;
GRANT EXECUTE ON FUNCTION admin_get_segment_users(TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION admin_compare_metric(TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ) TO authenticated;

-- ============================================
-- Comments
-- ============================================

COMMENT ON FUNCTION admin_get_metric_trends IS 'Phase 2: Returns time-series data for trends (dau, mrr, signups, churn)';
COMMENT ON FUNCTION admin_get_churn_risk_users IS 'Phase 2: Identifies users at risk of cancellation with risk scores';
COMMENT ON FUNCTION admin_get_revenue_forecast IS 'Phase 2: Projects future MRR based on historical growth patterns';
COMMENT ON FUNCTION admin_get_cohort_analysis IS 'Phase 2: Analyzes user retention and behavior by signup cohort';
COMMENT ON FUNCTION admin_detect_anomalies IS 'Phase 2: Detects unusual metric deviations for alerting';
COMMENT ON VIEW admin_user_segments IS 'Phase 2: User segmentation for targeted campaigns';
COMMENT ON FUNCTION admin_get_segment_users IS 'Phase 2: Returns users in a specific segment for export';
COMMENT ON FUNCTION admin_compare_metric IS 'Phase 2: Compares metric values between two time periods';
