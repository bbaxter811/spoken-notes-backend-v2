-- ============================================
-- ADMIN DASHBOARD: User Search Function
-- Purpose: Search users by email or name for admin dashboard
-- ============================================

CREATE OR REPLACE FUNCTION admin_search_users(
  p_search_term TEXT DEFAULT '',
  p_limit INT DEFAULT 50
)
RETURNS TABLE(
  user_id UUID,
  email TEXT,
  phone TEXT,
  created_at TIMESTAMPTZ,
  last_sign_in_at TIMESTAMPTZ,
  subscription_tier TEXT,
  storage_used_bytes BIGINT,
  storage_limit_bytes BIGINT,
  subscription_status TEXT
) 
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id as user_id,
    u.email,
    u.phone,
    u.created_at,
    u.last_sign_in_at,
    pub.subscription_tier,
    pub.storage_used_bytes,
    pub.storage_limit_bytes,
    sub.status as subscription_status
  FROM auth.users u
  LEFT JOIN public.users pub ON u.id = pub.id
  LEFT JOIN subscriptions sub ON u.id = sub.user_id
  WHERE u.deleted_at IS NULL
    AND (
      p_search_term = '' 
      OR u.email ILIKE '%' || p_search_term || '%'
      OR u.phone ILIKE '%' || p_search_term || '%'
      OR u.raw_user_meta_data->>'name' ILIKE '%' || p_search_term || '%'
    )
  ORDER BY u.created_at DESC
  LIMIT p_limit;
END;
$$;

-- Grant execute to authenticated users (will be protected by admin middleware)
GRANT EXECUTE ON FUNCTION admin_search_users(TEXT, INT) TO authenticated;

-- Add comment
COMMENT ON FUNCTION admin_search_users IS 'Search users by email or name for admin dashboard. Protected by admin authentication middleware.';
