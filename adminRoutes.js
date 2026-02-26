// ============================================================================
// ADMIN DASHBOARD API ROUTES
// Protected by admin authentication middleware
// ============================================================================

const express = require('express');
const router = express.Router();

// ============================================================================
// ADMIN AUTHENTICATION MIDDLEWARE
// ============================================================================

/**
 * Admin authentication middleware
 * Checks if user is authenticated AND has admin privileges
 */
async function authenticateAdmin(req, res, next) {
  try {
    // First, check if user is authenticated via Supabase
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No authorization token provided' });
    }

    const token = authHeader.substring(7);

    // Verify token with Supabase
    const { data: { user }, error } = await req.supabaseAdmin.auth.getUser(token);

    if (error || !user) {
      console.error('❌ Admin auth failed - invalid token:', error);
      return res.status(401).json({ error: 'Invalid token' });
    }

    console.log('[AUTH_ADMIN] JWT validated. userId=', user.id, 'email=', user.email);

    // Check if user is an admin
    console.log('[AUTH_ADMIN] Querying table=admin_users for userId=', user.id);
    const { data: adminUser, error: adminError } = await req.supabaseAdmin
      .from('admin_users')
      .select('*')
      .eq('user_id', user.id)
      .eq('is_active', true)
      .single();

    if (adminError) {
      console.error('[AUTH_ADMIN] Supabase query error:', {
        userId: user.id,
        email: user.email,
        table: 'admin_users',
        errorCode: adminError.code,
        errorMessage: adminError.message,
        errorDetails: adminError.details,
        errorHint: adminError.hint
      });
      return res.status(403).json({ 
        error: 'Admin access denied', 
        detail: adminError.message,
        code: adminError.code
      });
    }

    if (!adminUser) {
      console.error('[AUTH_ADMIN] No admin record found for userId=', user.id, 'email=', user.email);
      return res.status(403).json({ error: 'Access denied - not in admin allowlist' });
    }

    // Attach user and admin info to request
    req.user = user;
    req.admin = adminUser;

    console.log(`✅ Admin authenticated: ${user.email} (${adminUser.admin_level})`);

    next();
  } catch (err) {
    console.error('❌ Admin authentication error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
}

// ============================================================================
// ADMIN LOGGING HELPER
// ============================================================================

/**
 * Log admin action to audit trail
 */
async function logAdminAction(supabaseAdmin, adminUser, targetUserId, targetUserEmail, actionType, actionCategory, payload, beforeState, afterState, reason, ipAddress, userAgent) {
  try {
    const { data, error } = await supabaseAdmin.rpc('log_admin_action', {
      p_admin_user_id: adminUser.user_id,
      p_admin_email: adminUser.email,
      p_target_user_id: targetUserId,
      p_target_user_email: targetUserEmail,
      p_action_type: actionType,
      p_action_category: actionCategory,
      p_payload_json: payload,
      p_before_state: beforeState,
      p_after_state: afterState,
      p_reason: reason,
      p_ip_address: ipAddress,
      p_user_agent: userAgent
    });

    if (error) {
      console.error('❌ Failed to log admin action:', error);
    } else {
      console.log(`✅ Admin action logged: ${actionType} by ${adminUser.email}`);
    }
  } catch (err) {
    console.error('❌ Admin logging error:', err);
  }
}

// ============================================================================
// HEALTH CHECK ENDPOINT (NO AUTH REQUIRED)
// ============================================================================

/**
 * GET /admin/health
 * Health check endpoint for admin routes (no authentication required)
 */
router.get('/health', async (req, res) => {
  try {
    res.status(200).json({
      status: 'ok',
      service: 'admin-routes',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      error: err.message
    });
  }
});

// ============================================================================
// METRICS ENDPOINTS
// ============================================================================

/**
 * GET /admin/metrics/overview
 * Get high-level metrics for dashboard overview
 */
router.get('/metrics/overview', authenticateAdmin, async (req, res) => {
  try {
    console.log(`📊 Admin metrics overview request from ${req.admin.email}`);

    // Query the admin_metrics_overview view
    const { data, error } = await req.supabaseAdmin
      .from('admin_metrics_overview')
      .select('*')
      .single();

    if (error) {
      console.error('❌ Metrics query error:', error);
      return res.status(500).json({ error: 'Failed to fetch metrics' });
    }

    res.json({
      success: true,
      metrics: data
    });

  } catch (err) {
    console.error('❌ Admin metrics error:', err);
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

/**
 * GET /admin/metrics/ai-usage
 * Get AI usage summary and top users
 */
router.get('/metrics/ai-usage', authenticateAdmin, async (req, res) => {
  try {
    console.log(`📊 Admin AI usage metrics request from ${req.admin.email}`);

    // Get top AI users this month
    const { data: topUsers, error } = await req.supabaseAdmin
      .from('admin_top_ai_users')
      .select('*')
      .limit(100);

    if (error) {
      console.error('❌ AI usage query error:', error);
      return res.status(500).json({ error: 'Failed to fetch AI usage' });
    }

    // Calculate total AI minutes used this month
    const totalMinutes = topUsers.reduce((sum, user) => sum + parseFloat(user.ai_minutes_used || 0), 0);

    res.json({
      success: true,
      total_ai_minutes_this_month: totalMinutes,
      top_users: topUsers
    });

  } catch (err) {
    console.error('❌ Admin AI usage metrics error:', err);
    res.status(500).json({ error: 'Failed to fetch AI usage metrics' });
  }
});

/**
 * GET /admin/metrics/storage
 * Get storage usage summary and top users
 */
router.get('/metrics/storage', authenticateAdmin, async (req, res) => {
  try {
    console.log(`📊 Admin storage metrics request from ${req.admin.email}`);

    // Get top storage users
    const { data: topUsers, error } = await req.supabaseAdmin
      .from('admin_top_storage_users')
      .select('*')
      .limit(100);

    if (error) {
      console.error('❌ Storage query error:', error);
      return res.status(500).json({ error: 'Failed to fetch storage usage' });
    }

    // Calculate total storage used
    const totalBytes = topUsers.reduce((sum, user) => sum + parseInt(user.storage_used_bytes || 0), 0);

    res.json({
      success: true,
      total_storage_bytes: totalBytes,
      top_users: topUsers
    });

  } catch (err) {
    console.error('❌ Admin storage metrics error:', err);
    res.status(500).json({ error: 'Failed to fetch storage metrics' });
  }
});

/**
 * GET /admin/metrics/subscriptions
 * Get subscription status breakdown
 */
router.get('/metrics/subscriptions', authenticateAdmin, async (req, res) => {
  try {
    console.log(`📊 Admin subscription metrics request from ${req.admin.email}`);

    // Query subscription summary
    const { data, error } = await req.supabaseAdmin
      .from('admin_subscription_summary')
      .select('*');

    if (error) {
      console.error('❌ Subscription query error:', error);
      return res.status(500).json({ error: 'Failed to fetch subscription metrics' });
    }

    res.json({
      success: true,
      subscriptions: data
    });

  } catch (err) {
    console.error('❌ Admin subscription metrics error:', err);
    res.status(500).json({ error: 'Failed to fetch subscription metrics' });
  }
});

// ============================================================================
// USER MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * GET /admin/users
 * Search/list users
 */
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const searchTerm = req.query.search || '';
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);

    console.log(`🔍 Admin user search: "${searchTerm}" (limit ${limit})`);

    // Use the admin_search_users function
    const { data, error } = await req.supabaseAdmin.rpc('admin_search_users', {
      p_search_term: searchTerm,
      p_limit: limit
    });

    if (error) {
      console.error('❌ User search error:', error);
      return res.status(500).json({ error: 'Failed to search users' });
    }

    res.json({
      success: true,
      users: data || []
    });

  } catch (err) {
    console.error('❌ Admin user search error:', err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

/**
 * GET /admin/users/:id
 * Get detailed user information
 */
router.get('/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    console.log(`👤 Admin user detail request: ${userId}`);

    // Use the admin_get_user_detail function
    const { data, error } = await req.supabaseAdmin.rpc('admin_get_user_detail', {
      p_user_id: userId
    });

    if (error) {
      console.error('❌ User detail query error:', error);
      return res.status(500).json({ error: 'Failed to fetch user details' });
    }

    if (!data) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user: data
    });

  } catch (err) {
    console.error('❌ Admin user detail error:', err);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// ============================================================================
// QUOTA ADJUSTMENT ENDPOINTS (A)
// ============================================================================

/**
 * POST /admin/users/:id/quotas
 * Adjust user quotas (AI minutes, SMS, storage)
 * 
 * Body:
 * {
 *   "action": "reset" | "add" | "set",
 *   "quota_type": "ai_minutes" | "sms" | "storage",
 *   "value": number (for add/set actions),
 *   "reason": "string" (required)
 * }
 */
router.post('/users/:id/quotas', authenticateAdmin, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { action, quota_type, value, reason } = req.body;

    // Validation
    if (!action || !quota_type || !reason) {
      return res.status(400).json({
        error: 'Missing required fields: action, quota_type, reason'
      });
    }

    if ((action === 'add' || action === 'set') && (value === undefined || value === null)) {
      return res.status(400).json({
        error: 'Value is required for add/set actions'
      });
    }

    console.log(`📝 Admin quota adjustment: ${action} ${quota_type} for user ${targetUserId} by ${req.admin.email}`);

    // Get target user email for logging
    const { data: targetUser, error: userError } = await req.supabaseAdmin.auth.admin.getUserById(targetUserId);
    if (userError || !targetUser) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Get current state
    let beforeState = {};
    let afterState = {};

    // Handle different quota types
    switch (quota_type) {
      case 'ai_minutes': {
        // Get current monthly usage
        const currentMonth = new Date().toISOString().substring(0, 7) + '-01';
        const { data: monthlyUsage } = await req.supabaseAdmin
          .from('user_ai_usage_monthly')
          .select('ai_minutes_used')
          .eq('user_id', targetUserId)
          .eq('month', currentMonth)
          .single();

        beforeState = {
          ai_minutes_used: monthlyUsage?.ai_minutes_used || 0
        };

        // Perform action
        if (action === 'reset') {
          // Reset to 0
          await req.supabaseAdmin
            .from('user_ai_usage_monthly')
            .update({ ai_minutes_used: 0, updated_at: new Date().toISOString() })
            .eq('user_id', targetUserId)
            .eq('month', currentMonth);

          afterState = { ai_minutes_used: 0 };

        } else if (action === 'add') {
          // Add to current value
          const newValue = parseFloat(beforeState.ai_minutes_used) + parseFloat(value);
          await req.supabaseAdmin
            .from('user_ai_usage_monthly')
            .upsert({
              user_id: targetUserId,
              month: currentMonth,
              ai_minutes_used: newValue,
              updated_at: new Date().toISOString()
            });

          afterState = { ai_minutes_used: newValue };

        } else if (action === 'set') {
          // Set absolute value
          await req.supabaseAdmin
            .from('user_ai_usage_monthly')
            .upsert({
              user_id: targetUserId,
              month: currentMonth,
              ai_minutes_used: parseFloat(value),
              updated_at: new Date().toISOString()
            });

          afterState = { ai_minutes_used: parseFloat(value) };
        }
        break;
      }

      case 'storage': {
        // Get current storage usage
        const { data: userData } = await req.supabaseAdmin
          .from('users')
          .select('storage_used_bytes, storage_limit_bytes')
          .eq('id', targetUserId)
          .single();

        beforeState = {
          storage_used_bytes: userData?.storage_used_bytes || 0,
          storage_limit_bytes: userData?.storage_limit_bytes || 104857600
        };

        // Perform action
        if (action === 'reset') {
          // Reset used to 0
          await req.supabaseAdmin
            .from('users')
            .update({ storage_used_bytes: 0 })
            .eq('id', targetUserId);

          afterState = {
            storage_used_bytes: 0,
            storage_limit_bytes: beforeState.storage_limit_bytes
          };

        } else if (action === 'add') {
          // Add to current limit
          const newLimit = parseInt(beforeState.storage_limit_bytes) + parseInt(value);
          await req.supabaseAdmin
            .from('users')
            .update({ storage_limit_bytes: newLimit })
            .eq('id', targetUserId);

          afterState = {
            storage_used_bytes: beforeState.storage_used_bytes,
            storage_limit_bytes: newLimit
          };

        } else if (action === 'set') {
          // Set absolute limit
          await req.supabaseAdmin
            .from('users')
            .update({ storage_limit_bytes: parseInt(value) })
            .eq('id', targetUserId);

          afterState = {
            storage_used_bytes: beforeState.storage_used_bytes,
            storage_limit_bytes: parseInt(value)
          };
        }
        break;
      }

      case 'sms': {
        // TODO: Implement SMS quota tracking if needed
        return res.status(501).json({
          error: 'SMS quota adjustment not yet implemented'
        });
      }

      default:
        return res.status(400).json({
          error: 'Invalid quota_type. Must be: ai_minutes, sms, or storage'
        });
    }

    // Log the admin action
    await logAdminAction(
      req.supabaseAdmin,
      req.admin,
      targetUserId,
      targetUser.user.email,
      'ADJUST_QUOTA',
      'QUOTA',
      { action, quota_type, value },
      beforeState,
      afterState,
      reason,
      req.ip,
      req.headers['user-agent']
    );

    res.json({
      success: true,
      message: `Quota ${action} successful`,
      before: beforeState,
      after: afterState
    });

  } catch (err) {
    console.error('❌ Admin quota adjustment error:', err);
    res.status(500).json({ error: 'Failed to adjust quota' });
  }
});

// ============================================================================
// CREDITS ENDPOINTS (B)
// ============================================================================

/**
 * POST /admin/users/:id/credits
 * Grant credits to a user
 * 
 * Body:
 * {
 *   "credit_type": "AI_MINUTES" | "SMS" | "STORAGE",
 *   "amount": number,
 *   "expires_at": "ISO8601" (optional),
 *   "reason": "string" (required)
 * }
 */
router.post('/users/:id/credits', authenticateAdmin, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { credit_type, amount, expires_at, reason } = req.body;

    // Validation
    if (!credit_type || !amount || !reason) {
      return res.status(400).json({
        error: 'Missing required fields: credit_type, amount, reason'
      });
    }

    if (!['AI_MINUTES', 'SMS', 'STORAGE'].includes(credit_type)) {
      return res.status(400).json({
        error: 'Invalid credit_type. Must be: AI_MINUTES, SMS, or STORAGE'
      });
    }

    if (amount <= 0) {
      return res.status(400).json({
        error: 'Amount must be greater than 0'
      });
    }

    console.log(`💳 Admin granting credit: ${amount} ${credit_type} to user ${targetUserId} by ${req.admin.email}`);

    // Get target user email for logging
    const { data: targetUser, error: userError } = await req.supabaseAdmin.auth.admin.getUserById(targetUserId);
    if (userError || !targetUser) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Grant credit using the database function
    const { data: creditId, error: creditError } = await req.supabaseAdmin.rpc('grant_user_credit', {
      p_user_id: targetUserId,
      p_credit_type: credit_type,
      p_amount: amount,
      p_granted_by: req.admin.user_id,
      p_reason: reason,
      p_expires_at: expires_at || null
    });

    if (creditError) {
      console.error('❌ Credit grant error:', creditError);
      return res.status(500).json({ error: 'Failed to grant credit' });
    }

    // Log the admin action
    await logAdminAction(
      req.supabaseAdmin,
      req.admin,
      targetUserId,
      targetUser.user.email,
      'GRANT_CREDIT',
      'CREDIT',
      { credit_type, amount, expires_at },
      {},
      { credit_id: creditId },
      reason,
      req.ip,
      req.headers['user-agent']
    );

    res.json({
      success: true,
      message: 'Credit granted successfully',
      credit_id: creditId
    });

  } catch (err) {
    console.error('❌ Admin credit grant error:', err);
    res.status(500).json({ error: 'Failed to grant credit' });
  }
});

// ============================================================================
// ENTITLEMENT OVERRIDE ENDPOINTS (C)
// ============================================================================

/**
 * POST /admin/users/:id/entitlements
 * Override user entitlements (plan, state, grace period)
 * 
 * Body:
 * {
 *   "override_type": "PLAN" | "STATE" | "GRACE_PERIOD" | "QUOTAS",
 *   "plan": "free" | "pro" | "plus" | "business" | "enterprise" (for PLAN type),
 *   "state": "ACTIVE" | "TRIAL" | "PAST_DUE" | "TERMINATED" | "GRACE" (for STATE type),
 *   "grace_enabled": boolean (for GRACE_PERIOD type),
 *   "grace_ends_at": "ISO8601" (for GRACE_PERIOD type),
 *   "quota_overrides": {"ai_minutes_limit": 1000} (for QUOTAS type),
 *   "expires_at": "ISO8601" (optional but recommended),
 *   "reason": "string" (required)
 * }
 */
router.post('/users/:id/entitlements', authenticateAdmin, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { override_type, plan, state, grace_enabled, grace_ends_at, quota_overrides, expires_at, reason } = req.body;

    // Validation
    if (!override_type || !reason) {
      return res.status(400).json({
        error: 'Missing required fields: override_type, reason'
      });
    }

    if (!['PLAN', 'STATE', 'GRACE_PERIOD', 'QUOTAS'].includes(override_type)) {
      return res.status(400).json({
        error: 'Invalid override_type. Must be: PLAN, STATE, GRACE_PERIOD, or QUOTAS'
      });
    }

    console.log(`🔐 Admin entitlement override: ${override_type} for user ${targetUserId} by ${req.admin.email}`);

    // Get target user email for logging
    const { data: targetUser, error: userError } = await req.supabaseAdmin.auth.admin.getUserById(targetUserId);
    if (userError || !targetUser) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Get current state
    const { data: currentOverrides } = await req.supabaseAdmin
      .from('entitlement_overrides')
      .select('*')
      .eq('user_id', targetUserId)
      .eq('is_active', true);

    // Apply override using the database function
    const { data: overrideId, error: overrideError } = await req.supabaseAdmin.rpc('apply_entitlement_override', {
      p_user_id: targetUserId,
      p_override_type: override_type,
      p_plan: plan || null,
      p_state: state || null,
      p_grace_enabled: grace_enabled !== undefined ? grace_enabled : null,
      p_grace_ends_at: grace_ends_at || null,
      p_quota_overrides: quota_overrides || null,
      p_granted_by: req.admin.user_id,
      p_reason: reason,
      p_expires_at: expires_at || null
    });

    if (overrideError) {
      console.error('❌ Entitlement override error:', overrideError);
      return res.status(500).json({ error: 'Failed to apply entitlement override' });
    }

    // Log the admin action
    await logAdminAction(
      req.supabaseAdmin,
      req.admin,
      targetUserId,
      targetUser.user.email,
      'OVERRIDE_ENTITLEMENT',
      'ENTITLEMENT',
      { override_type, plan, state, grace_enabled, grace_ends_at, quota_overrides, expires_at },
      { previous_overrides: currentOverrides },
      { override_id: overrideId },
      reason,
      req.ip,
      req.headers['user-agent']
    );

    res.json({
      success: true,
      message: 'Entitlement override applied successfully',
      override_id: overrideId
    });

  } catch (err) {
    console.error('❌ Admin entitlement override error:', err);
    res.status(500).json({ error: 'Failed to apply entitlement override' });
  }
});

/**
 * DELETE /admin/users/:userId/entitlements/:overrideId
 * Deactivate an entitlement override
 */
router.delete('/users/:userId/entitlements/:overrideId', authenticateAdmin, async (req, res) => {
  try {
    const { userId, overrideId } = req.params;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ error: 'Reason is required' });
    }

    console.log(`🔓 Admin deactivating entitlement override ${overrideId} for user ${userId}`);

    // Get target user email for logging
    const { data: targetUser, error: userError } = await req.supabaseAdmin.auth.admin.getUserById(userId);
    if (userError || !targetUser) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Get override details before deactivation
    const { data: override } = await req.supabaseAdmin
      .from('entitlement_overrides')
      .select('*')
      .eq('id', overrideId)
      .eq('user_id', userId)
      .single();

    // Deactivate override
    const { data: success, error } = await req.supabaseAdmin.rpc('deactivate_entitlement_override', {
      p_override_id: overrideId
    });

    if (error) {
      console.error('❌ Entitlement deactivation error:', error);
      return res.status(500).json({ error: 'Failed to deactivate override' });
    }

    // Log the admin action
    await logAdminAction(
      req.supabaseAdmin,
      req.admin,
      userId,
      targetUser.user.email,
      'DEACTIVATE_OVERRIDE',
      'ENTITLEMENT',
      { override_id: overrideId },
      { override },
      {},
      reason,
      req.ip,
      req.headers['user-agent']
    );

    res.json({
      success: true,
      message: 'Entitlement override deactivated successfully'
    });

  } catch (err) {
    console.error('❌ Admin entitlement deactivation error:', err);
    res.status(500).json({ error: 'Failed to deactivate override' });
  }
});

// ============================================================================
// AUDIT LOG ENDPOINTS
// ============================================================================

/**
 * GET /admin/actions
 * Get admin action log with filtering and pagination
 * 
 * Query params:
 * - page: page number (default: 1)
 * - limit: items per page (default: 50, max: 200)
 * - admin_email: filter by admin email
 * - target_email: filter by target user email
 * - action_type: filter by action type
 * - category: filter by action category
 * - start_date: filter by start date (ISO8601)
 * - end_date: filter by end date (ISO8601)
 */
router.get('/actions', authenticateAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = (page - 1) * limit;

    console.log(`📋 Admin actions log request from ${req.admin.email} (page ${page})`);

    // Build query
    let query = req.supabaseAdmin
      .from('admin_action_logs')
      .select('*', { count: 'exact' });

    // Apply filters
    if (req.query.admin_email) {
      query = query.ilike('admin_email', `%${req.query.admin_email}%`);
    }
    if (req.query.target_email) {
      query = query.ilike('target_user_email', `%${req.query.target_email}%`);
    }
    if (req.query.action_type) {
      query = query.eq('action_type', req.query.action_type);
    }
    if (req.query.category) {
      query = query.eq('action_category', req.query.category);
    }
    if (req.query.start_date) {
      query = query.gte('created_at', req.query.start_date);
    }
    if (req.query.end_date) {
      query = query.lte('created_at', req.query.end_date);
    }

    // Sort by created_at DESC with pagination
    query = query
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    const { data: actions, error, count } = await query;

    if (error) {
      console.error('❌ Admin actions query error:', error);
      return res.status(500).json({ error: 'Failed to fetch admin actions' });
    }

    const totalPages = Math.ceil((count || 0) / limit);

    res.json({
      success: true,
      actions: actions || [],
      pagination: {
        page,
        limit,
        total_items: count,
        total_pages: totalPages,
        has_next: page < totalPages,
        has_prev: page > 1
      }
    });

  } catch (err) {
    console.error('❌ Admin actions log error:', err);
    res.status(500).json({ error: 'Failed to fetch admin actions' });
  }
});

/**
 * GET /admin/actions/export
 * Export admin actions to CSV
 */
router.get('/actions/export', authenticateAdmin, async (req, res) => {
  try {
    console.log(`📥 Admin actions export request from ${req.admin.email}`);

    // Get actions (limit to 10,000 for export)
    const { data: actions, error } = await req.supabaseAdmin
      .from('admin_action_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(10000);

    if (error) {
      console.error('❌ Admin actions export query error:', error);
      return res.status(500).json({ error: 'Failed to export admin actions' });
    }

    // Convert to CSV
    const csv = convertToCSV(actions);

    // Set headers for CSV download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=admin-actions-${new Date().toISOString()}.csv`);
    res.send(csv);

    // Log the export action
    await logAdminAction(
      req.supabaseAdmin,
      req.admin,
      null,
      null,
      'EXPORT_ACTIONS',
      'SYSTEM',
      { export_count: actions.length },
      {},
      {},
      'CSV export of admin actions',
      req.ip,
      req.headers['user-agent']
    );

  } catch (err) {
    console.error('❌ Admin actions export error:', err);
    res.status(500).json({ error: 'Failed to export admin actions' });
  }
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Convert array of objects to CSV
 */
function convertToCSV(data) {
  if (!data || data.length === 0) return '';

  const headers = Object.keys(data[0]);
  const csvRows = [];

  // Add header row
  csvRows.push(headers.join(','));

  // Add data rows
  for (const row of data) {
    const values = headers.map(header => {
      const val = row[header];
      // Escape commas and quotes
      if (typeof val === 'object') {
        return `"${JSON.stringify(val).replace(/"/g, '""')}"`;
      }
      return `"${String(val).replace(/"/g, '""')}"`;
    });
    csvRows.push(values.join(','));
  }

  return csvRows.join('\n');
}

module.exports = function (supabaseAdmin) {
  // Middleware to attach supabaseAdmin to request
  router.use((req, res, next) => {
    if (!supabaseAdmin) {
      console.error('❌ FATAL: supabaseAdmin client is not initialized. Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables.');
      return res.status(500).json({ 
        error: 'Server configuration error', 
        detail: 'Supabase client not initialized' 
      });
    }
    req.supabaseAdmin = supabaseAdmin;
    next();
  });

  return router;
};
