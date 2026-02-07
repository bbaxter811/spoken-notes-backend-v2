require('dotenv').config();

// ============================================================================
// CRASH VISIBILITY - Must be at the very top
// ============================================================================
process.on("uncaughtException", (e) => {
  console.error("❌ UNCAUGHT EXCEPTION:", e);
  console.error("Stack:", e.stack);
  process.exit(1);
});

process.on("unhandledRejection", (e) => {
  console.error("❌ UNHANDLED REJECTION:", e);
  process.exit(1);
});

process.on("exit", (code) => {
  console.log("🚪 PROCESS EXIT - Code:", code);
});

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const OpenAI = require('openai');
const { v4: uuidv4 } = require('uuid');
const sgMail = require('@sendgrid/mail');
const { google } = require('googleapis');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;

// Initialize Stripe only if key is present (optional for deployment)
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    console.log('✅ Stripe initialized');
  } catch (err) {
    console.error('⚠️ Stripe initialization failed:', err.message);
  }
} else {
  console.log('⚠️ STRIPE_SECRET_KEY not set - Stripe disabled');
}

// CRITICAL: Raw body for Stripe webhooks (must be before express.json())
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) {
    console.error('❌ Stripe not initialized (missing STRIPE_SECRET_KEY)');
    return res.status(503).json({ error: 'Stripe not configured' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('❌ STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).json({ error: 'Webhook secret not configured' });
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    console.log(`✅ Stripe webhook received: ${event.type} (ID: ${event.id})`);
  } catch (err) {
    console.error(`❌ Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // IDEMPOTENCY CHECK: Prevent duplicate event processing
  try {
    const { data: existingEvent } = await supabaseAdmin
      .from('processed_stripe_events')
      .select('event_id')
      .eq('event_id', event.id)
      .single();

    if (existingEvent) {
      console.log(`⚠️ Event ${event.id} already processed - skipping`);
      return res.json({ received: true, status: 'already_processed' });
    }
  } catch (checkErr) {
    // Error likely means event doesn't exist (expected for first processing)
    console.log(`📝 First time processing event ${event.id}`);
  }

  // Handle different event types
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      console.log('💳 Checkout session completed:', session.id);
      console.log('   Customer ID:', session.customer);
      console.log('   Subscription ID:', session.subscription);
      console.log('   Client Reference ID:', session.client_reference_id); // This should be user_id

      const userId = session.client_reference_id; // App must pass user_id here

      if (!userId) {
        console.error('❌ No client_reference_id - cannot map to user');
        break;
      }

      // Fetch full subscription details from Stripe to get price_id and periods
      try {
        if (!session.subscription) {
          console.error('❌ No subscription ID in session');
          break;
        }

        console.log('🔍 Fetching subscription:', session.subscription);
        const subscription = await stripe.subscriptions.retrieve(session.subscription);

        if (!subscription) {
          console.error('❌ Failed to retrieve subscription from Stripe');
          break;
        }

        // Log the ENTIRE subscription object to debug
        console.log('📦 RAW subscription object:', JSON.stringify(subscription, null, 2).substring(0, 2000));

        const priceId = subscription.items.data[0]?.price.id || null;

        console.log('📦 Extracted fields:', {
          subscription_id: subscription.id,
          price_id: priceId,
          status: subscription.status,
          current_period_start: subscription.current_period_start,
          current_period_end: subscription.current_period_end
        });

        // If timestamps are missing, skip and let customer.subscription.created handle it
        if (!subscription.current_period_start || !subscription.current_period_end) {
          console.warn('⚠️ Missing period timestamps - will be handled by customer.subscription.created event');
          console.log('⚠️ Session details for reference:', {
            session_id: session.id,
            customer: session.customer,
            subscription: session.subscription,
            status: session.status
          });
          break;
        }

        // Insert subscription (no upsert - use insert only)
        const subscriptionData = {
          user_id: userId,
          stripe_customer_id: session.customer,
          stripe_subscription_id: subscription.id,
          price_id: priceId,
          status: subscription.status,
          state: 'ACTIVE_PAID',
          plan: 'pro', // TODO: Map from price_id to plan name
          current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
          current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };

        console.log('💾 Inserting subscription to Supabase:', subscriptionData);

        const { data, error } = await supabaseAdmin
          .from('subscriptions')
          .insert(subscriptionData)
          .select()
          .single();

        if (error) {
          console.error('❌ Failed to write subscription to Supabase:', error);
          console.error('❌ Error details:', JSON.stringify(error, null, 2));
        } else {
          console.log('✅ Subscription written to Supabase:', data);
        }
      } catch (err) {
        console.error('❌ Subscription write error:', err.message);
        console.error('❌ Stack:', err.stack);
      }
      break;
    }

    case 'customer.subscription.created': {
      const subscription = event.data.object;

      console.log('📝 customer.subscription.created:', subscription.id);
      console.log('   Customer ID:', subscription.customer);
      console.log('   Status:', subscription.status);

      // CRITICAL: Timestamps are on the subscription ITEM, not the subscription itself
      const firstItem = subscription.items?.data?.[0];
      const periodStart = firstItem?.current_period_start;
      const periodEnd = firstItem?.current_period_end;

      console.log('✅ Timestamps from subscription item:', {
        periodStart,
        periodEnd,
        itemId: firstItem?.id
      });

      // Try to find user_id by looking up stripe_customer_id OR from checkout session
      let userId = subscription.metadata?.user_id;

      if (!userId) {
        console.log('⚠️ No metadata.user_id - attempting to find via stripe_customer_id');

        // First try: Look for existing subscription with this customer
        try {
          const { data: existingRows, error: lookupError } = await supabaseAdmin
            .from('subscriptions')
            .select('user_id')
            .eq('stripe_customer_id', subscription.customer)
            .limit(1);

          if (existingRows && existingRows.length > 0) {
            userId = existingRows[0].user_id;
            console.log('✅ Found user_id via customer lookup:', userId);
          }
        } catch (lookupErr) {
          console.error('❌ Customer lookup error:', lookupErr.message);
        }

        // Second try: Query Stripe for the most recent checkout session with this customer
        if (!userId) {
          console.log('⚠️ Attempting to find userId via Stripe checkout sessions');
          try {
            const sessions = await stripe.checkout.sessions.list({
              customer: subscription.customer,
              limit: 1
            });

            if (sessions.data.length > 0 && sessions.data[0].client_reference_id) {
              userId = sessions.data[0].client_reference_id;
              console.log('✅ Found user_id via checkout session:', userId);
            }
          } catch (stripeErr) {
            console.error('❌ Stripe session lookup error:', stripeErr.message);
          }
        }

        if (!userId) {
          console.warn('⚠️ Could not find user_id - skipping this event');
          break;
        }
      }

      const priceId = subscription.items?.data?.[0]?.price?.id || null;

      try {
        // Validate timestamps exist
        if (!periodStart || !periodEnd) {
          console.error('❌ Missing timestamps even after extraction:', { periodStart, periodEnd });
          break;
        }

        // Only include columns that exist in the Supabase table
        const subscriptionData = {
          user_id: userId,
          stripe_customer_id: subscription.customer,
          stripe_subscription_id: subscription.id,
          price_id: priceId,
          status: subscription.status,
          // state: 'ACTIVE_PAID',  // Column doesn't exist in current schema
          // plan: 'pro',  // Column doesn't exist in current schema
          // current_period_start: new Date(periodStart * 1000).toISOString(),  // Column doesn't exist
          current_period_end: new Date(periodEnd * 1000).toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };

        console.log('💾 Upserting subscription with data:', JSON.stringify(subscriptionData, null, 2));

        const { data, error } = await supabaseAdmin
          .from('subscriptions')
          .upsert(subscriptionData, {
            onConflict: 'stripe_subscription_id',
            ignoreDuplicates: false
          })
          .select()
          .single();

        if (error) {
          console.error('❌ Failed to upsert subscription:', error);
          console.error('❌ Error details:', JSON.stringify(error, null, 2));
        } else {
          console.log('✅ Subscription upserted in Supabase (idempotent):', data);
        }
      } catch (err) {
        console.error('❌ Supabase write error:', err.message);
        console.error('❌ Stack:', err.stack);
      }
      break;
    }

    case 'customer.subscription.updated': {
      const subscription = event.data.object;
      console.log('🔄 Subscription updated:', subscription.id);
      console.log('   Status:', subscription.status);

      try {
        // Get period_end from subscription items (same location as in created event)
        const firstItem = subscription.items?.data?.[0];
        const periodEnd = firstItem?.current_period_end;

        const updateData = {
          status: subscription.status,
          updated_at: new Date().toISOString()
        };

        // Only add current_period_end if we have a valid timestamp
        if (periodEnd) {
          updateData.current_period_end = new Date(periodEnd * 1000).toISOString();
        }

        console.log('💾 Updating subscription with data:', updateData);

        const { data, error } = await supabaseAdmin
          .from('subscriptions')
          .update(updateData)
          .eq('stripe_subscription_id', subscription.id)
          .select();

        if (error) {
          console.error('❌ Failed to update subscription:', error);
          console.error('❌ Error details:', JSON.stringify(error, null, 2));
        } else {
          console.log('✅ Subscription updated in Supabase:', data);
        }
      } catch (err) {
        console.error('❌ Supabase write error:', err.message);
        console.error('❌ Stack:', err.stack);
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      console.log('❌ Subscription deleted:', subscription.id);

      try {
        const { data, error } = await supabaseAdmin
          .from('subscriptions')
          .update({
            status: 'canceled',
            updated_at: new Date().toISOString()
          })
          .eq('stripe_subscription_id', subscription.id);

        if (error) {
          console.error('❌ Failed to mark subscription as canceled:', error);
        } else {
          console.log('✅ Subscription marked as canceled in Supabase');
        }
      } catch (err) {
        console.error('❌ Supabase write error:', err);
      }
      break;
    }

    case 'invoice.payment_succeeded': {
      const invoice = event.data.object;
      console.log('✅ Payment succeeded:', invoice.id);
      console.log('   Customer:', invoice.customer);
      console.log('   Subscription:', invoice.subscription);
      console.log('   Amount:', invoice.amount_paid / 100, invoice.currency.toUpperCase());
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      console.log('💸 Payment failed:', invoice.id);
      console.log('   Customer:', invoice.customer);
      console.log('   Subscription:', invoice.subscription);

      // Mark subscription as past_due
      if (invoice.subscription) {
        try {
          const { data, error } = await supabaseAdmin
            .from('subscriptions')
            .update({
              status: 'past_due',
              updated_at: new Date().toISOString()
            })
            .eq('stripe_subscription_id', invoice.subscription);

          if (error) {
            console.error('❌ Failed to update subscription status:', error);
          } else {
            console.log('✅ Subscription marked as past_due');
          }
        } catch (err) {
          console.error('❌ Supabase write error:', err);
        }
      }
      break;
    }

    default:
      console.log(`⚠️ Unhandled event type: ${event.type}`);
  }

  // Mark event as processed (idempotency tracking)
  try {
    await supabaseAdmin
      .from('processed_stripe_events')
      .insert({
        event_id: event.id,
        event_type: event.type
      });
    console.log(`✅ Event ${event.id} marked as processed`);
  } catch (insertErr) {
    console.error(`⚠️ Failed to mark event as processed (non-fatal):`, insertErr.message);
  }

  res.json({ received: true });
});

// DIAGNOSTIC: Test send-email route (returns 401 if working, 404 if missing)
app.get('/api/assistant/send-email/test', (req, res) => {
  res.json({
    message: 'send-email route exists',
    status: 'Route is registered and working',
    note: 'POST to this route requires authentication. This GET endpoint is for verification only.'
  });
});

// JSON parsing for all other routes
app.use(express.json());

// Initialize Supabase client (admin for server-side operations)
let supabaseAdmin;
let openai;

try {
  supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
  console.log('✅ Supabase client initialized');
  console.log(`📍 Supabase URL: ${process.env.SUPABASE_URL}`); // Log URL for verification
} catch (err) {
  console.error('⚠️  Supabase initialization warning:', err.message);
}

// Initialize OpenAI client
try {
  openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
  });
  console.log('✅ OpenAI client initialized');
} catch (err) {
  console.error('⚠️  OpenAI initialization warning:', err.message);
}

// Initialize SendGrid for email sending
if (process.env.SENDGRID_API_KEY) {
  try {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    console.log('✅ SendGrid initialized');
  } catch (err) {
    console.error('⚠️  SendGrid initialization warning:', err.message);
  }
} else {
  console.log('⚠️  SENDGRID_API_KEY not set - email sending disabled');
}

// Configure multer for file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB max file size
  }
});

// CORS middleware
app.use(cors());

// Static file serving for temp files
const tempDir = path.join(__dirname, 'temp_files');
app.use('/temp_files', express.static(tempDir, {
  maxAge: '7d',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.docx')) {
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
    } else if (filePath.endsWith('.xlsx')) {
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
    }
  }
}));

// Auth middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);

    // Verify token with Supabase
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    message: 'Backend V2 - Minimal'
  });
});

// DIAGNOSTIC: Routes verification endpoint
app.get('/api/routes', (req, res) => {
  try {
    const routes = [];

    // Extract all registered routes from Express
    if (app._router && app._router.stack) {
      app._router.stack.forEach((middleware) => {
        if (middleware.route) {
          // Direct route
          routes.push({
            path: middleware.route.path,
            methods: Object.keys(middleware.route.methods)
          });
        } else if (middleware.name === 'router' && middleware.handle && middleware.handle.stack) {
          // Router middleware
          middleware.handle.stack.forEach((handler) => {
            if (handler.route) {
              routes.push({
                path: handler.route.path,
                methods: Object.keys(handler.route.methods)
              });
            }
          });
        }
      });
    }

    res.json({
      message: 'Registered routes',
      count: routes.length,
      routes: routes.sort((a, b) => a.path.localeCompare(b.path)),
      assistantEmailRoute: routes.find(r => r.path === '/api/assistant/send-email') ? '✅ FOUND' : '❌ MISSING'
    });
  } catch (error) {
    console.error('Error listing routes:', error);
    res.status(500).json({ error: 'Failed to list routes', message: error.message });
  }
});

// PROTECTION 1: Rate limiting - in-memory tracker (resets on server restart)
const testEndpointRateLimits = new Map(); // { ip: { count, resetAt } }
const TEST_RATE_LIMIT = 20; // Max requests per IP per hour
const TEST_RATE_WINDOW = 60 * 60 * 1000; // 1 hour in ms

// PROTECTION 2: Hard expiry - endpoint refuses after this date
const TEST_ENDPOINT_EXPIRY = new Date('2026-02-02T00:00:00Z'); // 72 hours from now (Feb 2, 2026)

/**
 * TEMPORARY TEST ENDPOINT (Phase 3 validation only)
 * POST /api/test/smoke
 * Validates subscription + storage enforcement without bearer token
 * Guarded by TEST_SECRET environment variable
 * 
 * PROTECTIONS:
 * - Rate limit: 20 requests per IP per hour
 * - Hard expiry: Refuses requests after Feb 2, 2026
 * 
 * REMOVE AFTER PHASE 3 VALIDATION COMPLETE
 */
app.post('/api/test/smoke', async (req, res) => {
  // PROTECTION 2: Check hard expiry first
  if (new Date() > TEST_ENDPOINT_EXPIRY) {
    console.error(`🚫 Test endpoint expired (after ${TEST_ENDPOINT_EXPIRY.toISOString()})`);
    return res.status(410).json({
      error: 'Test endpoint expired',
      message: 'This temporary endpoint is no longer available. Remove TEST_SECRET and test endpoint code.'
    });
  }

  // PROTECTION 1: Rate limiting
  const clientIp = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const now = Date.now();

  let rateLimit = testEndpointRateLimits.get(clientIp);
  if (!rateLimit || now > rateLimit.resetAt) {
    // New window
    rateLimit = { count: 0, resetAt: now + TEST_RATE_WINDOW };
    testEndpointRateLimits.set(clientIp, rateLimit);
  }

  rateLimit.count++;

  if (rateLimit.count > TEST_RATE_LIMIT) {
    const resetIn = Math.ceil((rateLimit.resetAt - now) / 1000 / 60); // minutes
    console.warn(`⚠️ Rate limit exceeded for IP ${clientIp} (${rateLimit.count} requests)`);
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: `Too many requests. Try again in ${resetIn} minutes.`,
      retryAfter: resetIn * 60 // seconds
    });
  }

  const { secret, userId, testType } = req.body;

  // Verify test secret
  const TEST_SECRET = process.env.TEST_SECRET;
  if (!TEST_SECRET) {
    return res.status(503).json({ error: 'Test endpoint disabled (no TEST_SECRET)' });
  }

  if (secret !== TEST_SECRET) {
    console.warn(`⚠️ Invalid test secret attempt from IP ${clientIp}`);
    return res.status(403).json({ error: 'Invalid test secret' });
  }

  if (!userId) {
    return res.status(400).json({ error: 'userId required' });
  }

  console.log(`🧪 Test endpoint: ${testType} for user ${userId}`);

  try {
    if (testType === 'subscription') {
      // Test 1: Check subscription endpoint logic
      const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

      const { data: subData, error: subError } = await supabase
        .from('subscriptions')
        .select('status, price_id, stripe_customer_id, stripe_subscription_id, current_period_end')
        .eq('user_id', userId)
        .maybeSingle();

      if (subError) {
        return res.status(500).json({ error: 'Subscription lookup failed', details: subError.message });
      }

      // Determine storage cap
      let storageLimit = 104857600; // 100 MB default (free)
      let planTier = 'free';

      if (subData && (subData.status === 'active' || subData.status === 'trialing')) {
        const priceId = subData.price_id;
        if (priceId === process.env.STRIPE_PRICE_PRO) {
          storageLimit = 5368709120; // 5 GB
          planTier = 'pro';
        } else {
          storageLimit = 5368709120; // Unknown price_id = pro (safe default for paying customers)
          planTier = 'pro';
        }
      }

      // Get storage usage
      const { data: usageData } = await supabase
        .from('user_storage_usage')
        .select('total_bytes')
        .eq('user_id', userId)
        .single();

      const storageUsed = usageData?.total_bytes || 0;

      return res.json({
        testType: 'subscription',
        userId,
        subscription: subData || { status: 'free', message: 'No subscription row' },
        storageLimit,
        storageUsed,
        planTier,
        percentUsed: Math.round((storageUsed / storageLimit) * 100)
      });

    } else if (testType === 'upload_check') {
      // Test 2: Simulate upload storage check (without actual file)
      const { fileSize } = req.body;

      if (!fileSize) {
        return res.status(400).json({ error: 'fileSize required for upload_check' });
      }

      const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

      // Check subscription
      let storageLimit = 104857600; // 100 MB default
      let planTier = 'free';

      const { data: subData } = await supabase
        .from('subscriptions')
        .select('status, price_id')
        .eq('user_id', userId)
        .maybeSingle();

      if (subData && (subData.status === 'active' || subData.status === 'trialing')) {
        const priceId = subData.price_id;
        if (priceId === process.env.STRIPE_PRICE_PRO) {
          storageLimit = 5368709120; // 5 GB
          planTier = 'pro';
        } else {
          storageLimit = 5368709120;
          planTier = 'pro';
        }
      }

      // Get current usage
      const { data: usageData } = await supabase
        .from('user_storage_usage')
        .select('total_bytes')
        .eq('user_id', userId)
        .single();

      const currentUsage = usageData?.total_bytes || 0;
      const projectedTotal = currentUsage + fileSize;

      if (projectedTotal > storageLimit) {
        return res.status(402).json({
          testType: 'upload_check',
          result: 'BLOCKED',
          code: 'STORAGE_LIMIT',
          blocked_reason: 'CAP_WOULD_EXCEED',
          message: 'Storage limit reached. Upgrade your plan to continue.',
          currentUsage,
          storageLimit,
          fileSize,
          projectedTotal,
          planTier
        });
      }

      return res.json({
        testType: 'upload_check',
        result: 'ALLOWED',
        currentUsage,
        storageLimit,
        fileSize,
        projectedTotal,
        percentUsed: Math.round((projectedTotal / storageLimit) * 100),
        planTier
      });

    } else {
      return res.status(400).json({ error: 'Unknown testType. Use "subscription" or "upload_check"' });
    }

  } catch (error) {
    console.error('🧪 Test endpoint error:', error);
    return res.status(500).json({ error: 'Test failed', details: error.message });
  }
});

// Test Supabase connection
app.get('/api/test-db', async (req, res) => {
  try {
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ message: 'Supabase connected!', data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// RECORDING ENDPOINTS - Priority 1
// ============================================================================

/**
 * POST /api/voice-command/transcribe
 * SYNC transcription for voice commands (3 second snippets)
 * Returns transcript immediately (no database storage)
 */
app.post('/api/voice-command/transcribe', authenticateUser, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }

    console.log(`🎤 Voice command transcription request from user ${req.user.id}, size: ${req.file.size} bytes`);

    // Create a File-like object for OpenAI API
    const audioFile = new File([req.file.buffer], req.file.originalname, {
      type: 'audio/wav'
    });

    // Call Whisper API (synchronous - waits for result)
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Voice command transcribed: "${transcription.text}"`);

    // Return transcript immediately
    res.json({
      success: true,
      transcript: transcription.text
    });

  } catch (err) {
    console.error('❌ Voice command transcription error:', err);
    res.status(500).json({ error: 'Failed to transcribe voice command' });
  }
});

/**
 * POST /api/recordings/upload
 * Upload audio file, transcribe with Whisper, save to Supabase
 */
app.post('/api/recordings/upload', authenticateUser, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }

    const { duration } = req.body; // Duration in seconds from app
    const userId = req.user.id;
    const recordingId = uuidv4();

    console.log(`📤 Uploading recording for user ${userId}, duration: ${duration}s, size: ${req.file.size} bytes`);

    // PHASE 3: Server-side storage limit enforcement (CRITICAL - fail-safe)
    // Active tiers: Free (100 MB) | Pro (5 GB)
    // Coming soon: Plus, Business (not enforced yet)

    let storageLimit = 104857600; // 100 MB default for free tier
    let planTier = 'free';

    try {
      const { data: subData, error: subError } = await supabaseAdmin
        .from('subscriptions')
        .select('status, price_id')
        .eq('user_id', userId)
        .maybeSingle();

      if (subError) {
        console.error('⚠️ Failed to check subscription, using free tier limit:', subError);
      } else if (subData && (subData.status === 'active' || subData.status === 'trialing')) {
        // Only Pro is enforced for now (Plus/Business coming soon)
        const priceId = subData.price_id;

        if (priceId === process.env.STRIPE_PRICE_PRO) {
          storageLimit = 5368709120; // 5 GB for Pro
          planTier = 'pro';
          console.log('✅ Pro user - 5GB limit');
        } else {
          // Unknown or future tier - default to Pro for active subscriptions
          storageLimit = 5368709120; // 5 GB
          planTier = 'pro';
          console.log('⚠️ Unknown price_id, defaulting to Pro (5GB)');
        }
      } else {
        console.log('ℹ️ Free tier - 100MB limit');
      }
    } catch (subCheckError) {
      console.error('⚠️ Subscription check failed, defaulting to free tier:', subCheckError);
      // FAIL-SAFE: If we can't check subscription, use free tier limit (conservative)
    }

    // 2. Check current storage usage
    const { data: usageData, error: usageError } = await supabaseAdmin
      .from('user_storage_usage')
      .select('total_bytes')
      .eq('user_id', userId)
      .single();

    if (usageError && usageError.code !== 'PGRST116') {
      console.error('❌ Failed to check storage usage:', usageError);
      return res.status(500).json({
        code: 'STORAGE_CHECK_FAILED',
        error: 'Unable to verify storage limit. Please try again.'
      });
    }

    const currentUsage = usageData?.total_bytes || 0;
    const newTotal = currentUsage + req.file.size;

    // 3. Enforce storage limit (FAIL-CLOSED)
    if (newTotal > storageLimit) {
      console.log(`🚫 Storage limit exceeded: ${newTotal} > ${storageLimit} bytes`);
      return res.status(402).json({
        code: 'STORAGE_LIMIT',
        blocked_reason: 'CAP_WOULD_EXCEED',
        message: 'Storage limit reached. Upgrade your plan to continue.',
        total_bytes: currentUsage,
        cap_bytes: storageLimit,
        upload_size_bytes: req.file.size,
        projected_total_bytes: newTotal
      });
    }

    console.log(`✅ Storage check passed: ${newTotal} / ${storageLimit} bytes (${Math.round(newTotal / storageLimit * 100)}% used)`);

    // 1. Upload audio to Supabase Storage
    const fileName = `${recordingId}-${Date.now()}.${req.file.originalname.split('.').pop()}`;
    const filePath = `${userId}/${fileName}`;

    const { data: uploadData, error: uploadError } = await supabaseAdmin
      .storage
      .from('recordings')
      .upload(filePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) {
      console.error('Storage upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload audio file' });
    }

    // Get public URL for the uploaded file
    const { data: { publicUrl } } = supabaseAdmin
      .storage
      .from('recordings')
      .getPublicUrl(filePath);

    console.log(`✅ Audio uploaded to storage: ${filePath}`);

    // 2. Create recording record in database (status: 'processing')
    // Store the storage path, not the public URL (we'll generate signed URLs when fetching)
    const { data: recording, error: dbError } = await supabaseAdmin
      .from('recordings')
      .insert({
        id: recordingId,
        user_id: userId,
        audio_url: filePath, // Store the path, not public URL
        filename: req.file.originalname,
        duration_seconds: parseInt(duration) || 0,
        file_size_bytes: req.file.size,
        status: 'processing'
      })
      .select()
      .single();

    if (dbError) {
      console.error('Database insert error:', dbError);
      return res.status(500).json({ error: 'Failed to save recording metadata' });
    }

    console.log(`💾 Recording saved to DB: ${recordingId}`);

    // Generate signed URL for the response (valid for 1 hour)
    const { data: signedUrlData } = await supabaseAdmin
      .storage
      .from('recordings')
      .createSignedUrl(filePath, 3600); // 1 hour expiry

    // 3. Transcribe audio with Whisper (WAIT for voice commands - they need immediate response)
    console.log(`🎙️  Starting transcription for ${recordingId}`);

    const audioFile = new File([req.file.buffer], req.file.originalname, {
      type: req.file.mimetype
    });

    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Transcription complete for ${recordingId}: ${transcription.text}`);

    // Update recording with transcription
    await supabaseAdmin
      .from('recordings')
      .update({
        transcription: transcription.text,
        status: 'completed'
      })
      .eq('id', recordingId);

    console.log(`💾 Transcription saved for ${recordingId}`);

    // Return response with transcription included
    res.status(201).json({
      success: true,
      recording: {
        id: recording.id,
        audio_url: signedUrlData?.signedUrl || filePath,
        duration_seconds: recording.duration_seconds,
        transcription: transcription.text,
        status: 'completed',
        created_at: recording.created_at
      }
    });

  } catch (err) {
    console.error('❌ Upload error:', err);
    res.status(500).json({ error: 'Failed to upload recording' });
  }
});

/**
 * Async transcription function - runs after upload response is sent
 */
async function transcribeRecordingAsync(recordingId, audioBuffer, filename) {
  try {
    console.log(`🎙️  Starting transcription for ${recordingId}`);

    // Create a File-like object for OpenAI API
    const audioFile = new File([audioBuffer], filename, {
      type: filename.endsWith('.wav') ? 'audio/wav' : 'audio/mp4'
    });

    // Call Whisper API
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Transcription complete for ${recordingId}: ${transcription.text.substring(0, 100)}...`);

    // Update recording with transcription
    const { error: updateError } = await supabaseAdmin
      .from('recordings')
      .update({
        transcription: transcription.text,
        status: 'completed',
        updated_at: new Date().toISOString()
      })
      .eq('id', recordingId);

    if (updateError) {
      console.error('Failed to update transcription:', updateError);
    } else {
      console.log(`💾 Transcription saved for ${recordingId}`);
    }

  } catch (err) {
    console.error(`❌ Transcription error for ${recordingId}:`, err);

    // Mark as error in database
    await supabaseAdmin
      .from('recordings')
      .update({
        status: 'error',
        updated_at: new Date().toISOString()
      })
      .eq('id', recordingId);
  }
}

/**
 * GET /api/recordings
 * Fetch all recordings for authenticated user
 */
app.get('/api/recordings', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = parseInt(req.query.limit) || 50;

    const { data: recordings, error } = await supabaseAdmin
      .from('recordings')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch recordings' });
    }

    // Generate signed URLs for each recording (valid for 1 hour)
    const recordingsWithSignedUrls = await Promise.all(
      recordings.map(async (recording) => {
        if (recording.audio_url) {
          const { data: signedUrlData } = await supabaseAdmin
            .storage
            .from('recordings')
            .createSignedUrl(recording.audio_url, 3600); // 1 hour expiry

          return {
            ...recording,
            audio_url: signedUrlData?.signedUrl || recording.audio_url
          };
        }
        return recording;
      })
    );

    res.json({
      success: true,
      recordings: recordingsWithSignedUrls || []
    });

  } catch (err) {
    console.error('❌ Fetch recordings error:', err);
    res.status(500).json({ error: 'Failed to fetch recordings' });
  }
});

/**
 * GET /api/recordings/:id
 * Get single recording details
 */
app.get('/api/recordings/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const { data: recording, error } = await supabaseAdmin
      .from('recordings')
      .select('*')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (error || !recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    res.json({
      success: true,
      recording
    });

  } catch (err) {
    console.error('❌ Fetch recording error:', err);
    res.status(500).json({ error: 'Failed to fetch recording' });
  }
});

/**
 * DELETE /api/recordings/:id
 * Delete a recording
 */
app.delete('/api/recordings/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Get recording to find audio file path
    const { data: recording, error: fetchError } = await supabaseAdmin
      .from('recordings')
      .select('audio_url')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (fetchError || !recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    // Extract storage path from audio_url
    // Example URL: https://...supabase.co/storage/v1/object/public/recordings/user123/file.wav
    // We need: user123/file.wav
    let storageFilePath = null;
    if (recording.audio_url) {
      const urlMatch = recording.audio_url.match(/\/recordings\/(.+)$/);
      if (urlMatch) {
        storageFilePath = urlMatch[1];
      }
    }

    // Delete from database first
    const { error: deleteError } = await supabaseAdmin
      .from('recordings')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (deleteError) {
      console.error('Database delete error:', deleteError);
      return res.status(500).json({ error: 'Failed to delete recording' });
    }

    // Delete audio file from storage (if path was extracted)
    if (storageFilePath) {
      try {
        const { error: storageError } = await supabaseAdmin.storage
          .from('recordings')
          .remove([storageFilePath]);

        if (storageError) {
          console.error('⚠️ Storage delete error (non-blocking):', storageError);
          // Don't fail the request - database record already deleted
        } else {
          console.log(`✅ Deleted audio file from storage: ${storageFilePath}`);
        }
      } catch (storageErr) {
        console.error('⚠️ Storage delete exception (non-blocking):', storageErr);
      }
    } else {
      console.log('⚠️ No storage path extracted from audio_url - skipping storage delete');
    }

    res.json({
      success: true,
      message: 'Recording deleted'
    });

  } catch (err) {
    console.error('❌ Delete recording error:', err);
    res.status(500).json({ error: 'Failed to delete recording' });
  }
});

// ============================================================================
// CHAT ENDPOINTS - Priority 3
// ============================================================================

/**
 * POST /api/chat
 * Chat with AI based on retrieval mode (hybrid/memory/web)
 * Supports conversation history for multi-turn conversations
 */
app.post('/api/chat', authenticateUser, async (req, res) => {
  try {
    const {
      message,
      retrievalMode = 'hybrid',
      assistantName = 'Assistant',
      voiceGender = 'female',
      voiceAttitude = 'helpful',
      conversationHistory = [] // Accept conversation history from client
    } = req.body;
    const userId = req.user.id;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    console.log(`💬 Chat request from user ${userId}, mode: ${retrievalMode}`);
    console.log('   Personality -> Name: ' + assistantName + ', Gender: ' + voiceGender + ', Attitude: ' + voiceAttitude);
    console.log('   Conversation history: ' + conversationHistory.length + ' messages');

    // Build personality description
    const genderDesc = voiceGender === 'male' ? 'male' : 'female';
    const attitudeDesc = voiceAttitude === 'friendly' ? 'friendly and warm' : voiceAttitude === 'formal' ? 'professional and formal' : 'helpful and supportive';
    const personality = `You are ${assistantName}, a ${genderDesc} ${attitudeDesc} AI assistant.`;

    // Assistant personality and role (Production Architecture)
    const capabilities = `

YOUR ROLE:
You help the user draft, remember, and reflect. You do NOT execute actions - the app handles that.

WHAT YOU DO:
- Draft emails, texts, and notes
- Summarize past recordings
- Answer questions about recorded content
- Narrate completed actions

WHAT YOU DON'T DO:
- Execute actions (app handles confirmation and execution)
- Decide permissions or capabilities
- Ask if you're "allowed" to do something

CONTACT INFORMATION:
When user asks about contact details (email, phone, address, birthday), be honest:
"I'll need to look that up in your contacts. Let me check for you."

Then the app will provide the information, and you can relay it back.

CRITICAL - Email/SMS Action Protocol:
When user requests to send email or SMS:
1. Extract FULL recipient name/email accurately (e.g., "Brian Baxter", "john@example.com")
2. Respond: "I'll send [TYPE] to [FULL NAME/EMAIL] saying: [MESSAGE]. Ready to send?"
3. Wait for user confirmation
4. NEVER say action completed until AFTER user confirms

Examples:
✅ User: "Send email to Brian Baxter saying hello"
   You: "I'll send an email to Brian Baxter saying: hello. Ready to send?"
   
✅ User: "Email me saying test"
   You: "I'll send an email to yourself saying: test. Ready to send?"

✅ User: "Send text to John saying I'm running late"
   You: "I'll send a text to John saying: I'm running late. Ready to send?"

FORBIDDEN (Never say these):
❌ "The email has been sent" (before user confirms)
❌ "Email sent successfully" (before confirmation)
❌ "I can't send emails" (you CAN via backend)

After user says "send"/"confirm", the action executes and you'll see the result.
Then you can say: "Sent!"

You ARE connected to email, SMS, and file systems via the backend.
The app handles contact lookups when needed.
Be conversational, accurate with names/recipients, and wait for confirmation.`;

    // Build context based on retrieval mode
    let context = '';

    if (retrievalMode === 'memory' || retrievalMode === 'hybrid') {
      // Fetch recent recordings for context (simple text search for now)
      const { data: recordings } = await supabaseAdmin
        .from('recordings')
        .select('transcription, created_at')
        .eq('user_id', userId)
        .eq('status', 'completed')
        .not('transcription', 'is', null)
        .order('created_at', { ascending: false});
      // NO LIMIT - Chat can access ALL transcripts from Supabase

      if (recordings && recordings.length > 0) {
        context = recordings
          .map(r => `[${new Date(r.created_at).toLocaleDateString()}] ${r.transcription}`)
          .join('\n\n');
      }
    }

    // Prepare system prompt based on mode
    let systemPrompt = '';
    if (retrievalMode === 'memory') {
      systemPrompt = `${personality}${capabilities} You have access to the user's voice recordings. Use the following transcriptions to answer questions:\n\n${context || 'No recordings available yet.'}`;
    } else if (retrievalMode === 'web') {
      systemPrompt = `${personality}${capabilities} Answer questions using your general knowledge and web information.`;
    } else {
      // hybrid
      systemPrompt = `${personality}${capabilities} You have access to the user's voice recordings and general knowledge. Use both to provide comprehensive answers.\n\nRecent recordings:\n${context || 'No recordings available yet.'}`;
    }

    // Build messages array with conversation history
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory, // Include full conversation history
      { role: 'user', content: message }
    ];

    // Call OpenAI Chat API with GPT-4o (faster, better conversational, cheaper)
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: messages,
      temperature: 0.7,
      max_tokens: 150, // Enough for confirmation prompts + recipient extraction
    });

    const response = completion.choices[0].message.content;

    res.json({
      success: true,
      response,
      mode: retrievalMode,
      context_used: retrievalMode !== 'web'
    });

  } catch (err) {
    console.error('❌ Chat error:', err);
    res.status(500).json({ error: 'Failed to process chat message' });
  }
});

// ============================================================================
// CONTACT LOOKUP ENDPOINTS - On-Demand Only
// ============================================================================

/**
 * GET /api/contacts/search?q=name
 * Search user's device contacts - returns MAX 2 results only
 * Frontend should send device contacts in request body for server-side matching
 */
app.post('/api/contacts/search', authenticateUser, async (req, res) => {
  try {
    const { query, contacts } = req.body;
    const userId = req.user.id;

    if (!query || !contacts || !Array.isArray(contacts)) {
      return res.status(400).json({ error: 'Query and contacts array required' });
    }

    console.log(`[CONTACT_SEARCH] user=${userId} q="${query}" total_contacts=${contacts.length}`);

    // Simple fuzzy matching (case-insensitive, substring match)
    const queryLower = query.toLowerCase().trim();
    const matches = contacts
      .filter(c => {
        const nameLower = (c.name || '').toLowerCase();
        const emailLower = (c.email || '').toLowerCase();
        const companyLower = (c.company || '').toLowerCase();
        return nameLower.includes(queryLower) || 
               emailLower.includes(queryLower) ||
               companyLower.includes(queryLower);
      })
      .slice(0, 2) // Hard limit: MAX 2 results
      .map((c, idx) => ({
        contact_id: `${userId}-${idx}`, // Ephemeral ID for this session
        display_name: c.name,
        primary_email: c.email || null,
        primary_phone: c.phone || null,
        company: c.company || null
      }));

    console.log(`[CONTACT_SEARCH] results=${matches.length}`);

    res.json({
      success: true,
      results: matches,
      query: query
    });

  } catch (err) {
    console.error('❌ Contact search error:', err);
    res.status(500).json({ error: 'Failed to search contacts' });
  }
});

// ============================================================================
// USER PREFERENCES ENDPOINTS - Priority 4
// ============================================================================

/**
 * GET /api/user/preferences
 * Get user's settings preferences
 */
app.get('/api/user/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: preferences, error } = await supabaseAdmin
      .from('user_preferences')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows found
      console.error('Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch preferences' });
    }

    // Return defaults if no preferences exist yet
    if (!preferences) {
      return res.json({
        success: true,
        preferences: {
          assistant_name: 'Assistant',
          voice_gender: 'female',
          voice_attitude: 'helpful',
          retrieval_mode: 'hybrid',
          tap_detection_enabled: true,
          tap_sensitivity: 'medium',
          double_tap_action: 'record',
          triple_tap_action: 'pause',
        }
      });
    }

    res.json({
      success: true,
      preferences
    });

  } catch (err) {
    console.error('❌ Fetch preferences error:', err);
    res.status(500).json({ error: 'Failed to fetch preferences' });
  }
});

/**
 * POST /api/user/preferences
 * Save/update user's settings preferences
 */
app.post('/api/user/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      assistant_name,
      voice_gender,
      voice_attitude,
      retrieval_mode,
      tap_detection_enabled,
      tap_sensitivity,
      double_tap_action,
      triple_tap_action,
    } = req.body;

    // Check if preferences exist
    const { data: existing } = await supabaseAdmin
      .from('user_preferences')
      .select('user_id')
      .eq('user_id', userId)
      .single();

    const preferencesData = {
      user_id: userId,
      assistant_name,
      voice_gender,
      voice_attitude,
      retrieval_mode,
      tap_detection_enabled,
      tap_sensitivity,
      double_tap_action,
      triple_tap_action,
      updated_at: new Date().toISOString()
    };

    let result;
    if (existing) {
      // Update existing preferences
      result = await supabaseAdmin
        .from('user_preferences')
        .update(preferencesData)
        .eq('user_id', userId)
        .select()
        .single();
    } else {
      // Insert new preferences
      result = await supabaseAdmin
        .from('user_preferences')
        .insert(preferencesData)
        .select()
        .single();
    }

    if (result.error) {
      console.error('Database error:', result.error);
      return res.status(500).json({ error: 'Failed to save preferences' });
    }

    res.json({
      success: true,
      preferences: result.data
    });

  } catch (err) {
    console.error('❌ Save preferences error:', err);
    res.status(500).json({ error: 'Failed to save preferences' });
  }
});

// Auth endpoints
app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('📝 Signup request received:', req.body.email);
    const { email, password, name } = req.body;

    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    // Sign up with Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name: name || null
        }
      }
    });

    if (authError) {
      console.log('❌ Supabase signup error:', authError.message);
      return res.status(400).json({ error: authError.message });
    }

    console.log('✅ Signup successful:', authData.user.id);
    // Return user data and session token
    res.json({
      token: authData.session.access_token,
      user: {
        id: authData.user.id,
        email: authData.user.email,
        name: authData.user.user_metadata?.name,
        created_at: authData.user.created_at
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login request received:', req.body.email);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    // Sign in with Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (authError) {
      console.log('❌ Login failed:', authError.message);
      return res.status(401).json({ error: authError.message });
    }

    console.log('✅ Login successful:', authData.user.id);
    // Return user data and session token
    res.json({
      token: authData.session.access_token,
      user: {
        id: authData.user.id,
        email: authData.user.email,
        name: authData.user.user_metadata?.name,
        created_at: authData.user.created_at
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/reset-password
 * Request password reset email
 */
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    console.log('🔄 Password reset request:', req.body.email);
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'spokennotesclean://reset-password',
    });

    if (error) {
      console.log('❌ Password reset error:', error.message);
      return res.status(400).json({ error: error.message });
    }

    console.log('✅ Password reset email sent to:', email);
    res.json({
      success: true,
      message: 'Password reset email sent. Check your inbox.'
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Google OAuth - Initiate Calendar authorization flow
 */
app.get('/auth/google/initiate', authenticateUser, (req, res) => {
  try {
    console.log('🔐 [OAUTH] Initiating Google Calendar OAuth for user:', req.user.id);

    if (!process.env.GOOGLE_CALENDAR_CLIENT_ID || !process.env.GOOGLE_CALENDAR_CLIENT_SECRET) {
      return res.status(503).json({ error: 'Calendar OAuth not configured' });
    }

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CALENDAR_CLIENT_ID,
      process.env.GOOGLE_CALENDAR_CLIENT_SECRET,
      `${process.env.API_BASE_URL || 'https://spoken-notes-backend-v2.onrender.com'}/auth/google/callback`
    );

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline', // Get refresh token
      prompt: 'consent', // Force consent screen to get refresh token
      scope: ['https://www.googleapis.com/auth/calendar.events'],
      state: req.user.id // Pass user ID for callback identification
    });

    console.log('✅ [OAUTH] Generated auth URL for user:', req.user.id);
    res.json({ authUrl });
  } catch (err) {
    console.error('❌ [OAUTH] Initiation error:', err);
    res.status(500).json({ error: 'Failed to initiate OAuth flow' });
  }
});

/**
 * Google OAuth - Callback handler (receives authorization code)
 */
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state: userId } = req.query;
    console.log('🔐 [OAUTH] Callback received for user:', userId);

    if (!code || !userId) {
      console.log('❌ [OAUTH] Missing code or userId');
      return res.redirect('spokennotesclean://oauth-error?error=missing_params');
    }

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CALENDAR_CLIENT_ID,
      process.env.GOOGLE_CALENDAR_CLIENT_SECRET,
      `${process.env.API_BASE_URL || 'https://spoken-notes-backend-v2.onrender.com'}/auth/google/callback`
    );

    // Exchange authorization code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    console.log('✅ [OAUTH] Received tokens (refresh_token present:', !!tokens.refresh_token, ')');

    if (!tokens.refresh_token) {
      console.log('⚠️ [OAUTH] No refresh token received - user may have already authorized');
      return res.redirect('spokennotesclean://oauth-error?error=no_refresh_token');
    }

    // Store refresh token in database
    const { error: dbError } = await supabaseAdmin
      .from('users')
      .update({
        google_refresh_token: tokens.refresh_token,
        google_token_expires_at: tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : null
      })
      .eq('id', userId);

    if (dbError) {
      console.error('❌ [OAUTH] Failed to store tokens:', dbError);
      return res.redirect('spokennotesclean://oauth-error?error=database_error');
    }

    console.log('✅ [OAUTH] Tokens stored successfully for user:', userId);
    res.redirect('spokennotesclean://oauth-success');
  } catch (err) {
    console.error('❌ [OAUTH] Callback error:', err);
    res.redirect('spokennotesclean://oauth-error?error=token_exchange_failed');
  }
});

/**
 * TTS - Generate speech from text (Premium feature)
 */
app.post('/api/tts', authenticateUser, async (req, res) => {
  try {
    const { text, voiceGender = 'female', voiceSelection = 'voice1' } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    // Map gender + accent to OpenAI voice
    const voiceKey = `${voiceGender}-${voiceSelection}`;
    const voiceMapping = {
      // Female voices
      'female-voice1': 'nova',     // American - warm, engaging
      'female-voice2': 'shimmer',  // British - soft, clear
      'female-voice3': 'nova',     // Australian - use nova
      'female-voice4': 'shimmer',  // Indian - use shimmer
      // Male voices
      'male-voice1': 'onyx',       // American - deep, authoritative
      'male-voice2': 'echo',       // British - clear, professional
      'male-voice3': 'onyx',       // Australian - use onyx
      'male-voice4': 'fable',      // Indian - balanced, clear
    };

    const voice = voiceMapping[voiceKey] || 'nova';

    // Call OpenAI TTS API
    const mp3 = await openai.audio.speech.create({
      model: 'tts-1',
      voice: voice,
      input: text,
      speed: 1.0,
    });

    // Stream audio back to client
    const buffer = Buffer.from(await mp3.arrayBuffer());

    res.set({
      'Content-Type': 'audio/mpeg',
      'Content-Length': buffer.length,
    });

    res.send(buffer);

  } catch (error) {
    console.error('❌ TTS error:', error);
    res.status(500).json({
      error: 'Failed to generate speech',
      message: error.message
    });
  }
});

// ============================================================================
// ASSISTANT ACTIONS - File Creation & Communication (Phase 3)
// ============================================================================

/**
 * POST /api/assistant/create-excel
 * Creates an Excel file from structured data
 */
app.post('/api/assistant/create-excel', authenticateUser, async (req, res) => {
  try {
    const { filename, data, content } = req.body;
    const userId = req.user.id;

    if (!filename) {
      return res.status(400).json({ error: 'Filename is required' });
    }

    const ExcelJS = require('exceljs');
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Sheet1');

    // If structured data provided, use it
    if (data && Array.isArray(data)) {
      // Assume data is array of objects
      const headers = Object.keys(data[0] || {});
      worksheet.addRow(headers);
      data.forEach(row => {
        worksheet.addRow(Object.values(row));
      });
    } else if (content) {
      // Parse content as simple text rows
      const rows = content.split('\n').map(line => [line]);
      rows.forEach(row => worksheet.addRow(row));
    } else {
      worksheet.addRow(['Sample Data']);
    }

    // Generate buffer
    const buffer = await workbook.xlsx.writeBuffer();

    // Store in Supabase storage
    const filePath = `${userId}/assistant/${filename}`;
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('assistant-files')
      .upload(filePath, buffer, {
        contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        upsert: true
      });

    if (uploadError) {
      console.error('Excel upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to save Excel file' });
    }

    // Get public URL
    const { data: urlData } = supabaseAdmin.storage
      .from('assistant-files')
      .getPublicUrl(filePath);

    console.log(`✅ Excel file created: ${filename} for user ${userId}`);

    res.json({
      success: true,
      filename,
      url: urlData.publicUrl,
      path: filePath
    });
  } catch (error) {
    console.error('Error creating Excel file:', error);
    res.status(500).json({ error: 'Failed to create Excel file', details: error.message });
  }
});

/**
 * POST /api/assistant/create-pdf
 * Creates a PDF document from text content
 */
app.post('/api/assistant/create-pdf', authenticateUser, async (req, res) => {
  try {
    const { filename, content, title } = req.body;
    const userId = req.user.id;

    if (!filename || !content) {
      return res.status(400).json({ error: 'Filename and content are required' });
    }

    const PDFDocument = require('pdfkit');
    const chunks = [];

    const doc = new PDFDocument();

    // Collect chunks
    doc.on('data', chunk => chunks.push(chunk));

    // Create PDF content
    if (title) {
      doc.fontSize(20).text(title, { align: 'center' });
      doc.moveDown();
    }

    doc.fontSize(12).text(content, {
      align: 'left',
      lineGap: 5
    });

    doc.end();

    // Wait for completion
    await new Promise((resolve, reject) => {
      doc.on('end', resolve);
      doc.on('error', reject);
    });

    const buffer = Buffer.concat(chunks);

    // Store in Supabase storage
    const filePath = `${userId}/assistant/${filename}`;
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('assistant-files')
      .upload(filePath, buffer, {
        contentType: 'application/pdf',
        upsert: true
      });

    if (uploadError) {
      console.error('PDF upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to save PDF file' });
    }

    // Get public URL
    const { data: urlData } = supabaseAdmin.storage
      .from('assistant-files')
      .getPublicUrl(filePath);

    console.log(`✅ PDF file created: ${filename} for user ${userId}`);

    res.json({
      success: true,
      filename,
      url: urlData.publicUrl,
      path: filePath
    });
  } catch (error) {
    console.error('Error creating PDF file:', error);
    res.status(500).json({ error: 'Failed to create PDF file', details: error.message });
  }
});

/**
 * POST /api/assistant/create-word
 * Creates a Word document (.docx) from text content
 */
app.post('/api/assistant/create-word', authenticateUser, async (req, res) => {
  try {
    const { filename, content, title } = req.body;
    const userId = req.user.id;

    if (!filename || !content) {
      return res.status(400).json({ error: 'Filename and content are required' });
    }

    const { Document, Packer, Paragraph, TextRun, HeadingLevel } = require('docx');

    const paragraphs = [];

    // Add title if provided
    if (title) {
      paragraphs.push(
        new Paragraph({
          text: title,
          heading: HeadingLevel.HEADING_1,
        })
      );
    }

    // Split content into paragraphs
    const contentLines = content.split('\n').filter(line => line.trim());
    contentLines.forEach(line => {
      paragraphs.push(
        new Paragraph({
          children: [new TextRun(line)],
        })
      );
    });

    const doc = new Document({
      sections: [{
        children: paragraphs,
      }],
    });

    const buffer = await Packer.toBuffer(doc);

    // Store in Supabase storage
    const filePath = `${userId}/assistant/${filename}`;
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('assistant-files')
      .upload(filePath, buffer, {
        contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        upsert: true
      });

    if (uploadError) {
      console.error('Word upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to save Word file' });
    }

    // Get public URL
    const { data: urlData } = supabaseAdmin.storage
      .from('assistant-files')
      .getPublicUrl(filePath);

    console.log(`✅ Word file created: ${filename} for user ${userId}`);

    res.json({
      success: true,
      filename,
      fileUrl: urlData.publicUrl
    });
  } catch (error) {
    console.error('Error creating Word file:', error);
    res.status(500).json({ error: 'Failed to create Word file', details: error.message });
  }
});

/**
 * POST /api/assistant/send-email
 * Sends an email via SendGrid (provider-based)
 * From: noreply@thebaxgroupllc.com (verified sender)
 * Reply-To: user's email address
 */
app.post('/api/assistant/send-email', authenticateUser, async (req, res) => {
  // PHASE 1 CHECKPOINT 1: Route Hit
  const requestId = req.headers['x-request-id'] || req.body.request_id || `backend-${Date.now()}`;
  console.log(`[EMAIL] HIT_SEND_EMAIL request_id=${requestId} user_id=${req.user?.id} ip=${req.ip}`);

  try {
    const { recipient, subject, content } = req.body;
    const userId = req.user.id;
    const userEmail = req.user.email;

    // PHASE 1 CHECKPOINT 2: Auth OK
    console.log(`[EMAIL] AUTH_OK request_id=${requestId} user_id=${userId} user_email=${userEmail}`);

    if (!recipient || !content) {
      console.log(`[EMAIL] VALIDATION_FAILED request_id=${requestId} missing_fields=${!recipient ? 'recipient' : 'content'}`);
      return res.status(400).json({ error: 'Recipient and content are required' });
    }

    // Handle "SELF" marker - send to user's own email
    const actualRecipient = recipient === 'SELF' ? userEmail : recipient;
    console.log(`[EMAIL] RECIPIENT_RESOLVED request_id=${requestId} input=${recipient} resolved=${actualRecipient}`);

    // Check if SendGrid is configured
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_FROM_EMAIL) {
      console.warn(`[EMAIL] SENDGRID_NOT_CONFIGURED request_id=${requestId}`);
      return res.status(503).json({
        error: 'Email service not configured',
        draft: true // Signal that email was drafted but not sent
      });
    }

    const emailId = uuidv4();
    const fromEmail = process.env.SENDGRID_FROM_EMAIL; // e.g., assistant@spokennotes.com

    const msg = {
      to: actualRecipient,
      from: fromEmail,
      replyTo: userEmail, // Replies go to the user
      subject: subject || 'Message from Spoken Notes',
      text: content,
      html: content.replace(/\n/g, '<br>'), // Simple HTML formatting
    };

    console.log(`[EMAIL] CALLING_SENDGRID request_id=${requestId} from=${fromEmail} to=${actualRecipient}`);

    const response = await sgMail.send(msg);
    const messageId = response[0].headers['x-message-id'];

    // PHASE 1 CHECKPOINT 3: SendGrid Result
    console.log(`[EMAIL] SENDGRID_RESULT request_id=${requestId} status=accepted msg_id=${messageId}`);

    // Log to Supabase
    await supabaseAdmin
      .from('email_logs')
      .insert({
        id: emailId,
        user_id: userId,
        to_email: recipient,
        from_email: fromEmail,
        reply_to: userEmail,
        subject: msg.subject,
        body: content,
        status: 'sent',
        provider: 'sendgrid',
        provider_message_id: messageId,
        request_id: requestId, // PHASE 1: Store request_id
        sent_at: new Date().toISOString()
      });

    console.log(`[EMAIL] DB_LOGGED request_id=${requestId} email_log_id=${emailId}`);

    res.json({
      success: true,
      messageId,
      recipient,
      requestId // PHASE 1: Return request_id to client
    });
  } catch (error) {
    // PHASE 1 CHECKPOINT 3: SendGrid Error
    console.error(`[EMAIL] SENDGRID_RESULT request_id=${requestId} status=rejected error=${error.message}`);
    console.error('[EMAIL] ERROR_DETAILS:', {
      request_id: requestId,
      message: error.message,
      code: error.code,
      statusCode: error.response?.statusCode,
      body: error.response?.body
    });

    // Log failure to Supabase
    try {
      await supabaseAdmin
        .from('email_logs')
        .insert({
          id: uuidv4(),
          user_id: req.user.id,
          to_email: req.body.recipient,
          from_email: process.env.SENDGRID_FROM_EMAIL,
          reply_to: req.user.email,
          subject: req.body.subject || 'Message from Spoken Notes',
          body: req.body.content,
          status: 'failed',
          provider: 'sendgrid',
          error_message: error.message,
          request_id: requestId, // PHASE 1: Store request_id even on failure
          sent_at: new Date().toISOString()
        });
    } catch (logError) {
      console.error('Failed to log email error:', logError);
    }

    res.status(500).json({
      error: 'Failed to send email',
      details: error.response?.body?.errors?.[0]?.message || error.message
    });
  }
});

/**
 * POST /api/assistant/send-sms
 * Sends an SMS via Twilio (Pattern B - Action Framework)
 * REQUIRES: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER environment variables
 */
app.post('/api/assistant/send-sms', authenticateUser, async (req, res) => {
  const requestStart = Date.now();
  const { request_id, recipient, content } = req.body;
  const userId = req.user.id;

  // Validation
  if (!request_id) {
    return res.status(400).json({ error: 'request_id is required' });
  }
  if (!recipient || !content) {
    return res.status(400).json({ error: 'Recipient and content are required' });
  }

  console.log(`[SMS] 📱 request_id=${request_id} user=${userId} to=${recipient}`);

  try {
    // Check if Twilio is configured
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE_NUMBER) {
      console.warn(`[SMS] ⚠️ Twilio not configured - request_id=${request_id}`);
      
      // Log failure to action_logs
      await supabaseAdmin.from('action_logs').insert({
        request_id,
        user_id: userId,
        action_type: 'send_sms',
        payload_json: { recipient, content },
        status: 'failed',
        provider: 'twilio',
        error_message: 'SMS service not configured (missing Twilio credentials)'
      });
      
      return res.status(503).json({ 
        success: false,
        request_id,
        error: 'SMS service not configured' 
      });
    }

    // Initialize Twilio client
    const twilio = require('twilio');
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

    // Send SMS
    const message = await client.messages.create({
      body: content,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: recipient
    });

    const duration = Date.now() - requestStart;
    console.log(`[SMS] ✅ Sent in ${duration}ms: ${message.sid} to ${recipient} request_id=${request_id}`);

    // Log success to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'send_sms',
      payload_json: { recipient, content },
      status: 'sent',
      provider: 'twilio',
      provider_id: message.sid,
      completed_at: new Date().toISOString()
    });

    res.json({
      success: true,
      request_id,
      provider_id: message.sid,
      recipient,
      status: 'sent'
    });
  } catch (error) {
    const duration = Date.now() - requestStart;
    console.error(`[SMS] ❌ Failed in ${duration}ms: request_id=${request_id} error=${error.message}`);
    
    // Log failure to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'send_sms',
      payload_json: { recipient, content },
      status: 'failed',
      provider: 'twilio',
      error_message: error.message
    });
    
    res.status(500).json({ 
      success: false,
      request_id,
      error: 'Failed to send SMS', 
      details: error.message 
    });
  }
});

/**
 * POST /api/assistant/create-docx
 * Creates a Word document (.docx) using docx library (Pattern B - Action Framework)
 */
app.post('/api/assistant/create-docx', authenticateUser, async (req, res) => {
  const requestStart = Date.now();
  const { request_id, filename, content } = req.body;
  const userId = req.user.id;

  // Validation
  if (!request_id) {
    return res.status(400).json({ error: 'request_id is required' });
  }
  if (!content) {
    return res.status(400).json({ error: 'Content is required' });
  }

  const safeFilename = filename || `document_${Date.now()}.docx`;
  console.log(`[DOCX] 📄 request_id=${request_id} user=${userId} filename=${safeFilename}`);

  try {
    const { Document, Packer, Paragraph, TextRun } = require('docx');
    const fs = require('fs');
    const path = require('path');

    // Create document with content
    const doc = new Document({
      sections: [{
        properties: {},
        children: [
          new Paragraph({
            children: [
              new TextRun({
                text: content,
                size: 24, // 12pt font
              }),
            ],
          }),
        ],
      }],
    });

    // Generate docx buffer
    const buffer = await Packer.toBuffer(doc);

    // For now, save to temporary directory (TODO: Upload to cloud storage)
    const tempDir = path.join(__dirname, 'temp_files');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    const filePath = path.join(tempDir, safeFilename);
    fs.writeFileSync(filePath, buffer);

    const duration = Date.now() - requestStart;
    const fileUrl = `/temp_files/${safeFilename}`; // Temporary local URL

    console.log(`[DOCX] ✅ Created in ${duration}ms: ${safeFilename} request_id=${request_id}`);

    // Log to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_docx',
      payload_json: { filename: safeFilename, content },
      status: 'completed',
      provider: 'docx',
      provider_url: fileUrl,
      completed_at: new Date().toISOString()
    });

    res.json({
      success: true,
      request_id,
      url: fileUrl,
      filename: safeFilename,
      status: 'completed'
    });
  } catch (error) {
    const duration = Date.now() - requestStart;
    console.error(`[DOCX] ❌ Failed in ${duration}ms: request_id=${request_id} error=${error.message}`);

    // Log failure
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_docx',
      payload_json: { filename: safeFilename, content },
      status: 'failed',
      provider: 'docx',
      error_message: error.message
    });

    res.status(500).json({
      success: false,
      request_id,
      error: 'Failed to create document',
      details: error.message
    });
  }
});

/**
 * POST /api/assistant/create-xlsx
 * Creates an Excel spreadsheet (.xlsx) using xlsx library (Pattern B - Action Framework)
 */
app.post('/api/assistant/create-xlsx', authenticateUser, async (req, res) => {
  const requestStart = Date.now();
  const { request_id, filename, content, data } = req.body;
  const userId = req.user.id;

  // Validation
  if (!request_id) {
    return res.status(400).json({ error: 'request_id is required' });
  }
  if (!content && !data) {
    return res.status(400).json({ error: 'Content or data is required' });
  }

  const safeFilename = filename || `spreadsheet_${Date.now()}.xlsx`;
  console.log(`[XLSX] 📊 request_id=${request_id} user=${userId} filename=${safeFilename}`);

  try {
    const XLSX = require('xlsx');
    const fs = require('fs');
    const path = require('path');

    // Create workbook
    const wb = XLSX.utils.book_new();

    // If structured data provided, use it; otherwise parse content as simple rows
    if (data && Array.isArray(data)) {
      const ws = XLSX.utils.json_to_sheet(data);
      XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    } else {
      // Simple text content - split into rows
      const rows = content.split('\\n').map(line => [line]);
      const ws = XLSX.utils.aoa_to_sheet(rows);
      XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    }

    // Write to temporary directory
    const tempDir = path.join(__dirname, 'temp_files');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    const filePath = path.join(tempDir, safeFilename);
    XLSX.writeFile(wb, filePath);

    const duration = Date.now() - requestStart;
    const fileUrl = `/temp_files/${safeFilename}`;

    console.log(`[XLSX] ✅ Created in ${duration}ms: ${safeFilename} request_id=${request_id}`);

    // Log to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_xlsx',
      payload_json: { filename: safeFilename, content, data },
      status: 'completed',
      provider: 'xlsx',
      provider_url: fileUrl,
      completed_at: new Date().toISOString()
    });

    res.json({
      success: true,
      request_id,
      url: fileUrl,
      filename: safeFilename,
      status: 'completed'
    });
  } catch (error) {
    const duration = Date.now() - requestStart;
    console.error(`[XLSX] ❌ Failed in ${duration}ms: request_id=${request_id} error=${error.message}`);

    // Log failure
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_xlsx',
      payload_json: { filename: safeFilename, content, data },
      status: 'failed',
      provider: 'xlsx',
      error_message: error.message
    });

    res.status(500).json({
      success: false,
      request_id,
      error: 'Failed to create spreadsheet',
      details: error.message
    });
  }
});

/**
 * POST /api/assistant/create-calendar-event
 * Creates a calendar event via Google Calendar API (Pattern B - Action Framework)
 * Logs to action_logs with request_id tracking
 */
app.post('/api/assistant/create-calendar-event', authenticateUser, async (req, res) => {
  const requestStart = Date.now();
  const { request_id, title, content, rawContent } = req.body;
  const userId = req.user.id;

  // Validation
  if (!request_id) {
    return res.status(400).json({ error: 'request_id is required' });
  }
  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }

  console.log(`[CALENDAR] 📅 request_id=${request_id} user=${userId} title=${title}`);

  try {
    // Check Google Calendar configuration
    if (!process.env.GOOGLE_CALENDAR_CLIENT_ID || !process.env.GOOGLE_CALENDAR_CLIENT_SECRET) {
      console.log('[CALENDAR] ⚠️ Google Calendar not configured');
      
      await supabaseAdmin.from('action_logs').insert({
        request_id,
        user_id: userId,
        action_type: 'create_calendar_event',
        payload_json: { title, content, rawContent },
        status: 'failed',
        provider: 'google_calendar',
        error_message: 'Calendar service not configured'
      });
      
      return res.status(503).json({ 
        success: false, 
        request_id, 
        error: 'Calendar service not configured. Please provide Google Calendar API credentials.' 
      });
    }

    // Get user's Google Calendar refresh token from database
    const { data: user, error: userError } = await supabaseAdmin
      .from('users')
      .select('google_refresh_token')
      .eq('id', userId)
      .single();

    if (userError || !user) {
      console.log('[CALENDAR] ❌ Failed to fetch user:', userError?.message);
      
      await supabaseAdmin.from('action_logs').insert({
        request_id,
        user_id: userId,
        action_type: 'create_calendar_event',
        payload_json: { title, content, rawContent },
        status: 'failed',
        provider: 'google_calendar',
        error_message: 'User not found'
      });
      
      return res.status(500).json({ 
        success: false, 
        request_id, 
        error: 'Failed to fetch user data' 
      });
    }

    if (!user.google_refresh_token) {
      console.log('[CALENDAR] ⚠️ User has not connected Google Calendar');
      
      await supabaseAdmin.from('action_logs').insert({
        request_id,
        user_id: userId,
        action_type: 'create_calendar_event',
        payload_json: { title, content, rawContent },
        status: 'requires_auth',
        provider: 'google_calendar',
        error_message: 'Google Calendar not connected'
      });
      
      return res.status(401).json({ 
        success: false, 
        request_id, 
        error: 'Google Calendar not connected',
        auth_url: '/auth/google/initiate' 
      });
    }

    // Initialize OAuth2 client with refresh token
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CALENDAR_CLIENT_ID,
      process.env.GOOGLE_CALENDAR_CLIENT_SECRET,
      `${process.env.API_BASE_URL || 'https://spoken-notes-backend-v2.onrender.com'}/auth/google/callback`
    );

    oauth2Client.setCredentials({
      refresh_token: user.google_refresh_token
    });

    // Parse date/time from rawContent (simple heuristic for now)
    // Default: tomorrow at 2:00 PM for 1 hour
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(14, 0, 0, 0);
    
    const eventEnd = new Date(tomorrow);
    eventEnd.setHours(15, 0, 0, 0);

    // Create calendar event
    const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
    
    const event = {
      summary: title,
      description: content || rawContent || '',
      start: {
        dateTime: tomorrow.toISOString(),
        timeZone: 'America/New_York' // TODO: Get user timezone
      },
      end: {
        dateTime: eventEnd.toISOString(),
        timeZone: 'America/New_York'
      }
    };

    const calendarResponse = await calendar.events.insert({
      calendarId: 'primary',
      requestBody: event
    });

    const eventId = calendarResponse.data.id;
    const eventLink = calendarResponse.data.htmlLink;
    
    const duration = Date.now() - requestStart;
    console.log(`[CALENDAR] ✅ Created in ${duration}ms: ${eventId} request_id=${request_id}`);

    // Log success to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_calendar_event',
      payload_json: { title, content, rawContent },
      status: 'completed',
      provider: 'google_calendar',
      provider_id: eventId,
      provider_url: eventLink,
      completed_at: new Date().toISOString()
    });

    res.json({
      success: true,
      request_id,
      provider_id: eventId,
      event_link: eventLink,
      status: 'completed'
    });
  } catch (error) {
    const duration = Date.now() - requestStart;
    console.error(`[CALENDAR] ❌ Failed in ${duration}ms: request_id=${request_id} error=${error.message}`);

    // Log failure
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_calendar_event',
      payload_json: { title, content, rawContent },
      status: 'failed',
      provider: 'google_calendar',
      error_message: error.message
    });

    res.status(500).json({
      success: false,
      request_id,
      error: 'Failed to create calendar event',
      details: error.message
    });
  }
});

/**
 * POST /api/assistant/create-reminder
 * Creates a reminder (internal database) (Pattern B - Action Framework)
 * Logs to action_logs with request_id tracking
 */
app.post('/api/assistant/create-reminder', authenticateUser, async (req, res) => {
  const requestStart = Date.now();
  const { request_id, text, rawContent } = req.body;
  const userId = req.user.id;

  // Validation
  if (!request_id) {
    return res.status(400).json({ error: 'request_id is required' });
  }
  if (!text) {
    return res.status(400).json({ error: 'Text is required' });
  }

  console.log(`[REMINDER] ⏰ request_id=${request_id} user=${userId} text=${text}`);

  try {
    // TODO: Parse remind_at time from rawContent using date/time NLP
    // For now, default to 1 hour from now
    const remindAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    // Insert into reminders table
    const { data: reminder, error: insertError } = await supabaseAdmin
      .from('reminders')
      .insert({
        user_id: userId,
        text: text,
        remind_at: remindAt,
        status: 'pending'
      })
      .select()
      .single();

    if (insertError) {
      console.error('[REMINDER] Insert error:', insertError);
      throw insertError;
    }

    const duration = Date.now() - requestStart;
    console.log(`[REMINDER] ✅ Created in ${duration}ms: ${reminder.id} request_id=${request_id}`);

    // Log to action_logs
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_reminder',
      payload_json: { text, rawContent, remind_at: remindAt },
      status: 'completed',
      provider: 'internal',
      provider_id: reminder.id,
      completed_at: new Date().toISOString()
    });

    res.json({
      success: true,
      request_id,
      provider_id: reminder.id,
      remind_at: remindAt,
      status: 'completed'
    });
  } catch (error) {
    const duration = Date.now() - requestStart;
    console.error(`[REMINDER] ❌ Failed in ${duration}ms: request_id=${request_id} error=${error.message}`);

    // Log failure
    await supabaseAdmin.from('action_logs').insert({
      request_id,
      user_id: userId,
      action_type: 'create_reminder',
      payload_json: { text, rawContent },
      status: 'failed',
      provider: 'internal',
      error_message: error.message
    });

    res.status(500).json({
      success: false,
      request_id,
      error: 'Failed to create reminder',
      details: error.message
    });
  }
});

/**
 * POST /api/assistant/create-note
 * Creates a note/summary similar to recording transcripts
 * Saves to database like recordings
 */
app.post('/api/assistant/create-note', authenticateUser, async (req, res) => {
  try {
    const { title, content } = req.body;
    const userId = req.user.id;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const noteId = uuidv4();
    const noteTitle = title || `Note ${new Date().toLocaleDateString()}`;

    console.log(`📝 Creating note for user ${userId}: "${noteTitle}"`);

    // Insert note into recordings table (reusing existing structure)
    const { data: noteData, error: insertError } = await supabaseAdmin
      .from('recordings')
      .insert({
        id: noteId,
        user_id: userId,
        audio_url: null, // No audio for text notes
        duration_seconds: 0,
        transcription: content,
        status: 'completed',
        created_at: new Date().toISOString()
      })
      .select()
      .single();

    if (insertError) {
      console.error('Note creation error:', insertError);
      return res.status(500).json({ error: 'Failed to save note' });
    }

    console.log(`✅ Note created: ${noteId} for user ${userId}`);

    res.json({
      success: true,
      note: {
        id: noteData.id,
        title: noteTitle,
        content: noteData.transcription,
        created_at: noteData.created_at
      }
    });
  } catch (error) {
    console.error('Error creating note:', error);
    res.status(500).json({ error: 'Failed to create note', details: error.message });
  }
});

// ============================================================================
// BILLING/METERING ENDPOINTS
// ============================================================================

/**
 * POST /api/billing/create-checkout
 * Creates a Stripe Checkout Session for subscription purchase
 * CRITICAL: Sets client_reference_id = user_id for webhook mapping
 */
app.post('/api/billing/create-checkout', authenticateUser, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({ error: 'Stripe not configured' });
    }

    const userId = req.user.id;
    const { priceId, successUrl, cancelUrl } = req.body;

    if (!priceId) {
      return res.status(400).json({ error: 'priceId is required' });
    }

    console.log(`💳 Creating Checkout Session for user ${userId}, price: ${priceId}`);

    // Create Checkout Session with client_reference_id = user_id
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{
        price: priceId,
        quantity: 1,
      }],
      success_url: successUrl || `${process.env.APP_URL || 'https://yourapp.com'}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl || `${process.env.APP_URL || 'https://yourapp.com'}/cancel`,
      client_reference_id: userId, // ← CRITICAL: Maps Stripe customer to app user
      customer_email: req.user.email, // Pre-fill email
      metadata: {
        user_id: userId // Backup mapping
      }
    });

    console.log(`✅ Checkout Session created: ${session.id}`);

    res.json({
      success: true,
      sessionId: session.id,
      url: session.url // Frontend redirects user to this URL
    });

  } catch (err) {
    console.error('❌ Checkout Session creation error:', err);
    res.status(500).json({ error: 'Failed to create checkout session', message: err.message });
  }
});

/**
 * GET /api/billing/usage
 * Returns current storage usage for the authenticated user
 * Reads from user_storage_usage view (combines audio + text bytes)
 */
app.get('/api/billing/usage', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const capBytes = parseInt(process.env.STORAGE_CAP_BYTES) || 262144000; // 250 MB default

    console.log(`📊 Storage usage request from user ${userId}`);

    // Query the user_storage_usage view
    const { data, error } = await supabaseAdmin
      .from('user_storage_usage')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows (user has no uploads yet)
      console.error('❌ Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch storage usage' });
    }

    // If no data, user has 0 bytes used
    const totalBytes = data?.total_bytes || 0;
    const audioBytes = data?.audio_bytes || 0;
    const textBytes = data?.text_bytes || 0;

    const percentUsed = Math.round((totalBytes / capBytes) * 100);

    // Determine alert level
    let alertLevel = 'none';
    if (percentUsed >= 100) {
      alertLevel = 'blocked';
    } else if (percentUsed >= 90) {
      alertLevel = 'critical';
    } else if (percentUsed >= 70) {
      alertLevel = 'warning';
    }

    const usage = {
      total_bytes: totalBytes,
      audio_bytes: audioBytes,
      text_bytes: textBytes,
      cap_bytes: capBytes,
      percent_used: percentUsed,
      alert_level: alertLevel,
      tier: 'free' // TODO: Read from user subscription table when implemented
    };

    console.log(`✅ Usage: ${totalBytes} / ${capBytes} bytes (${percentUsed}%)`);

    res.json({
      success: true,
      usage
    });

  } catch (err) {
    console.error('❌ Billing usage error:', err);
    res.status(500).json({ error: 'Failed to fetch storage usage' });
  }
});

/**
 * GET /api/billing/subscription
 * Returns subscription info + storage metrics (Phase 3: Single source of truth)
 * Used by mobile app for pre-flight storage checks
 */
app.get('/api/billing/subscription', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`📊 Subscription info request from user ${userId}`);

    // Get storage cap based on plan
    // For now: hardcoded to Free (100 MB)
    // TODO: Query subscriptions table when multi-tier billing is implemented
    const plan = 'free';
    let storageCapBytes;

    switch (plan) {
      case 'pro':
        storageCapBytes = 5368709120; // 5 GB
        break;
      case 'plus':
        storageCapBytes = 5368709120; // 5 GB (same as Pro for now)
        break;
      case 'business':
        storageCapBytes = 5368709120; // 5 GB (same as Pro for now)
        break;
      case 'free':
      default:
        storageCapBytes = 104857600; // 100 MB
        break;
    }

    // Query storage usage from user_storage_usage view
    const { data, error } = await supabaseAdmin
      .from('user_storage_usage')
      .select('total_bytes')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows
      console.error('❌ Storage query error:', error);
      return res.status(500).json({ error: 'Failed to fetch storage usage' });
    }

    const storageUsedBytes = data?.total_bytes || 0;

    const subscription = {
      status: 'active', // TODO: Read from subscriptions table
      plan: plan,
      current_period_end: null, // TODO: Read from subscriptions table
      storage_used: storageUsedBytes,
      storage_limit: storageCapBytes,
    };

    console.log(`✅ Subscription: ${plan} | Storage: ${storageUsedBytes} / ${storageCapBytes} bytes`);

    res.json(subscription);

  } catch (err) {
    console.error('❌ Subscription retrieval error:', err);
    res.status(500).json({ error: 'Failed to retrieve subscription' });
  }
});

/**
 * POST /api/billing/cleanup-orphaned-storage
 * Find and delete audio files in storage that have no corresponding DB record
 * This handles orphaned files from deletions before the storage deletion fix
 */
app.post('/api/billing/cleanup-orphaned-storage', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`🧹 Storage cleanup request from user ${userId}`);

    // Get all audio files for this user from storage
    const { data: storageFiles, error: storageError } = await supabaseAdmin.storage
      .from('recordings')
      .list(userId, {
        limit: 1000,
        sortBy: { column: 'created_at', order: 'desc' }
      });

    if (storageError) {
      console.error('❌ Storage list error:', storageError);
      return res.status(500).json({ error: 'Failed to list storage files' });
    }

    if (!storageFiles || storageFiles.length === 0) {
      console.log('✅ No files in storage for this user');
      return res.json({
        success: true,
        orphaned_count: 0,
        bytes_freed: 0,
        message: 'No files found in storage'
      });
    }

    // Get all recording audio URLs from database for this user
    const { data: recordings, error: dbError } = await supabaseAdmin
      .from('recordings')
      .select('audio_url')
      .eq('user_id', userId);

    if (dbError) {
      console.error('❌ Database query error:', dbError);
      return res.status(500).json({ error: 'Failed to query recordings' });
    }

    // Extract filenames from audio URLs
    const dbFilenames = new Set();
    (recordings || []).forEach(rec => {
      if (rec.audio_url) {
        const match = rec.audio_url.match(/\/([^\/]+)$/);
        if (match) {
          dbFilenames.add(match[1]);
        }
      }
    });

    console.log(`📊 Storage: ${storageFiles.length} files | DB: ${dbFilenames.size} references`);

    // Find orphaned files (in storage but not in DB)
    const orphanedFiles = [];
    let totalBytesFreed = 0;

    storageFiles.forEach(file => {
      if (!dbFilenames.has(file.name)) {
        orphanedFiles.push(`${userId}/${file.name}`);
        totalBytesFreed += file.metadata?.size || 0;
      }
    });

    if (orphanedFiles.length === 0) {
      console.log('✅ No orphaned files found - storage is clean');
      return res.json({
        success: true,
        orphaned_count: 0,
        bytes_freed: 0,
        message: 'Storage is already clean - no orphaned files'
      });
    }

    console.log(`🗑️ Found ${orphanedFiles.length} orphaned files (${Math.round(totalBytesFreed / 1024 / 1024)} MB)`);

    // Delete orphaned files in batches of 50
    const batchSize = 50;
    let deletedCount = 0;

    for (let i = 0; i < orphanedFiles.length; i += batchSize) {
      const batch = orphanedFiles.slice(i, i + batchSize);
      const { error: deleteError } = await supabaseAdmin.storage
        .from('recordings')
        .remove(batch);

      if (deleteError) {
        console.error(`⚠️ Batch delete error (continuing):`, deleteError);
      } else {
        deletedCount += batch.length;
        console.log(`✅ Deleted batch ${Math.floor(i / batchSize) + 1}: ${batch.length} files`);
      }
    }

    console.log(`🎉 Cleanup complete: ${deletedCount}/${orphanedFiles.length} files deleted, ${Math.round(totalBytesFreed / 1024 / 1024)} MB freed`);

    res.json({
      success: true,
      orphaned_count: deletedCount,
      bytes_freed: totalBytesFreed,
      message: `Deleted ${deletedCount} orphaned files (${Math.round(totalBytesFreed / 1024 / 1024)} MB freed)`
    });

  } catch (err) {
    console.error('❌ Storage cleanup error:', err);
    res.status(500).json({ error: 'Failed to cleanup storage' });
  }
});

// Automated daily cleanup: Find and remove orphaned storage files across all users
async function cleanupOrphanedStorageGlobal() {
  try {
    console.log('🧹 [CRON] Starting automated global storage cleanup...');

    // Get all users with recordings
    const { data: users, error: userError } = await supabaseAdmin
      .from('recordings')
      .select('user_id')
      .limit(1000);

    if (userError || !users) {
      console.error('❌ [CRON] Failed to get users:', userError);
      return;
    }

    const uniqueUsers = [...new Set(users.map(u => u.user_id))];
    console.log(`📊 [CRON] Checking storage for ${uniqueUsers.length} users...`);

    let totalOrphaned = 0;
    let totalBytesFreed = 0;

    // Process each user (limit to 100 per run to avoid timeouts)
    for (const userId of uniqueUsers.slice(0, 100)) {
      try {
        // Get storage files
        const { data: storageFiles } = await supabaseAdmin.storage
          .from('recordings')
          .list(userId, { limit: 1000 });

        if (!storageFiles || storageFiles.length === 0) continue;

        // Get DB filenames
        const { data: recordings } = await supabaseAdmin
          .from('recordings')
          .select('audio_url')
          .eq('user_id', userId);

        const dbFilenames = new Set();
        (recordings || []).forEach(rec => {
          if (rec.audio_url) {
            const match = rec.audio_url.match(/\/([^\/]+)$/);
            if (match) dbFilenames.add(match[1]);
          }
        });

        // Find orphaned files
        const orphanedFiles = [];
        storageFiles.forEach(file => {
          if (!dbFilenames.has(file.name)) {
            orphanedFiles.push(`${userId}/${file.name}`);
            totalBytesFreed += file.metadata?.size || 0;
          }
        });

        // Delete orphaned files
        if (orphanedFiles.length > 0) {
          const { error: deleteError } = await supabaseAdmin.storage
            .from('recordings')
            .remove(orphanedFiles);

          if (!deleteError) {
            totalOrphaned += orphanedFiles.length;
            console.log(`✅ [CRON] User ${userId}: Deleted ${orphanedFiles.length} orphaned files`);
          }
        }

      } catch (userErr) {
        console.error(`⚠️ [CRON] Error processing user ${userId}:`, userErr);
      }
    }

    console.log(`🎉 [CRON] Global cleanup complete: ${totalOrphaned} files deleted, ${Math.round(totalBytesFreed / 1024 / 1024)} MB freed`);

  } catch (err) {
    console.error('❌ [CRON] Global cleanup error:', err);
  }
}

// Schedule daily cleanup at 2 AM UTC
setInterval(() => {
  const now = new Date();
  if (now.getUTCHours() === 2 && now.getUTCMinutes() === 0) {
    cleanupOrphanedStorageGlobal();
  }
}, 60000); // Check every minute

// Start server
console.log('📍 About to call app.listen() on port', PORT);
const server = app.listen(PORT, '0.0.0.0')
  .on('listening', () => {
    console.log(`🚀 Backend V2 running on http://0.0.0.0:${PORT}`);
    console.log(`📝 Health: http://localhost:${PORT}/health`);
    console.log(`🔗 Routes list: http://localhost:${PORT}/api/routes`);
    console.log(`📧 Email route: POST /api/assistant/send-email (requires auth)`);
    console.log(`🔍 Test route: GET /api/assistant/send-email/test (no auth)`);
    console.log('✅ Server is listening, event loop active');
  })
  .on('error', (err) => {
    console.error('❌ Server startup error:', err);
    process.exit(1);
  });

// Keep process alive - prevent empty event loop exit
setInterval(() => {
  // Keepalive heartbeat
}, 30000);

server.on('error', (err) => {
  console.error('❌ Server error:', err);
  process.exit(1);
});

