-- PHASE 3: Stripe Webhook Idempotency Upgrade
-- Run this in Supabase SQL Editor BEFORE deploying backend changes

-- Create processed_stripe_events table to prevent duplicate event processing
CREATE TABLE IF NOT EXISTS processed_stripe_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_processed_events_type ON processed_stripe_events(event_type);
CREATE INDEX IF NOT EXISTS idx_processed_events_timestamp ON processed_stripe_events(processed_at);

-- Grant insert access to service role (backend webhook handler)
-- Note: No RLS needed - only backend can write to this table

-- Optional: Cleanup old events (keep last 30 days)
-- Run this periodically via cron job or manually:
-- DELETE FROM processed_stripe_events WHERE processed_at < NOW() - INTERVAL '30 days';

-- Verify table created
SELECT * FROM processed_stripe_events LIMIT 0;
