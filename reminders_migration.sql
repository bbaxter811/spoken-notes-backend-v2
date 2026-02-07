-- =============================================
-- Reminders Table Migration
-- Pattern B: Internal database storage for reminders
-- =============================================

-- Create reminders table
CREATE TABLE IF NOT EXISTS reminders (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  remind_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'cancelled')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  sent_at TIMESTAMPTZ
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_reminders_user_id ON reminders(user_id);
CREATE INDEX IF NOT EXISTS idx_reminders_remind_at ON reminders(remind_at);
CREATE INDEX IF NOT EXISTS idx_reminders_status ON reminders(status);
CREATE INDEX IF NOT EXISTS idx_reminders_pending_upcoming ON reminders(status, remind_at) 
  WHERE status = 'pending';

-- Enable Row Level Security
ALTER TABLE reminders ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Users can manage their own reminders
DROP POLICY IF EXISTS "Users can manage own reminders" ON reminders;
CREATE POLICY "Users can manage own reminders"
  ON reminders FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- RLS Policy: Service role can manage all reminders (for background worker)
DROP POLICY IF EXISTS "Service role can manage all reminders" ON reminders;
CREATE POLICY "Service role can manage all reminders"
  ON reminders FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

-- Optional: Create a function to mark reminders as sent
CREATE OR REPLACE FUNCTION mark_reminder_sent(reminder_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE reminders
  SET status = 'sent', sent_at = NOW()
  WHERE id = reminder_id AND status = 'pending';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Optional: Create a function to get pending reminders (for background worker)
CREATE OR REPLACE FUNCTION get_pending_reminders()
RETURNS TABLE (
  id UUID,
  user_id UUID,
  text TEXT,
  remind_at TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT r.id, r.user_id, r.text, r.remind_at
  FROM reminders r
  WHERE r.status = 'pending' AND r.remind_at <= NOW()
  ORDER BY r.remind_at ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Comments for documentation
COMMENT ON TABLE reminders IS 'Stores user reminders with scheduled delivery times';
COMMENT ON COLUMN reminders.status IS 'pending=awaiting delivery, sent=delivered, cancelled=user cancelled';
COMMENT ON COLUMN reminders.remind_at IS 'When to send the reminder notification';
COMMENT ON COLUMN reminders.sent_at IS 'When reminder was actually sent (NULL if not sent yet)';
