-- Add phone number to auth.users for SMS "send me" support
-- Run this in Supabase SQL Editor

-- Supabase auth.users already has a 'phone' column (nullable)
-- We just need to populate it for existing user

-- Update your user's phone number (replace USER_ID with your actual UUID)
-- You can find your user ID by running: SELECT id, email FROM auth.users;

-- FOR NOW: Using Supabase dashboard's Authentication > Users > Edit User
-- to add phone: +14438004564

-- Future users: Phone captured during signup or in settings

-- Example query to check:
-- SELECT id, email, phone FROM auth.users WHERE email = 'bbaxter811@gmail.com';
