// Generate fresh JWT token for admin testing
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://wshtcatmwomyjcnrctul.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_SERVICE_KEY) {
  console.error('❌ SUPABASE_SERVICE_ROLE_KEY not found in .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

async function getAdminToken() {
  try {
    console.log('🔐 Authenticating as bbaxter811@gmail.com...\n');

    // Sign in with email/password
    const { data, error } = await supabase.auth.signInWithPassword({
      email: 'bbaxter811@gmail.com',
      password: 'Locklock1'
    });

    if (error) {
      console.error('❌ Authentication failed:', error.message);
      process.exit(1);
    }

    console.log('✅ Authentication successful!\n');
    console.log('User ID:', data.user.id);
    console.log('Email:', data.user.email);
    console.log('\n📋 Copy this token (valid for 1 hour):\n');
    console.log(data.session.access_token);
    console.log('\n');

    // Test the admin endpoint
    console.log('🧪 Testing admin endpoint...\n');
    const response = await fetch('https://spoken-notes-backend-v2.onrender.com/admin/metrics/overview', {
      headers: {
        'Authorization': `Bearer ${data.session.access_token}`
      }
    });

    const result = await response.json();
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(result, null, 2));

    if (response.status === 200) {
      console.log('\n🎉 ADMIN AUTH SUCCESS! You are authenticated as an admin.');
    } else if (response.status === 500) {
      console.log('\n✅ GOOD! Admin auth works, just need database views.');
    } else if (response.status === 403) {
      console.log('\n⚠️ 403: You are not in admin_users table yet.');
    } else if (response.status === 401) {
      console.log('\n❌ 401: Token validation failed.');
    }

  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

getAdminToken();
