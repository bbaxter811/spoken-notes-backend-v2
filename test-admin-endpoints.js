// Comprehensive test of all admin endpoints
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://wshtcatmwomyjcnrctul.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BASE_URL = 'https://spoken-notes-backend-v2.onrender.com';

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// Test results tracking
const results = {
  passed: [],
  failed: [],
  warnings: []
};

async function testEndpoint(name, url, token, expectedStatus = 200) {
  try {
    const response = await fetch(url, {
      headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    });

    const contentType = response.headers.get('content-type');
    let data;

    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    const success = response.status === expectedStatus;
    const result = {
      name,
      url,
      status: response.status,
      expectedStatus,
      success,
      data: typeof data === 'string' ? data.substring(0, 200) : data
    };

    if (success) {
      results.passed.push(result);
      console.log(`✅ PASS: ${name} (${response.status})`);
    } else {
      results.failed.push(result);
      console.log(`❌ FAIL: ${name} (got ${response.status}, expected ${expectedStatus})`);
    }

    return result;
  } catch (error) {
    const result = {
      name,
      url,
      status: 'ERROR',
      expectedStatus,
      success: false,
      error: error.message
    };
    results.failed.push(result);
    console.log(`❌ ERROR: ${name} - ${error.message}`);
    return result;
  }
}

async function runTests() {
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   ADMIN DASHBOARD API - COMPREHENSIVE TEST SUITE         ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  // Get admin token
  console.log('🔐 Authenticating as admin...\n');
  const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
    email: 'bbaxter811@gmail.com',
    password: 'Locklock1'
  });

  if (authError) {
    console.error('❌ FATAL: Authentication failed:', authError.message);
    process.exit(1);
  }

  const token = authData.session.access_token;
  console.log('✅ Admin authenticated\n');
  console.log('═══════════════════════════════════════════════════════════\n');

  // Test 1: Health endpoint (no auth)
  console.log('TEST 1: Health Check (No Auth Required)');
  await testEndpoint('Health Check', `${BASE_URL}/admin/health`, null, 200);
  console.log('');

  // Test 2: Metrics Overview
  console.log('TEST 2: Metrics Overview');
  await testEndpoint('Metrics Overview', `${BASE_URL}/admin/metrics/overview`, token, 200);
  console.log('');

  // Test 3: AI Usage Metrics
  console.log('TEST 3: AI Usage Metrics');
  await testEndpoint('AI Usage Top Users', `${BASE_URL}/admin/metrics/ai-usage`, token, 200);
  console.log('');

  // Test 4: Storage Metrics
  console.log('TEST 4: Storage Metrics');
  await testEndpoint('Storage Top Users', `${BASE_URL}/admin/metrics/storage`, token, 200);
  console.log('');

  // Test 5: Subscription Summary
  console.log('TEST 5: Subscription Summary');
  await testEndpoint('Subscription Summary', `${BASE_URL}/admin/metrics/subscriptions`, token, 200);
  console.log('');

  // Test 6: User Search
  console.log('TEST 6: User Search');
  await testEndpoint('User Search', `${BASE_URL}/admin/users?search=bbaxter`, token, 200);
  console.log('');

  // Test 7: Audit Log
  console.log('TEST 7: Audit Log');
  await testEndpoint('Audit Log', `${BASE_URL}/admin/actions?limit=10`, token, 200);
  console.log('');

  // Test 8: Auth Required (should fail without token)
  console.log('TEST 8: Auth Required (No Token)');
  await testEndpoint('Metrics Without Token', `${BASE_URL}/admin/metrics/overview`, null, 401);
  console.log('');

  // Test 9: Admin-only access (test with regular user token would go here)
  console.log('TEST 9: Rate Limiting Check');
  console.log('⏭️  SKIP: Rate limiting requires 100+ requests\n');
  results.warnings.push({
    name: 'Rate Limiting',
    message: 'Skipped - requires 100+ requests to test'
  });

  // Print summary
  console.log('═══════════════════════════════════════════════════════════\n');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║                     TEST SUMMARY                         ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  console.log(`✅ PASSED: ${results.passed.length}`);
  console.log(`❌ FAILED: ${results.failed.length}`);
  console.log(`⚠️  WARNINGS: ${results.warnings.length}\n`);

  if (results.passed.length > 0) {
    console.log('PASSED TESTS:');
    results.passed.forEach(test => {
      console.log(`  ✅ ${test.name} (${test.status})`);
    });
    console.log('');
  }

  if (results.failed.length > 0) {
    console.log('FAILED TESTS:');
    results.failed.forEach(test => {
      console.log(`  ❌ ${test.name} (${test.status})`);
      if (test.error) {
        console.log(`     Error: ${test.error}`);
      } else if (test.data) {
        const preview = typeof test.data === 'object'
          ? JSON.stringify(test.data, null, 2).substring(0, 150)
          : test.data.substring(0, 150);
        console.log(`     Response: ${preview}...`);
      }
    });
    console.log('');
  }

  if (results.warnings.length > 0) {
    console.log('WARNINGS:');
    results.warnings.forEach(warning => {
      console.log(`  ⚠️  ${warning.name}: ${warning.message}`);
    });
    console.log('');
  }

  console.log('═══════════════════════════════════════════════════════════\n');

  // Final verdict
  if (results.failed.length === 0) {
    console.log('🎉 ALL TESTS PASSED! Admin Dashboard API is fully operational.\n');
  } else {
    console.log(`⚠️  ${results.failed.length} test(s) failed. Review errors above.\n`);
  }

  // Detailed results for specific endpoints
  console.log('═══════════════════════════════════════════════════════════\n');
  console.log('DETAILED ENDPOINT RESPONSES:\n');

  const metricsTest = results.passed.find(t => t.name === 'Metrics Overview');
  if (metricsTest) {
    console.log('📊 Metrics Overview:');
    console.log(JSON.stringify(metricsTest.data, null, 2));
    console.log('');
  }

  const usersTest = results.passed.find(t => t.name === 'User Search');
  if (usersTest) {
    console.log('👥 User Search Results:');
    console.log(JSON.stringify(usersTest.data, null, 2));
    console.log('');
  }

  const auditTest = results.passed.find(t => t.name === 'Audit Log');
  if (auditTest) {
    console.log('📝 Audit Log:');
    console.log(JSON.stringify(auditTest.data, null, 2));
    console.log('');
  }
}

runTests().catch(err => {
  console.error('❌ Test suite error:', err);
  process.exit(1);
});
