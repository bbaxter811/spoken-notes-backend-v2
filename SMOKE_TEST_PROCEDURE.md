# Phase 3 Smoke Test Procedure

## Prerequisites
1. **Backend deployed**: Commit `d3bb315` (or later) live on Render
2. **Supabase migration**: Run `PHASE3_IDEMPOTENCY_UPGRADE.sql` in Supabase SQL Editor
3. **TEST_SECRET configured**: Add env var in Render dashboard → Environment → `TEST_SECRET=<random_string>`

---

## Setup: Generate Test Secret

```powershell
# Generate random 32-character secret
$testSecret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
Write-Host "TEST_SECRET=$testSecret"
```

**Add to Render:**
1. Go to https://dashboard.render.com → your backend service
2. Environment → Add Environment Variable
3. Key: `TEST_SECRET`, Value: `<generated_secret_above>`
4. Save changes (triggers redeploy)

---

## Test 1: Health Check ✅ PASSED

```powershell
Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/health"
```

**Expected**:
```json
{
  "status": "ok",
  "timestamp": "2026-01-29T21:12:24.864Z",
  "message": "Backend V2 - Minimal"
}
```

**Status**: ✅ PASSED (2026-01-29 2:12 PM)

---

## Test 2: Subscription Check

**Get your user_id:**
- Option A: Check Supabase Auth dashboard → Users → copy UUID
- Option B: In APK after login, check AsyncStorage for authToken → decode JWT → extract `sub` claim

```powershell
$testSecret = "YOUR_TEST_SECRET_HERE"
$userId = "YOUR_USER_ID_HERE"

$body = @{
    secret = $testSecret
    userId = $userId
    testType = "subscription"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/api/test/smoke" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

**Expected for Free User**:
```json
{
  "testType": "subscription",
  "userId": "04de1ea7-d49b-4a1e-b2c7-a7dc28829614",
  "subscription": {
    "status": "free",
    "message": "No subscription row"
  },
  "storageLimit": 104857600,   // 100 MB
  "storageUsed": 12345678,
  "planTier": "free",
  "percentUsed": 12
}
```

**Expected for Pro User**:
```json
{
  "testType": "subscription",
  "userId": "04de1ea7-d49b-4a1e-b2c7-a7dc28829614",
  "subscription": {
    "status": "active",
    "price_id": "price_1SuLvnIBMNezxkKM2ZAHzDcf",
    "stripe_customer_id": "cus_Tsh1OdMEqrmAGJ",
    "current_period_end": "2026-02-28T13:51:47.000Z"
  },
  "storageLimit": 5368709120,   // 5 GB
  "storageUsed": 123456789,
  "planTier": "pro",
  "percentUsed": 2
}
```

---

## Test 3: Upload Storage Enforcement

**Test 3a: Upload ALLOWED (below limit)**

```powershell
$testSecret = "YOUR_TEST_SECRET_HERE"
$userId = "YOUR_USER_ID_HERE"

$body = @{
    secret = $testSecret
    userId = $userId
    testType = "upload_check"
    fileSize = 5000000  # 5 MB file
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/api/test/smoke" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

**Expected**:
```json
{
  "testType": "upload_check",
  "result": "ALLOWED",
  "currentUsage": 50000000,      // 50 MB used
  "storageLimit": 104857600,     // 100 MB limit (free)
  "fileSize": 5000000,           // 5 MB file
  "projectedTotal": 55000000,    // 55 MB after upload
  "percentUsed": 52,
  "planTier": "free"
}
```

**Test 3b: Upload BLOCKED (exceeds limit)**

```powershell
$body = @{
    secret = $testSecret
    userId = $userId
    testType = "upload_check"
    fileSize = 60000000  # 60 MB file (would exceed 100 MB cap)
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/api/test/smoke" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

**Expected (HTTP 402)**:
```json
{
  "testType": "upload_check",
  "result": "BLOCKED",
  "code": "STORAGE_LIMIT",
  "blocked_reason": "CAP_WOULD_EXCEED",
  "message": "Storage limit reached. Upgrade your plan to continue.",
  "currentUsage": 50000000,
  "storageLimit": 104857600,
  "fileSize": 60000000,
  "projectedTotal": 110000000,  // Exceeds 100 MB
  "planTier": "free"
}
```

---

## Validation Checklist

- [ ] Test 1: Health check returns 200 OK
- [ ] Test 2: Subscription check returns correct plan + storage limits
- [ ] Test 3a: Upload allowed when below limit (200 OK)
- [ ] Test 3b: Upload blocked when exceeds limit (402 Payment Required)
- [ ] Free tier enforces 100 MB cap
- [ ] Pro tier enforces 5 GB cap
- [ ] Server-side logic matches frontend expectations

---

## Cleanup (After Phase 3 Complete)

**1. Remove test endpoint from code:**
```javascript
// Delete entire /api/test/smoke endpoint block from index.js (lines ~486-633)
```

**2. Remove TEST_SECRET from Render:**
- Dashboard → Environment → Delete `TEST_SECRET` variable

**3. Commit removal:**
```bash
git commit -m "chore: remove temporary Phase 3 test endpoint"
git push origin main
```

---

## Security Notes

⚠️ **This endpoint bypasses authentication for testing only**
- Guarded by secret (not public knowledge)
- Read-only operations (no writes except logging)
- Should be removed after validation
- If leaked, attacker can only read subscription status (low impact)

✅ **Why this is safer than sharing bearer tokens:**
- No user session exposure
- No ability to perform user actions
- Limited scope (2 test operations only)
- Temporary (removed after Phase 3)
- One-time secret (not reusable across sessions)
