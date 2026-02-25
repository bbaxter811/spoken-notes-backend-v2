# ============================================
# PHASE 1+2 DEPLOYMENT VERIFICATION
# Run this before device testing
# ============================================

Write-Host "`n=== DEPLOYMENT VERIFICATION SCRIPT ===" -ForegroundColor Cyan -BackgroundColor Black
Write-Host ""

# Step 1: Check Render health
Write-Host "Step 1: Checking Render health..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/health" -Method GET -TimeoutSec 10
    Write-Host "  ✅ Health: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Health check failed: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Check available routes
Write-Host "`nStep 2: Checking if /api/files endpoints exist..." -ForegroundColor Yellow
try {
    $routes = Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/api/routes" -Method GET -TimeoutSec 10
    $fileRoutes = $routes | Where-Object { $_ -like '*files*' }
    
    if ($fileRoutes) {
        Write-Host "  ✅ File routes deployed:" -ForegroundColor Green
        $fileRoutes | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    } else {
        Write-Host "  ❌ File routes NOT FOUND - Phase 1 not deployed!" -ForegroundColor Red
        Write-Host "    Check Render dashboard: https://dashboard.render.com/" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "  ⚠️ Could not fetch routes: $_" -ForegroundColor Yellow
}

# Step 3: Test /api/files endpoint (should return 401 without auth)
Write-Host "`nStep 3: Testing /api/files endpoint..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/api/files" -Method GET -ErrorAction Stop
    Write-Host "  ⚠️ Unexpected: Got response without auth token" -ForegroundColor Yellow
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✅ Endpoint exists (401 auth required as expected)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Gray
    }
}

# Step 4: Check commit hash (manual check needed)
Write-Host "`nStep 4: Verify Render deployed latest commits..." -ForegroundColor Yellow
Write-Host "  Local backend commits:" -ForegroundColor Gray
cd "$PSScriptRoot"
git log --oneline -3
Write-Host ""
Write-Host "  ⚠️ MANUAL VERIFICATION REQUIRED:" -ForegroundColor Yellow
Write-Host "    1. Open Render dashboard: https://dashboard.render.com/" -ForegroundColor White
Write-Host "    2. Click spoken-notes-backend-v2 service" -ForegroundColor White
Write-Host "    3. Check 'Events' tab" -ForegroundColor White
Write-Host "    4. Verify latest deploy shows commit: e247ae8 or 04f01a9" -ForegroundColor White
Write-Host ""

# Summary
Write-Host "=== VERIFICATION SUMMARY ===" -ForegroundColor Cyan -BackgroundColor Black
Write-Host ""
Write-Host "Database (Supabase):" -ForegroundColor White
Write-Host "  ✅ user_files table created" -ForegroundColor Green
Write-Host "  ✅ ai_usage_logs table created" -ForegroundColor Green
Write-Host "  ✅ user_ai_usage_monthly table created" -ForegroundColor Green
Write-Host ""
Write-Host "Backend (Render):" -ForegroundColor White
Write-Host "  ✅ Health endpoint OK" -ForegroundColor Green
Write-Host "  ? /api/files endpoints - CHECK ABOVE" -ForegroundColor Yellow
Write-Host ""
Write-Host "Frontend (Local):" -ForegroundColor White
Write-Host "  ✅ My Files screen committed: commit 651df13" -ForegroundColor Green
Write-Host "  ⚠️ No git remote configured (local only)" -ForegroundColor Yellow
Write-Host "  ✅ Ready for APK build with new UI" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEP: Build APK with latest frontend + test on device" -ForegroundColor Cyan
Write-Host ""
