# ADMIN API TEST SUITE - Phase 1 Validation
# Run all tests requested by user

# Get fresh token first
Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     ADMIN API TEST SUITE - Phase 1 Validation            ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "Getting fresh JWT token..." -ForegroundColor Gray
$tokenOutput = node get-admin-token.js 2>&1 | Out-String
$tokenMatch = $tokenOutput -match 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
if ($matches) {
    $ADMIN_JWT = $matches[0]
    Write-Host "✅ Token obtained`n" -ForegroundColor Green
}
else {
    Write-Host "❌ Failed to get token" -ForegroundColor Red
    exit 1
}

$H = @{ Authorization = "Bearer $ADMIN_JWT" }

# Test A - Health (no auth)
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Test A — Health Check (no auth, should be 200)" -ForegroundColor White
try {
    $result = Invoke-RestMethod -Uri "https://spoken-notes-backend-v2.onrender.com/admin/health"
    Write-Host "✅ PASS: 200 OK" -ForegroundColor Green
    Write-Host "   Service: $($result.service)" -ForegroundColor Gray
}
catch {
    Write-Host "❌ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test B - 401 without token
Write-Host "Test B — 401 without token" -ForegroundColor White
try {
    $result = Invoke-WebRequest -UseBasicParsing -Uri "https://spoken-notes-backend-v2.onrender.com/admin/metrics/overview"
    Write-Host "❌ FAIL: Got $($result.StatusCode), expected 401" -ForegroundColor Red
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "✅ PASS: 401 Unauthorized" -ForegroundColor Green
    }
    else {
        Write-Host "❌ FAIL: Got $($_.Exception.Response.StatusCode.value__), expected 401" -ForegroundColor Red
    }
}
Write-Host ""

# Test C - 200 with admin token
Write-Host "Test C — Metrics with admin token (should be 200)" -ForegroundColor White
try {
    $result = Invoke-RestMethod -Headers $H -Uri "https://spoken-notes-backend-v2.onrender.com/admin/metrics/overview"
    Write-Host "✅ PASS: 200 OK" -ForegroundColor Green
    Write-Host "   Total users: $($result.metrics.total_users)" -ForegroundColor Gray
}
catch {
    Write-Host "❌ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test D - User search
Write-Host "Test D — User search (should be 200 after adding function)" -ForegroundColor White
try {
    $result = Invoke-RestMethod -Headers $H -Uri "https://spoken-notes-backend-v2.onrender.com/admin/users?search=bbaxter"
    Write-Host "✅ PASS: 200 OK" -ForegroundColor Green
    Write-Host "   Found $($result.users.Count) user(s)" -ForegroundColor Gray
    if ($result.users.Count -gt 0) {
        Write-Host "   First user: $($result.users[0].email)" -ForegroundColor Gray
    }
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "❌ FAIL: HTTP $status" -ForegroundColor Red
    if ($status -eq 500) {
        Write-Host "   ⚠️  Function admin_search_users not created yet in Supabase" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test E - Rate limiting
Write-Host "Test E — Rate limiting (101 requests, should hit 429)" -ForegroundColor White
Write-Host "   This will take ~30-40 seconds..." -ForegroundColor Gray

$codes = @()
$startTime = Get-Date

for ($i = 1; $i -le 101; $i++) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Headers $H -Uri "https://spoken-notes-backend-v2.onrender.com/admin/metrics/overview" -Method GET
        $codes += $r.StatusCode
    }
    catch {
        $codes += $_.Exception.Response.StatusCode.value__
    }
    
    if ($i % 20 -eq 0) {
        Write-Host "   Progress: $i/101 requests..." -ForegroundColor Gray
    }
}

$elapsed = (Get-Date) - $startTime
Write-Host "   Completed in $([int]$elapsed.TotalSeconds) seconds" -ForegroundColor Gray
Write-Host "`n   Last 10 status codes:" -ForegroundColor White
$codes[-10..-1] | ForEach-Object { 
    if ($_ -eq 429) { 
        Write-Host "     $_" -ForegroundColor Yellow 
    }
    else { 
        Write-Host "     $_" -ForegroundColor Gray 
    }
}

if ($codes -contains 429) {
    $firstLimit = $codes.IndexOf(429) + 1
    Write-Host "`n✅ PASS: Rate limit triggered at request #$firstLimit" -ForegroundColor Green
}
else {
    Write-Host "`n❌ FAIL: No rate limit detected (expected 429 after 100 requests)" -ForegroundColor Red
}

Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                    TEST SUMMARY" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
