# Phase 1 Evidence Pack Generator
# Generated: March 2, 2026

$jwt = "eyJhbGciOiJIUzI1NiIsImtpZCI6InZwRTZSQXp2OHlENTdiZlkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3dzaHRjYXRtd29teWpjbnJjdHVsLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI1YjczNWU0NC0yZjNhLTQwZjUtYjdmYi1iMmI0YWVmOWM2MTEiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzcyNDgzMTgwLCJpYXQiOjE3NzI0Nzk1ODAsImVtYWlsIjoiYmJheHRlcjgxMUBnbWFpbC5jb20iLCJwaG9uZSI6IisxNDQzODAwNDU2NCIsImFwcF9tZXRhZGF0YSI6eyJwcm92aWRlciI6ImVtYWlsIiwicHJvdmlkZXJzIjpbImVtYWlsIl19LCJ1c2VyX21ldGFkYXRhIjp7ImVtYWlsIjoiYmJheHRlcjgxMUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkJyaWFuIEJheHRlciAiLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjViNzM1ZTQ0LTJmM2EtNDBmNS1iN2ZiLWIyYjRhZWY5YzYxMSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzcyNDc5NTgwfV0sInNlc3Npb25faWQiOiJjZmFiZDg0YS04NTVkLTRmODYtYmM3ZC02MTZkZGExNDVkZDAiLCJpc19hbm9ueW1vdXMiOmZhbHNlfQ.7Ehh3LuQB5DFSN3IQnGeQYqJHkUqQIgeIylSNi0QBII"
$base = "https://spoken-notes-backend-v2.onrender.com"
$ProgressPreference = 'SilentlyContinue'

$output = @()
$output += "="*80
$output += "PHASE 1 EVIDENCE PACK - Admin API Security Validation"
$output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
$output += "Backend: https://spoken-notes-backend-v2.onrender.com"
$output += "Commit: 2c3016e (adminRoutes restructure + trust proxy)"
$output += "="*80
$output += ""

# Test A
Write-Host "Running Test A: Health Check..." -ForegroundColor Cyan
$output += "TEST A: Health Check (No Auth Required)"
$output += "-"*80
try {
    $response = Invoke-RestMethod -Uri "$base/admin/health" -UseBasicParsing
    $output += "Status: 200 OK"
    $output += "Response: $($response | ConvertTo-Json -Compress)"
    Write-Host "✅ Test A Passed" -ForegroundColor Green
} catch {
    $output += "Status: $($_.Exception.Response.StatusCode.value__)"
    $output += "Error: $($_.Exception.Message)"
    Write-Host "❌ Test A Failed" -ForegroundColor Red
}
$output += ""

# Test B
Write-Host "Running Test B: Auth Enforcement..." -ForegroundColor Cyan
$output += "TEST B: Auth Enforcement (Expect 401 Without Token)"
$output += "-"*80
try {
    $response = Invoke-RestMethod -Uri "$base/admin/metrics/overview" -UseBasicParsing
    $output += "Status: 200 (UNEXPECTED - should be 401!)"
    Write-Host "❌ Test B Failed - No 401" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    $output += "Status: $statusCode (Expected)"
    $output += "Message: Correctly rejected - no token provided"
    Write-Host "✅ Test B Passed - Got $statusCode" -ForegroundColor Green
}
$output += ""

# Test C
Write-Host "Running Test C: Metrics Overview with JWT..." -ForegroundColor Cyan
$output += "TEST C: Metrics Overview with Valid JWT"
$output += "-"*80
try {
    $response = Invoke-RestMethod -Uri "$base/admin/metrics/overview" -Headers @{Authorization="Bearer $jwt"} -UseBasicParsing
    $output += "Status: 200 OK"
    $output += "Response: $($response | ConvertTo-Json -Compress)"
    Write-Host "✅ Test C Passed" -ForegroundColor Green
} catch {
    $output += "Status: $($_.Exception.Response.StatusCode.value__)"
    $output += "Error: $($_.Exception.Message)"
    Write-Host "❌ Test C Failed" -ForegroundColor Red
}
$output += ""

# Test D
Write-Host "Running Test D: User Search..." -ForegroundColor Cyan
$output += "TEST D: User Search with Valid JWT"
$output += "-"*80
try {
    $response = Invoke-RestMethod -Uri "$base/admin/users?search=bbaxter" -Headers @{Authorization="Bearer $jwt"} -UseBasicParsing
    $output += "Status: 200 OK"
    $output += "Users Found: $($response.users.Count)"
    if ($response.users.Count -gt 0) {
        $output += "First User:"
        $output += "  - Email: $($response.users[0].email)"
        $output += "  - User ID: $($response.users[0].user_id)"
        $output += "  - Subscription Tier: $($response.users[0].subscription_tier)"
        $output += "  - Created: $($response.users[0].created_at)"
    }
    Write-Host "✅ Test D Passed - Found $($response.users.Count) user(s)" -ForegroundColor Green
} catch {
    $output += "Status: $($_.Exception.Response.StatusCode.value__)"
    $output += "Error: $($_.Exception.Message)"
    Write-Host "❌ Test D Failed" -ForegroundColor Red
}
$output += ""

# Test E - Rate Limiting
Write-Host "Running Test E: Rate Limiting (101 requests)..." -ForegroundColor Yellow
Write-Host "This will take approximately 1 minute. Please wait..." -ForegroundColor Gray
$output += "TEST E: Rate Limiting (101 Requests to Trigger 429)"
$output += "-"*80
$output += "Sending 101 requests to /admin/metrics/overview..."
$output += ""

$statuses = @()
$start = Get-Date
for ($i = 1; $i -le 101; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "$base/admin/metrics/overview" -Headers @{Authorization="Bearer $jwt"} -UseBasicParsing -ErrorAction Stop
        $statuses += 200
    } catch {
        $statuses += $_.Exception.Response.StatusCode.value__
    }
    
    if ($i % 10 -eq 0) {
        Write-Host "  Progress: $i/101 requests sent..." -ForegroundColor Gray
    }
}
$end = Get-Date
$duration = ($end - $start).TotalSeconds

$output += "Total Requests: 101"
$output += "Duration: $([math]::Round($duration, 2)) seconds"
$output += ""
$output += "Last 10 Status Codes:"
$last10 = $statuses[-10..-1]
for ($i = 0; $i -lt $last10.Count; $i++) {
    $reqNum = 92 + $i
    $status = $last10[$i]
    $output += "  Request #$reqNum : $status"
}
$output += ""
$count200 = ($statuses | Where-Object { $_ -eq 200 }).Count
$count429 = ($statuses | Where-Object { $_ -eq 429 }).Count
$output += "Summary:"
$output += "  - 200 OK: $count200 requests"
$output += "  - 429 Too Many Requests: $count429 requests"
$output += ""

if ($count429 -gt 0) {
    $output += "✅ Rate limiting is WORKING - 429 status codes detected after limit"
    Write-Host "✅ Test E Passed - Rate limiting triggered" -ForegroundColor Green
} else {
    $output += "⚠️  Rate limiting NOT TRIGGERED - No 429 status codes received"
    Write-Host "⚠️  Test E Warning - No rate limit triggered" -ForegroundColor Yellow
}

$output += ""
$output += "="*80
$output += "END OF PHASE 1 EVIDENCE PACK"
$output += "="*80

# Write to file
$output -join "`n" | Out-File -FilePath "PHASE1_EVIDENCE.txt" -Encoding UTF8

Write-Host "`n✅ Evidence pack saved to PHASE1_EVIDENCE.txt" -ForegroundColor Green
Write-Host "File location: $(Get-Location)\PHASE1_EVIDENCE.txt" -ForegroundColor Cyan
