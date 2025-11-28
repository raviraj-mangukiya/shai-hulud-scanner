# Download Latest Shai-Hulud IOCs
# Fetches the latest IOC data from Wiz Research and other sources

param(
    [string]$ConfigPath = "config.json",
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir $ConfigPath
$iocCacheDir = Join-Path $scriptDir "ioc-cache"
$iocCacheFile = Join-Path $iocCacheDir "iocs.json"
$lastUpdateFile = Join-Path $iocCacheDir "last-update.txt"

# Create cache directory if it doesn't exist
if (-not (Test-Path $iocCacheDir)) {
    New-Item -ItemType Directory -Path $iocCacheDir -Force | Out-Null
}

# Load configuration
if (-not (Test-Path $configFile)) {
    Write-Host "Error: Config file not found: $configFile" -ForegroundColor Red
    exit 1
}

$config = Get-Content $configFile -Raw | ConvertFrom-Json

# Check if update is needed
$needsUpdate = $Force
if (-not $needsUpdate -and (Test-Path $lastUpdateFile)) {
    $lastUpdate = Get-Content $lastUpdateFile
    $lastUpdateTime = [DateTime]::Parse($lastUpdate)
    $updateInterval = [TimeSpan]::FromHours($config.update_interval_hours)
    $needsUpdate = (Get-Date) - $lastUpdateTime -gt $updateInterval
}

if (-not $needsUpdate -and (Test-Path $iocCacheFile)) {
    Write-Host "IOC cache is up to date. Use -Force to force update." -ForegroundColor Green
    exit 0
}

Write-Host "Downloading latest Shai-Hulud IOCs..." -ForegroundColor Cyan
Write-Host ""

$allIocs = @{
    patterns = $config.ioc_patterns
    sources = @()
    last_updated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    version = "1.0"
}

$successCount = 0
$failCount = 0

foreach ($source in $config.ioc_sources) {
    if (-not $source.enabled) {
        continue
    }

    Write-Host "Fetching from: $($source.name)" -ForegroundColor Yellow
    
    $urls = @($source.url)
    if ($source.fallback_url) {
        $urls += $source.fallback_url
    }

    $success = $false
    foreach ($url in $urls) {
        try {
            Write-Host "  Trying: $url" -ForegroundColor Gray
            
            # Use Invoke-WebRequest with proper error handling
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                $remoteIocs = $response.Content | ConvertFrom-Json
                
                # Merge remote IOCs with local patterns
                if ($remoteIocs.patterns) {
                    foreach ($patternType in $remoteIocs.patterns.PSObject.Properties.Name) {
                        if (-not $allIocs.patterns.$patternType) {
                            $allIocs.patterns | Add-Member -MemberType NoteProperty -Name $patternType -Value @()
                        }
                        $allIocs.patterns.$patternType = $allIocs.patterns.$patternType + $remoteIocs.patterns.$patternType | Select-Object -Unique
                    }
                }
                
                $allIocs.sources += @{
                    name = $source.name
                    url = $url
                    fetched_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
                
                Write-Host "  [OK] Successfully fetched from $($source.name)" -ForegroundColor Green
                $success = $true
                $successCount++
                break
            }
        }
        catch {
            Write-Host "  [ERROR] Failed: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if (-not $success) {
        Write-Host "  [ERROR] Failed to fetch from $($source.name)" -ForegroundColor Red
        $failCount++
    }
}

# If all sources failed, use local patterns from config
if ($successCount -eq 0) {
    Write-Host ""
    Write-Host "Warning: Could not fetch remote IOCs. Using local patterns from config." -ForegroundColor Yellow
    $allIocs.sources += @{
        name = "Local Config"
        url = "local"
        fetched_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# Save IOCs to cache
$allIocs | ConvertTo-Json -Depth 10 | Set-Content $iocCacheFile -Encoding UTF8
(Get-Date).ToString("yyyy-MM-dd HH:mm:ss") | Set-Content $lastUpdateFile

Write-Host ""
Write-Host "IOC download complete!" -ForegroundColor Green
Write-Host "  Successfully fetched: $successCount source(s)" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "  Failed: $failCount source(s)" -ForegroundColor Yellow
}
Write-Host "  Cache file: $iocCacheFile" -ForegroundColor Gray
Write-Host ""
