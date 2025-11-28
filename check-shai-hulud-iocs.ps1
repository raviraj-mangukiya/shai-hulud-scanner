# Shai-Hulud IOC Detection Script
# Based on Wiz Research findings
# This script downloads the latest IOCs and checks for Indicators of Compromise (IOCs)

param(
    [string]$ProjectPath = "..",
    [switch]$Verbose,
    [switch]$SkipDownload
)

$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "config.json"
$iocCacheFile = Join-Path $scriptDir "ioc-cache\iocs.json"
$downloadScript = Join-Path $scriptDir "download-iocs.ps1"

# Download latest IOCs first
if (-not $SkipDownload) {
    Write-Host "Updating IOCs..." -ForegroundColor Cyan
    & $downloadScript -ConfigPath "config.json"
    Write-Host ""
}

# Load IOCs from cache
$iocs = $null
if (Test-Path $iocCacheFile) {
    try {
        $iocs = Get-Content $iocCacheFile -Raw | ConvertFrom-Json
        Write-Host "Loaded IOCs from cache (last updated: $($iocs.last_updated))" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Could not load IOC cache. Using default patterns." -ForegroundColor Yellow
    }
}

# Fallback to config if cache is not available
if (-not $iocs) {
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        $iocs = @{
            patterns = $config.ioc_patterns
            last_updated = "local config"
        }
        Write-Host "Using IOCs from local config" -ForegroundColor Yellow
    }
    else {
        Write-Host "Error: No IOC data available. Please run download-iocs.ps1 first." -ForegroundColor Red
        exit 1
    }
}

$foundIOCs = @()
$scanResults = @{
    PostinstallScripts = @()
    BundleJsInTarballs = @()
    SuspiciousWorkflows = @()
    SuspiciousPackages = @()
    FileHashes = @()
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Shai-Hulud IOC Scanner" -ForegroundColor Cyan
Write-Host "Based on Wiz Research" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = (Resolve-Path $ProjectPath).Path
Write-Host "Scanning project: $projectRoot" -ForegroundColor Yellow
Write-Host ""

# Load compromised packages list from CSV
$compromisedPackages = @()
$compromisedPackagesCacheFile = Join-Path $scriptDir "ioc-cache\compromised-packages.json"
$config = Get-Content $configFile -Raw | ConvertFrom-Json

if ($config.compromised_packages_csv_url) {
    try {
        # Check if cache exists and is recent (within 24 hours)
        $shouldDownload = $true
        if (Test-Path $compromisedPackagesCacheFile) {
            $cacheData = Get-Content $compromisedPackagesCacheFile -Raw | ConvertFrom-Json
            $cacheTime = [DateTime]::Parse($cacheData.last_updated)
            $hoursSinceUpdate = (Get-Date) - $cacheTime
            if ($hoursSinceUpdate.TotalHours -lt 24) {
                $shouldDownload = $false
                $compromisedPackages = $cacheData.packages
                if ($Verbose) {
                    Write-Host "Loaded $($compromisedPackages.Count) compromised packages from cache" -ForegroundColor Gray
                }
            }
        }
        
        if ($shouldDownload -and -not $SkipDownload) {
            if ($Verbose) {
                Write-Host "Downloading compromised packages list..." -ForegroundColor Gray
            }
            $csvContent = Invoke-WebRequest -Uri $config.compromised_packages_csv_url -UseBasicParsing | Select-Object -ExpandProperty Content
            $lines = $csvContent -split "`n" | Where-Object { $_ -and $_ -notmatch "^Package," }
            
            foreach ($line in $lines) {
                $packageName = ($line -split ",")[0].Trim()
                if ($packageName -and $packageName -ne "Package") {
                    $compromisedPackages += $packageName
                }
            }
            
            # Cache the results
            $cacheDir = Split-Path $compromisedPackagesCacheFile -Parent
            if (-not (Test-Path $cacheDir)) {
                New-Item -ItemType Directory -Path $cacheDir | Out-Null
            }
            @{
                packages = $compromisedPackages
                last_updated = (Get-Date).ToString("o")
            } | ConvertTo-Json | Set-Content $compromisedPackagesCacheFile
            
            if ($Verbose) {
                Write-Host "Downloaded and cached $($compromisedPackages.Count) compromised packages" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "Warning: Could not download compromised packages list: $_" -ForegroundColor Yellow
        # Try to load from cache as fallback
        if (Test-Path $compromisedPackagesCacheFile) {
            try {
                $cacheData = Get-Content $compromisedPackagesCacheFile -Raw | ConvertFrom-Json
                $compromisedPackages = $cacheData.packages
                Write-Host "Loaded $($compromisedPackages.Count) compromised packages from cache (fallback)" -ForegroundColor Yellow
            }
            catch {
                # Cache is corrupted, ignore
            }
        }
    }
}

# Function to calculate SHA-256 hash
function Get-FileHash256 {
    param([string]$FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    }
    catch {
        return $null
    }
}

# Function to calculate SHA-1 hash
function Get-FileHash1 {
    param([string]$FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA1 -ErrorAction Stop
        return $hash.Hash.ToLower()
    }
    catch {
        return $null
    }
}

# Function to check for postinstall scripts in package.json files
function Check-PostinstallScripts {
    Write-Host "[1/5] Checking for malicious 'postinstall' scripts in package.json files..." -ForegroundColor Green
    
    $packageJsonFiles = Get-ChildItem -Path $projectRoot -Filter "package.json" -Recurse -ErrorAction SilentlyContinue
    
    $patterns = $iocs.patterns.postinstall_patterns
    if (-not $patterns) {
        $patterns = @("bundle\.js", "toJSON\(secrets\)", "eval\(", "require\(.*process", "child_process", "exec\(", "spawn\(")
    }
    
    foreach ($file in $packageJsonFiles) {
        try {
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
            
            if ($content.scripts -and $content.scripts.postinstall) {
                $postinstallScript = $content.scripts.postinstall
                
                $isSuspicious = $false
                $matchedPatterns = @()
                
                foreach ($pattern in $patterns) {
                    if ($postinstallScript -match $pattern) {
                        $isSuspicious = $true
                        $matchedPatterns += $pattern
                    }
                }
                
                $result = @{
                    File = $file.FullName
                    Script = $postinstallScript
                    IsSuspicious = $isSuspicious
                    MatchedPatterns = $matchedPatterns
                }
                
                $scanResults.PostinstallScripts += $result
                
                if ($isSuspicious) {
                    Write-Host "  [WARNING] Suspicious postinstall script found in: $($file.FullName)" -ForegroundColor Red
                    Write-Host "    Script: $postinstallScript" -ForegroundColor Yellow
                    Write-Host "    Matched patterns: $($matchedPatterns -join ', ')" -ForegroundColor Yellow
                    $foundIOCs += "Suspicious postinstall script in $($file.FullName)"
                } elseif ($Verbose) {
                    Write-Host "  [INFO] Postinstall script found in: $($file.FullName)" -ForegroundColor Gray
                    Write-Host "    Script: $postinstallScript" -ForegroundColor Gray
                }
            }
        }
        catch {
            if ($Verbose) {
                Write-Host "  [INFO] Could not parse package.json: $($file.FullName)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "  Found $($scanResults.PostinstallScripts.Count) package.json files with postinstall scripts" -ForegroundColor $(if ($scanResults.PostinstallScripts.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""
}

# Function to check for bundle.js in tarballs
function Check-BundleJsInTarballs {
    Write-Host "[2/5] Checking for 'bundle.js' in npm tarball files (.tgz)..." -ForegroundColor Green
    
    $tarballFiles = Get-ChildItem -Path $projectRoot -Filter "*.tgz" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($tarball in $tarballFiles) {
        try {
            $tarAvailable = Get-Command tar -ErrorAction SilentlyContinue
            
            if ($tarAvailable) {
                $contents = tar -tf $tarball.FullName 2>$null
                if ($contents -match "bundle\.js") {
                    $result = @{
                        File = $tarball.FullName
                        ContainsBundleJs = $true
                    }
                    $scanResults.BundleJsInTarballs += $result
                    Write-Host "  [WARNING] Found bundle.js in tarball: $($tarball.FullName)" -ForegroundColor Red
                    $foundIOCs += "bundle.js found in tarball $($tarball.FullName)"
                }
            } else {
                $7zipAvailable = Get-Command 7z -ErrorAction SilentlyContinue
                if ($7zipAvailable) {
                    $contents = 7z l $tarball.FullName 2>$null
                    if ($contents -match "bundle\.js") {
                        $result = @{
                            File = $tarball.FullName
                            ContainsBundleJs = $true
                        }
                        $scanResults.BundleJsInTarballs += $result
                        Write-Host "  [WARNING] Found bundle.js in tarball: $($tarball.FullName)" -ForegroundColor Red
                        $foundIOCs += "bundle.js found in tarball $($tarball.FullName)"
                    }
                } else {
                    if ($Verbose) {
                        Write-Host "  [INFO] Cannot check tarball contents (tar or 7zip not available): $($tarball.FullName)" -ForegroundColor Gray
                    }
                }
            }
        }
        catch {
            if ($Verbose) {
                Write-Host "  [INFO] Error checking tarball: $($tarball.FullName)" -ForegroundColor Gray
            }
        }
    }
    
    if ($tarballFiles.Count -eq 0) {
        Write-Host "  No .tgz files found" -ForegroundColor Green
    } else {
        Write-Host "  Checked $($tarballFiles.Count) tarball file(s)" -ForegroundColor $(if ($scanResults.BundleJsInTarballs.Count -gt 0) { "Yellow" } else { "Green" })
    }
    Write-Host ""
}

# Function to check for suspicious GitHub workflows
function Check-SuspiciousWorkflows {
    Write-Host "[3/5] Checking for suspicious GitHub workflows..." -ForegroundColor Green
    
    $workflowDirs = @()
    $workflowDirs += Join-Path $projectRoot ".github\workflows"
    $workflowDirs += Join-Path $projectRoot ".github"
    
    $workflowFiles = @()
    foreach ($dir in $workflowDirs) {
        if (Test-Path $dir) {
            $workflowFiles += Get-ChildItem -Path $dir -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
            $workflowFiles += Get-ChildItem -Path $dir -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue
        }
    }
    
    $patterns = $iocs.patterns.suspicious_workflow_patterns
    if (-not $patterns) {
        $patterns = @("toJSON\(secrets\)", "shai-hulud", "shai-hulud-workflow")
    }
    
    $suspiciousWorkflowFiles = $iocs.patterns.suspicious_workflow_files
    if (-not $suspiciousWorkflowFiles) {
        $suspiciousWorkflowFiles = @("shai-hulud.yaml", "shai-hulud-workflow.yml")
    }
    
    foreach ($file in $workflowFiles) {
        try {
            $content = Get-Content $file.FullName -Raw
            $fileName = Split-Path -Leaf $file.FullName
            $isSuspicious = $false
            $matchedPatterns = @()
            
            # Check filename
            foreach ($suspiciousName in $suspiciousWorkflowFiles) {
                if ($fileName -match $suspiciousName) {
                    $isSuspicious = $true
                    $matchedPatterns += "suspicious filename: $suspiciousName"
                }
            }
            
            # Check content patterns
            foreach ($pattern in $patterns) {
                if ($content -match $pattern) {
                    $isSuspicious = $true
                    $matchedPatterns += $pattern
                }
            }
            
            if ($isSuspicious) {
                $result = @{
                    File = $file.FullName
                    MatchedPatterns = $matchedPatterns
                }
                $scanResults.SuspiciousWorkflows += $result
                Write-Host "  [WARNING] Suspicious workflow found: $($file.FullName)" -ForegroundColor Red
                Write-Host "    Matched: $($matchedPatterns -join ', ')" -ForegroundColor Yellow
                $foundIOCs += "Suspicious workflow in $($file.FullName)"
                
                if ($Verbose) {
                    $lines = Get-Content $file.FullName
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        foreach ($pattern in $patterns) {
                            if ($lines[$i] -match $pattern) {
                                $start = [Math]::Max(0, $i - 2)
                                $end = [Math]::Min($lines.Count - 1, $i + 2)
                                Write-Host "    Context:" -ForegroundColor Gray
                                for ($j = $start; $j -le $end; $j++) {
                                    $marker = if ($j -eq $i) { ">>> " } else { "    " }
                                    Write-Host "    $marker$($lines[$j])" -ForegroundColor Gray
                                }
                                break
                            }
                        }
                    }
                }
            }
        }
        catch {
            if ($Verbose) {
                Write-Host "  [INFO] Error reading workflow file: $($file.FullName)" -ForegroundColor Gray
            }
        }
    }
    
    if ($workflowFiles.Count -eq 0) {
        Write-Host "  No GitHub workflow files found" -ForegroundColor Green
    } else {
        Write-Host "  Checked $($workflowFiles.Count) workflow file(s)" -ForegroundColor $(if ($scanResults.SuspiciousWorkflows.Count -gt 0) { "Yellow" } else { "Green" })
    }
    Write-Host ""
}

# Function to check file hashes
function Check-FileHashes {
    Write-Host "[4/5] Checking for known malicious file hashes..." -ForegroundColor Green
    
    $knownHashes = $iocs.patterns.known_hashes
    $knownHashesSha1 = $iocs.patterns.known_hashes_sha1
    
    # Support both old format (array of SHA256 strings) and new format (object with sha256/sha1 arrays)
    if ($knownHashes -is [System.Array] -and $knownHashes.Count -gt 0) {
        # Old format - convert to new structure
        $hashList = @()
        foreach ($hash in $knownHashes) {
            if ($hash -is [System.String]) {
                $hashList += @{ sha256 = $hash; filename = "bundle.js" }
            } elseif ($hash -is [System.Collections.Hashtable] -or $hash -is [PSCustomObject]) {
                $hashList += $hash
            }
        }
        $knownHashes = $hashList
    }
    
    if ($knownHashesSha1) {
        foreach ($hashEntry in $knownHashesSha1) {
            if ($hashEntry -is [System.Collections.Hashtable] -or $hashEntry -is [PSCustomObject]) {
                $knownHashes += $hashEntry
            } elseif ($hashEntry -is [System.String]) {
                # Assume it's a hash, try to infer filename from context
                $knownHashes += @{ sha1 = $hashEntry; filename = "" }
            }
        }
    }
    
    if (-not $knownHashes -or $knownHashes.Count -eq 0) {
        Write-Host "  No known hashes configured" -ForegroundColor Gray
        Write-Host ""
        return
    }
    
    if ($Verbose) {
        Write-Host "  Checking against $($knownHashes.Count) known hash(es)" -ForegroundColor Gray
    }
    
    # Files to check: bundle.js, bun_environment.js, setup_bun.js, and any specific filenames from hash config
    $targetFiles = @("bundle.js", "bun_environment.js", "setup_bun.js")
    $specificFilenames = $knownHashes | Where-Object { $_.filename } | ForEach-Object { $_.filename } | Select-Object -Unique
    $targetFiles += $specificFilenames | Where-Object { $_ -and $targetFiles -notcontains $_ }
    
    if ($Verbose) {
        Write-Host "  Target files to check: $($targetFiles -join ', ')" -ForegroundColor Gray
    }
    
    $totalFilesChecked = 0
    $filesToCheck = @()
    
    foreach ($targetFile in $targetFiles) {
        $foundFiles = Get-ChildItem -Path $projectRoot -Filter $targetFile -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.FullName -notmatch "node_modules[\\/]\.cache" }
        $filesToCheck += $foundFiles
    }
    
    $totalFilesChecked = $filesToCheck.Count
    
    if ($Verbose) {
        Write-Host "  Found $totalFilesChecked file(s) matching target filenames" -ForegroundColor Gray
    }
    
    foreach ($file in $filesToCheck) {
        if ($Verbose) {
            Write-Host "    Checking: $($file.FullName)" -ForegroundColor Gray
        }
        
        $fileHash256 = Get-FileHash256 -FilePath $file.FullName
        $fileHash1 = Get-FileHash1 -FilePath $file.FullName
        $fileName = $file.Name
        
        foreach ($hashEntry in $knownHashes) {
            $isMatch = $false
            $matchedHash = $null
            $hashType = $null
            
            # Check SHA256
            if ($hashEntry.sha256 -and $fileHash256 -and $fileHash256 -eq $hashEntry.sha256.ToLower()) {
                $isMatch = $true
                $matchedHash = $fileHash256
                $hashType = "SHA256"
            }
            # Check SHA1
            elseif ($hashEntry.sha1 -and $fileHash1 -and $fileHash1 -eq $hashEntry.sha1.ToLower()) {
                $isMatch = $true
                $matchedHash = $fileHash1
                $hashType = "SHA1"
            }
            # Support old format (just a hash string, assume SHA256)
            elseif ($hashEntry -is [System.String] -and $fileHash256 -and $fileHash256 -eq $hashEntry.ToLower()) {
                $isMatch = $true
                $matchedHash = $fileHash256
                $hashType = "SHA256"
            }
            
            # If filename is specified in hash entry, verify it matches
            if ($isMatch -and $hashEntry.filename) {
                if ($fileName -ne $hashEntry.filename) {
                    $isMatch = $false
                }
            }
            
            if ($isMatch) {
                $result = @{
                    File = $file.FullName
                    Hash = $matchedHash
                    HashType = $hashType
                    IsKnownMalicious = $true
                }
                $scanResults.FileHashes += $result
                Write-Host "  [WARNING] Known malicious file hash detected: $($file.FullName)" -ForegroundColor Red
                Write-Host "    Hash ($hashType): $matchedHash" -ForegroundColor Yellow
                if ($hashEntry.filename) {
                    Write-Host "    Expected filename: $($hashEntry.filename)" -ForegroundColor Yellow
                }
                $foundIOCs += "Known malicious hash ($hashType) in $($file.FullName)"
                break
            }
        }
    }
    
    Write-Host "  Checked $totalFilesChecked file(s)" -ForegroundColor $(if ($scanResults.FileHashes.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""
}

# Function to check for suspicious npm packages
function Check-SuspiciousPackages {
    Write-Host "[5/5] Checking for suspicious npm packages and bundle.js files..." -ForegroundColor Green
    
    $bundleJsFiles = Get-ChildItem -Path $projectRoot -Filter "bundle.js" -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.FullName -notmatch "node_modules[\\/]\.cache" }
    
    if ($Verbose) {
        Write-Host "  Scanning for bundle.js files..." -ForegroundColor Gray
    }
    
    foreach ($file in $bundleJsFiles) {
        $result = @{
            File = $file.FullName
            IsSuspicious = $true
        }
        $scanResults.SuspiciousPackages += $result
        
        $fileSize = (Get-Item $file.FullName).Length
        if ($fileSize -lt 1000) {
            Write-Host "  [WARNING] Small bundle.js file found: $($file.FullName) ($fileSize bytes)" -ForegroundColor Red
            $foundIOCs += "Suspicious bundle.js file: $($file.FullName)"
        } elseif ($Verbose) {
            Write-Host "  [INFO] bundle.js file found: $($file.FullName) ($fileSize bytes)" -ForegroundColor Gray
        }
    }
    
    $suspiciousPackagePatterns = $iocs.patterns.suspicious_packages
    if (-not $suspiciousPackagePatterns) {
        $suspiciousPackagePatterns = @("shai-hulud", "bundle", "postinstall")
    }
    
    if ($Verbose) {
        Write-Host "  Using suspicious package patterns: $($suspiciousPackagePatterns -join ', ')" -ForegroundColor Gray
    }
    
    # Check package.json files
    $packageJsonFiles = Get-ChildItem -Path $projectRoot -Filter "package.json" -Recurse -ErrorAction SilentlyContinue
    
    if ($Verbose) {
        Write-Host "  Found $($packageJsonFiles.Count) package.json file(s) to check" -ForegroundColor Gray
    }
    
    $totalPackagesChecked = 0
    $suspiciousPackagesFound = 0
    
    foreach ($file in $packageJsonFiles) {
        try {
            if ($Verbose) {
                Write-Host "    Checking: $($file.FullName)" -ForegroundColor Gray
            }
            
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
            
            $allDeps = @()
            if ($content.dependencies) { 
                $deps = $content.dependencies.PSObject.Properties.Name
                $allDeps += $deps
                if ($Verbose) {
                    Write-Host "      Found $($deps.Count) dependency(ies)" -ForegroundColor Gray
                }
            }
            if ($content.devDependencies) { 
                $devDeps = $content.devDependencies.PSObject.Properties.Name
                $allDeps += $devDeps
                if ($Verbose) {
                    Write-Host "      Found $($devDeps.Count) devDependency(ies)" -ForegroundColor Gray
                }
            }
            
            $totalPackagesChecked += $allDeps.Count
            
            foreach ($dep in $allDeps) {
                $isSuspicious = $false
                $matchReason = ""
                
                # Check against compromised packages list (exact match)
                if ($compromisedPackages -contains $dep) {
                    $isSuspicious = $true
                    $matchReason = "Known compromised package (from Wiz Research CSV)"
                    $suspiciousPackagesFound++
                    Write-Host "  [WARNING] Known compromised package found: $dep in $($file.FullName)" -ForegroundColor Red
                    Write-Host "    $matchReason" -ForegroundColor Yellow
                    $foundIOCs += "Known compromised package: $dep in $($file.FullName)"
                }
                # Check against pattern matching (if not already flagged)
                elseif ($dep -ne "postinstall") {
                    foreach ($pattern in $suspiciousPackagePatterns) {
                        if ($dep -match $pattern) {
                            $isSuspicious = $true
                            $matchReason = "Matched pattern: $pattern"
                            $suspiciousPackagesFound++
                            Write-Host "  [WARNING] Suspicious package name found: $dep in $($file.FullName)" -ForegroundColor Yellow
                            Write-Host "    $matchReason" -ForegroundColor Yellow
                            $foundIOCs += "Suspicious package: $dep in $($file.FullName)"
                            break
                        }
                    }
                }
            }
        }
        catch {
            if ($Verbose) {
                Write-Host "    [INFO] Could not parse package.json: $($file.FullName)" -ForegroundColor Gray
            }
        }
    }
    
    # Check package-lock.json files
    $packageLockFiles = Get-ChildItem -Path $projectRoot -Filter "package-lock.json" -Recurse -ErrorAction SilentlyContinue
    
    if ($Verbose) {
        Write-Host "  Found $($packageLockFiles.Count) package-lock.json file(s) to check" -ForegroundColor Gray
    }
    
    foreach ($file in $packageLockFiles) {
        try {
            if ($Verbose) {
                Write-Host "    Checking: $($file.FullName)" -ForegroundColor Gray
            }
            
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
            
            $lockPackages = @()
            if ($content.packages) {
                # package-lock.json v2+ format
                $lockPackages = $content.packages.PSObject.Properties.Name | Where-Object { $_ -ne "" }
            } elseif ($content.dependencies) {
                # package-lock.json v1 format
                function Get-PackageNames {
                    param($deps)
                    $names = @()
                    foreach ($dep in $deps.PSObject.Properties) {
                        $names += $dep.Name
                        if ($dep.Value.dependencies) {
                            $names += Get-PackageNames -deps $dep.Value.dependencies
                        }
                    }
                    return $names
                }
                $lockPackages = Get-PackageNames -deps $content.dependencies
            }
            
            if ($Verbose) {
                Write-Host "      Found $($lockPackages.Count) package(s) in lock file" -ForegroundColor Gray
            }
            
            $totalPackagesChecked += $lockPackages.Count
            
            foreach ($pkg in $lockPackages) {
                # Remove path prefix if present (e.g., "node_modules/package-name" -> "package-name")
                $pkgName = $pkg -replace '^node_modules/', '' -replace '^.*node_modules/', ''
                
                $isSuspicious = $false
                $matchReason = ""
                
                # Check against compromised packages list (exact match)
                if ($compromisedPackages -contains $pkgName) {
                    $isSuspicious = $true
                    $matchReason = "Known compromised package (from Wiz Research CSV)"
                    $suspiciousPackagesFound++
                    Write-Host "  [WARNING] Known compromised package found in lock file: $pkgName in $($file.FullName)" -ForegroundColor Red
                    Write-Host "    $matchReason" -ForegroundColor Yellow
                    $foundIOCs += "Known compromised package in lock file: $pkgName in $($file.FullName)"
                }
                # Check against pattern matching (if not already flagged)
                elseif ($pkgName -ne "postinstall") {
                    foreach ($pattern in $suspiciousPackagePatterns) {
                        if ($pkgName -match $pattern) {
                            $isSuspicious = $true
                            $matchReason = "Matched pattern: $pattern"
                            $suspiciousPackagesFound++
                            Write-Host "  [WARNING] Suspicious package name found in lock file: $pkgName in $($file.FullName)" -ForegroundColor Yellow
                            Write-Host "    $matchReason" -ForegroundColor Yellow
                            $foundIOCs += "Suspicious package in lock file: $pkgName in $($file.FullName)"
                            break
                        }
                    }
                }
            }
        }
        catch {
            if ($Verbose) {
                Write-Host "    [INFO] Could not parse package-lock.json: $($file.FullName)" -ForegroundColor Gray
            }
        }
    }
    
    if ($Verbose) {
        Write-Host "  Total packages checked: $totalPackagesChecked" -ForegroundColor Gray
        Write-Host "  Suspicious packages found: $suspiciousPackagesFound" -ForegroundColor $(if ($suspiciousPackagesFound -gt 0) { "Yellow" } else { "Green" })
    }
    
    if ($bundleJsFiles.Count -eq 0) {
        Write-Host "  No bundle.js files found" -ForegroundColor Green
    } else {
        Write-Host "  Found $($bundleJsFiles.Count) bundle.js file(s)" -ForegroundColor $(if ($scanResults.SuspiciousPackages.Count -gt 0) { "Yellow" } else { "Green" })
    }
    Write-Host ""
}

# Run all checks
Check-PostinstallScripts
Check-BundleJsInTarballs
Check-SuspiciousWorkflows
Check-FileHashes
Check-SuspiciousPackages

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scan Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$totalWarnings = $scanResults.PostinstallScripts | Where-Object { $_.IsSuspicious } | Measure-Object | Select-Object -ExpandProperty Count
$totalWarnings += $scanResults.BundleJsInTarballs.Count
$totalWarnings += $scanResults.SuspiciousWorkflows.Count
$totalWarnings += $scanResults.FileHashes.Count
$totalWarnings += ($scanResults.SuspiciousPackages | Where-Object { $_.IsSuspicious } | Measure-Object | Select-Object -ExpandProperty Count)

if ($totalWarnings -eq 0) {
    Write-Host "[OK] No Shai-Hulud IOCs detected" -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host "[WARNING] Found $totalWarnings potential IOC(s):" -ForegroundColor Red
    Write-Host ""
    
    foreach ($ioc in $foundIOCs) {
        Write-Host "  - $ioc" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Cyan
    Write-Host "  1. Review all flagged files manually" -ForegroundColor White
    Write-Host "  2. Check npm account for unauthorized package publications" -ForegroundColor White
    Write-Host "  3. Review GitHub Actions workflows for unauthorized changes" -ForegroundColor White
    Write-Host "  4. Rotate all potentially compromised credentials:" -ForegroundColor White
    Write-Host "     - npm tokens" -ForegroundColor White
    Write-Host "     - GitHub Personal Access Tokens" -ForegroundColor White
    Write-Host "     - API keys for cloud services" -ForegroundColor White
    Write-Host "  5. Check for unauthorized Shai-Hulud repositories on GitHub" -ForegroundColor White
    Write-Host ""
    exit 1
}
