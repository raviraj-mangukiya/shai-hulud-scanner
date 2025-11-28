#!/bin/bash

# Shai-Hulud IOC Detection Script
# Based on Wiz Research findings
# This script downloads the latest IOCs and checks for Indicators of Compromise (IOCs)

set -euo pipefail

PROJECT_PATH="${1:-..}"
VERBOSE="${2:-false}"
SKIP_DOWNLOAD="${3:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
IOC_CACHE_FILE="$SCRIPT_DIR/ioc-cache/iocs.json"
DOWNLOAD_SCRIPT="$SCRIPT_DIR/download-iocs.sh"

FOUND_IOCS=()
WARNINGS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Download latest IOCs first
if [ "$SKIP_DOWNLOAD" != "true" ]; then
    echo -e "${CYAN}Updating IOCs...${NC}"
    bash "$DOWNLOAD_SCRIPT" "$CONFIG_FILE" false
    echo ""
fi

# Load IOCs from cache
IOCS=""
if [ -f "$IOC_CACHE_FILE" ]; then
    if command -v jq >/dev/null 2>&1; then
        IOCS=$(cat "$IOC_CACHE_FILE")
        LAST_UPDATED=$(echo "$IOCS" | jq -r '.last_updated // "unknown"')
        echo -e "${GREEN}Loaded IOCs from cache (last updated: $LAST_UPDATED)${NC}"
    else
        echo -e "${YELLOW}Warning: jq not available. Using default patterns.${NC}"
    fi
fi

# Fallback to config if cache is not available
if [ -z "$IOCS" ] && [ -f "$CONFIG_FILE" ]; then
    if command -v jq >/dev/null 2>&1; then
        IOCS=$(jq '{patterns: .ioc_patterns, last_updated: "local config"}' "$CONFIG_FILE")
        echo -e "${YELLOW}Using IOCs from local config${NC}"
    fi
fi

if [ -z "$IOCS" ]; then
    echo -e "${RED}Error: No IOC data available. Please run download-iocs.sh first.${NC}"
    exit 1
fi

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Shai-Hulud IOC Scanner${NC}"
echo -e "${CYAN}Based on Wiz Research${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

PROJECT_ROOT=$(cd "$PROJECT_PATH" && pwd)
echo -e "${YELLOW}Scanning project: $PROJECT_ROOT${NC}"
echo ""

# Load compromised packages list from CSV
COMPROMISED_PACKAGES_CACHE_FILE="$SCRIPT_DIR/ioc-cache/compromised-packages.json"
COMPROMISED_PACKAGES=()

if command -v jq >/dev/null 2>&1 && [ -f "$CONFIG_FILE" ]; then
    CSV_URL=$(jq -r '.compromised_packages_csv_url // empty' "$CONFIG_FILE")
    
    if [ -n "$CSV_URL" ]; then
        # Check if cache exists and is recent (within 24 hours)
        SHOULD_DOWNLOAD=true
        if [ -f "$COMPROMISED_PACKAGES_CACHE_FILE" ]; then
            CACHE_TIME=$(jq -r '.last_updated // empty' "$COMPROMISED_PACKAGES_CACHE_FILE")
            if [ -n "$CACHE_TIME" ]; then
                # Simple check: if cache file is less than 24 hours old
                if [ "$(find "$COMPROMISED_PACKAGES_CACHE_FILE" -mtime -1 2>/dev/null)" ]; then
                    SHOULD_DOWNLOAD=false
                    COMPROMISED_PACKAGES=($(jq -r '.packages[]?' "$COMPROMISED_PACKAGES_CACHE_FILE" 2>/dev/null))
                    if [ "$VERBOSE" = "true" ]; then
                        echo -e "  ${GRAY}Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages from cache${NC}"
                    fi
                fi
            fi
        fi
        
        if [ "$SHOULD_DOWNLOAD" = "true" ] && [ "$SKIP_DOWNLOAD" != "true" ]; then
            if [ "$VERBOSE" = "true" ]; then
                echo -e "  ${GRAY}Downloading compromised packages list...${NC}"
            fi
            
            if command -v curl >/dev/null 2>&1; then
                CSV_CONTENT=$(curl -s "$CSV_URL" 2>/dev/null)
            elif command -v wget >/dev/null 2>&1; then
                CSV_CONTENT=$(wget -qO- "$CSV_URL" 2>/dev/null)
            else
                CSV_CONTENT=""
            fi
            
            if [ -n "$CSV_CONTENT" ]; then
                while IFS= read -r line; do
                    if [ -n "$line" ] && ! echo "$line" | grep -q "^Package,"; then
                        PACKAGE_NAME=$(echo "$line" | cut -d',' -f1 | tr -d ' ' | tr -d '"')
                        if [ -n "$PACKAGE_NAME" ] && [ "$PACKAGE_NAME" != "Package" ]; then
                            COMPROMISED_PACKAGES+=("$PACKAGE_NAME")
                        fi
                    fi
                done <<< "$CSV_CONTENT"
                
                # Cache the results
                mkdir -p "$(dirname "$COMPROMISED_PACKAGES_CACHE_FILE")"
                jq -n \
                    --argjson packages "$(printf '%s\n' "${COMPROMISED_PACKAGES[@]}" | jq -R . | jq -s .)" \
                    --arg last_updated "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                    '{packages: $packages, last_updated: $last_updated}' \
                    > "$COMPROMISED_PACKAGES_CACHE_FILE" 2>/dev/null || {
                    # Fallback if jq fails
                    echo "{\"packages\":[$(printf '"%s",' "${COMPROMISED_PACKAGES[@]}" | sed 's/,$//')],\"last_updated\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" > "$COMPROMISED_PACKAGES_CACHE_FILE"
                }
                
                if [ "$VERBOSE" = "true" ]; then
                    echo -e "  ${GRAY}Downloaded and cached ${#COMPROMISED_PACKAGES[@]} compromised packages${NC}"
                fi
            else
                echo -e "  ${YELLOW}Warning: Could not download compromised packages list${NC}"
                # Try to load from cache as fallback
                if [ -f "$COMPROMISED_PACKAGES_CACHE_FILE" ]; then
                    COMPROMISED_PACKAGES=($(jq -r '.packages[]?' "$COMPROMISED_PACKAGES_CACHE_FILE" 2>/dev/null))
                    if [ ${#COMPROMISED_PACKAGES[@]} -gt 0 ]; then
                        echo -e "  ${YELLOW}Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages from cache (fallback)${NC}"
                    fi
                fi
            fi
        fi
    fi
fi

# Function to calculate SHA-256 hash
get_file_hash256() {
    local file_path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_path" 2>/dev/null | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" 2>/dev/null | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]'
    else
        echo ""
    fi
}

# Function to calculate SHA-1 hash
get_file_hash1() {
    local file_path="$1"
    if command -v sha1sum >/dev/null 2>&1; then
        sha1sum "$file_path" 2>/dev/null | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 1 "$file_path" 2>/dev/null | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]'
    else
        echo ""
    fi
}

# Function to check for postinstall scripts
check_postinstall_scripts() {
    echo -e "${GREEN}[1/5] Checking for malicious 'postinstall' scripts in package.json files...${NC}"
    
    local patterns
    if command -v jq >/dev/null 2>&1; then
        patterns=$(echo "$IOCS" | jq -r '.patterns.postinstall_patterns[]? // empty' | tr '\n' '|' | sed 's/|$//')
    fi
    
    if [ -z "$patterns" ]; then
        patterns="bundle\.js|toJSON\(secrets\)|eval\(|require\(.*process|child_process|exec\(|spawn\("
    fi
    
    local count=0
    local suspicious_count=0
    
    while IFS= read -r -d '' file; do
        count=$((count + 1))
        
        if command -v jq >/dev/null 2>&1; then
            if jq -e '.scripts.postinstall' "$file" >/dev/null 2>&1; then
                local postinstall_script=$(jq -r '.scripts.postinstall' "$file")
                
                if echo "$postinstall_script" | grep -qE "($patterns)"; then
                    suspicious_count=$((suspicious_count + 1))
                    echo -e "  ${RED}[WARNING] Suspicious postinstall script found in: $file${NC}"
                    echo -e "    ${YELLOW}Script: $postinstall_script${NC}"
                    FOUND_IOCS+=("Suspicious postinstall script in $file")
                    WARNINGS=$((WARNINGS + 1))
                elif [ "$VERBOSE" = "true" ]; then
                    echo -e "  ${GRAY}[INFO] Postinstall script found in: $file${NC}"
                    echo -e "    ${GRAY}Script: $postinstall_script${NC}"
                fi
            fi
        fi
    done < <(find "$PROJECT_ROOT" -name "package.json" -type f -print0 2>/dev/null)
    
    if [ $count -eq 0 ]; then
        echo -e "  ${GREEN}No package.json files found${NC}"
    else
        if [ $suspicious_count -eq 0 ]; then
            echo -e "  ${GREEN}Found $count package.json file(s), none with suspicious postinstall scripts${NC}"
        else
            echo -e "  ${YELLOW}Found $count package.json file(s), $suspicious_count with suspicious postinstall scripts${NC}"
        fi
    fi
    echo ""
}

# Function to check for bundle.js in tarballs
check_bundle_js_in_tarballs() {
    echo -e "${GREEN}[2/5] Checking for 'bundle.js' in npm tarball files (.tgz)...${NC}"
    
    local tarball_count=0
    local suspicious_count=0
    
    while IFS= read -r -d '' tarball; do
        tarball_count=$((tarball_count + 1))
        
        if tar -tf "$tarball" 2>/dev/null | grep -q "bundle\.js"; then
            suspicious_count=$((suspicious_count + 1))
            echo -e "  ${RED}[WARNING] Found bundle.js in tarball: $tarball${NC}"
            FOUND_IOCS+=("bundle.js found in tarball $tarball")
            WARNINGS=$((WARNINGS + 1))
        fi
    done < <(find "$PROJECT_ROOT" -name "*.tgz" -type f -print0 2>/dev/null)
    
    if [ $tarball_count -eq 0 ]; then
        echo -e "  ${GREEN}No .tgz files found${NC}"
    else
        if [ $suspicious_count -eq 0 ]; then
            echo -e "  ${GREEN}Checked $tarball_count tarball file(s), none contain bundle.js${NC}"
        else
            echo -e "  ${YELLOW}Checked $tarball_count tarball file(s), $suspicious_count contain bundle.js${NC}"
        fi
    fi
    echo ""
}

# Function to check for suspicious GitHub workflows
check_suspicious_workflows() {
    echo -e "${GREEN}[3/5] Checking for suspicious GitHub workflows...${NC}"
    
    local patterns
    local suspicious_workflow_files
    if command -v jq >/dev/null 2>&1; then
        patterns=$(echo "$IOCS" | jq -r '.patterns.suspicious_workflow_patterns[]? // empty' | tr '\n' '|' | sed 's/|$//')
        suspicious_workflow_files=$(echo "$IOCS" | jq -r '.patterns.suspicious_workflow_files[]? // empty')
    fi
    
    if [ -z "$patterns" ]; then
        patterns="toJSON\(secrets\)|shai-hulud|shai-hulud-workflow"
    fi
    
    if [ -z "$suspicious_workflow_files" ]; then
        suspicious_workflow_files="shai-hulud.yaml
shai-hulud-workflow.yml"
    fi
    
    local workflow_count=0
    local suspicious_count=0
    
    if [ -d "$PROJECT_ROOT/.github/workflows" ] || [ -d "$PROJECT_ROOT/.github" ]; then
        while IFS= read -r -d '' file; do
            workflow_count=$((workflow_count + 1))
            local is_suspicious=false
            local matched_patterns=()
            local file_name=$(basename "$file")
            
            # Check filename
            while IFS= read -r suspicious_name; do
                if [ -n "$suspicious_name" ] && echo "$file_name" | grep -qi "$suspicious_name"; then
                    is_suspicious=true
                    matched_patterns+=("suspicious filename: $suspicious_name")
                fi
            done <<< "$suspicious_workflow_files"
            
            # Check content patterns
            if grep -qE "($patterns)" "$file"; then
                is_suspicious=true
                matched_patterns+=($(grep -oE "($patterns)" "$file" | head -1))
            fi
            
            if [ "$is_suspicious" = "true" ]; then
                suspicious_count=$((suspicious_count + 1))
                echo -e "  ${RED}[WARNING] Suspicious workflow found: $file${NC}"
                echo -e "    ${YELLOW}Matched: $(IFS=', '; echo "${matched_patterns[*]}")${NC}"
                FOUND_IOCS+=("Suspicious workflow in $file")
                WARNINGS=$((WARNINGS + 1))
            fi
        done < <(find "$PROJECT_ROOT/.github" -name "*.yml" -o -name "*.yaml" 2>/dev/null | tr '\n' '\0')
    fi
    
    if [ $workflow_count -eq 0 ]; then
        echo -e "  ${GREEN}No GitHub workflow files found${NC}"
    else
        if [ $suspicious_count -eq 0 ]; then
            echo -e "  ${GREEN}Checked $workflow_count workflow file(s), none suspicious${NC}"
        else
            echo -e "  ${YELLOW}Checked $workflow_count workflow file(s), $suspicious_count suspicious${NC}"
        fi
    fi
    echo ""
}

# Function to check file hashes
check_file_hashes() {
    echo -e "${GREEN}[4/5] Checking for known malicious file hashes...${NC}"
    
    local known_hashes=""
    local known_hashes_sha1=""
    
    if command -v jq >/dev/null 2>&1; then
        known_hashes=$(echo "$IOCS" | jq -c '.patterns.known_hashes[]? // empty' 2>/dev/null)
        known_hashes_sha1=$(echo "$IOCS" | jq -c '.patterns.known_hashes_sha1[]? // empty' 2>/dev/null)
    fi
    
    if [ -z "$known_hashes" ] && [ -z "$known_hashes_sha1" ]; then
        echo -e "  ${GRAY}No known hashes configured${NC}"
        echo ""
        return
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        local hash_count=0
        if [ -n "$known_hashes" ]; then
            hash_count=$(echo "$known_hashes" | wc -l | tr -d ' ')
        fi
        if [ -n "$known_hashes_sha1" ]; then
            local sha1_count=$(echo "$known_hashes_sha1" | wc -l | tr -d ' ')
            hash_count=$((hash_count + sha1_count))
        fi
        echo -e "  ${GRAY}Checking against $hash_count known hash(es)${NC}"
    fi
    
    # Files to check: bundle.js, bun_environment.js, setup_bun.js, and any specific filenames from hash config
    local target_files=("bundle.js" "bun_environment.js" "setup_bun.js")
    
    if command -v jq >/dev/null 2>&1; then
        # Extract unique filenames from hash configs
        local specific_files=$(echo "$IOCS" | jq -r '.patterns.known_hashes[]?.filename // empty, .patterns.known_hashes_sha1[]?.filename // empty' 2>/dev/null | sort -u)
        while IFS= read -r filename; do
            if [ -n "$filename" ]; then
                # Check if filename is already in target_files
                local found=0
                for target in "${target_files[@]}"; do
                    if [ "$target" = "$filename" ]; then
                        found=1
                        break
                    fi
                done
                if [ $found -eq 0 ]; then
                    target_files+=("$filename")
                fi
            fi
        done <<< "$specific_files"
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        echo -e "  ${GRAY}Target files to check: $(IFS=', '; echo "${target_files[*]}")${NC}"
    fi
    
    local total_files_checked=0
    local suspicious_count=0
    
    for target_file in "${target_files[@]}"; do
        while IFS= read -r -d '' file; do
            total_files_checked=$((total_files_checked + 1))
            
            if [ "$VERBOSE" = "true" ]; then
                echo -e "    ${GRAY}Checking: $file${NC}"
            fi
            
            local file_hash256=$(get_file_hash256 "$file")
            local file_hash1=$(get_file_hash1 "$file")
            local file_name=$(basename "$file")
            local is_match=false
            local matched_hash=""
            local hash_type=""
            
            # Check SHA256 hashes
            if [ -n "$known_hashes" ] && [ -n "$file_hash256" ]; then
                while IFS= read -r hash_entry; do
                    if [ -z "$hash_entry" ]; then
                        continue
                    fi
                    
                    local hash_sha256=$(echo "$hash_entry" | jq -r '.sha256 // empty' 2>/dev/null)
                    local hash_filename=$(echo "$hash_entry" | jq -r '.filename // empty' 2>/dev/null)
                    
                    # If it's a plain string (old format), use it as SHA256
                    if [ -z "$hash_sha256" ] && echo "$hash_entry" | grep -qE '^[0-9a-f]{64}$'; then
                        hash_sha256="$hash_entry"
                    fi
                    
                    if [ -n "$hash_sha256" ] && [ "$file_hash256" = "$(echo "$hash_sha256" | tr '[:upper:]' '[:lower:]')" ]; then
                        # If filename is specified, verify it matches
                        if [ -z "$hash_filename" ] || [ "$file_name" = "$hash_filename" ]; then
                            is_match=true
                            matched_hash="$file_hash256"
                            hash_type="SHA256"
                            break
                        fi
                    fi
                done <<< "$known_hashes"
            fi
            
            # Check SHA1 hashes
            if [ "$is_match" = "false" ] && [ -n "$known_hashes_sha1" ] && [ -n "$file_hash1" ]; then
                while IFS= read -r hash_entry; do
                    if [ -z "$hash_entry" ]; then
                        continue
                    fi
                    
                    local hash_sha1=$(echo "$hash_entry" | jq -r '.sha1 // empty' 2>/dev/null)
                    local hash_filename=$(echo "$hash_entry" | jq -r '.filename // empty' 2>/dev/null)
                    
                    if [ -n "$hash_sha1" ] && [ "$file_hash1" = "$(echo "$hash_sha1" | tr '[:upper:]' '[:lower:]')" ]; then
                        # If filename is specified, verify it matches
                        if [ -z "$hash_filename" ] || [ "$file_name" = "$hash_filename" ]; then
                            is_match=true
                            matched_hash="$file_hash1"
                            hash_type="SHA1"
                            break
                        fi
                    fi
                done <<< "$known_hashes_sha1"
            fi
            
            if [ "$is_match" = "true" ]; then
                suspicious_count=$((suspicious_count + 1))
                echo -e "  ${RED}[WARNING] Known malicious file hash detected: $file${NC}"
                echo -e "    ${YELLOW}Hash ($hash_type): $matched_hash${NC}"
                FOUND_IOCS+=("Known malicious hash ($hash_type) in $file")
                WARNINGS=$((WARNINGS + 1))
            fi
        done < <(find "$PROJECT_ROOT" -name "$target_file" -type f ! -path "*/node_modules/.cache/*" -print0 2>/dev/null)
    done
    
    local color="$GREEN"
    if [ $suspicious_count -gt 0 ]; then
        color="$YELLOW"
    fi
    echo -e "  Checked $total_files_checked file(s)" -ForegroundColor "$color"
    echo ""
}

# Function to check for suspicious npm packages
check_suspicious_packages() {
    echo -e "${GREEN}[5/5] Checking for suspicious npm packages and bundle.js files...${NC}"
    
    local bundle_js_count=0
    local suspicious_count=0
    
    if [ "$VERBOSE" = "true" ]; then
        echo -e "  ${GRAY}Scanning for bundle.js files...${NC}"
    fi
    
    while IFS= read -r -d '' file; do
        bundle_js_count=$((bundle_js_count + 1))
        local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        
        if [ "$file_size" -lt 1000 ]; then
            suspicious_count=$((suspicious_count + 1))
            echo -e "  ${RED}[WARNING] Small bundle.js file found: $file ($file_size bytes)${NC}"
            FOUND_IOCS+=("Suspicious bundle.js file: $file")
            WARNINGS=$((WARNINGS + 1))
        elif [ "$VERBOSE" = "true" ]; then
            echo -e "  ${GRAY}[INFO] bundle.js file found: $file ($file_size bytes)${NC}"
        fi
    done < <(find "$PROJECT_ROOT" -name "bundle.js" -type f ! -path "*/node_modules/.cache/*" -print0 2>/dev/null)
    
    local suspicious_package_patterns
    if command -v jq >/dev/null 2>&1; then
        suspicious_package_patterns=$(echo "$IOCS" | jq -r '.patterns.suspicious_packages[]? // empty' | tr '\n' '|' | sed 's/|$//')
    fi
    
    if [ -z "$suspicious_package_patterns" ]; then
        suspicious_package_patterns="shai-hulud|bundle|postinstall"
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        echo -e "  ${GRAY}Using suspicious package patterns: $(echo "$suspicious_package_patterns" | tr '|' ', ')${NC}"
    fi
    
    # Check package.json files
    local package_json_count=0
    local total_packages_checked=0
    local suspicious_packages_found=0
    
    while IFS= read -r -d '' file; do
        package_json_count=$((package_json_count + 1))
        
        if [ "$VERBOSE" = "true" ]; then
            echo -e "  ${GRAY}Checking: $file${NC}"
        fi
        
        if command -v jq >/dev/null 2>&1; then
            local deps=$(jq -r '.dependencies // {} | keys[]' "$file" 2>/dev/null)
            local dev_deps=$(jq -r '.devDependencies // {} | keys[]' "$file" 2>/dev/null)
            
            local deps_count=0
            local dev_deps_count=0
            
            for dep in $deps; do
                deps_count=$((deps_count + 1))
            done
            
            for dep in $dev_deps; do
                dev_deps_count=$((dev_deps_count + 1))
            done
            
            if [ "$VERBOSE" = "true" ]; then
                echo -e "    ${GRAY}Found $deps_count dependency(ies), $dev_deps_count devDependency(ies)${NC}"
            fi
            
            total_packages_checked=$((total_packages_checked + deps_count + dev_deps_count))
            
            for dep in $deps $dev_deps; do
                local is_suspicious=false
                local match_reason=""
                
                # Check against compromised packages list (exact match)
                for compromised_pkg in "${COMPROMISED_PACKAGES[@]}"; do
                    if [ "$dep" = "$compromised_pkg" ]; then
                        is_suspicious=true
                        match_reason="Known compromised package (from Wiz Research CSV)"
                        suspicious_packages_found=$((suspicious_packages_found + 1))
                        echo -e "  ${RED}[WARNING] Known compromised package found: $dep in $file${NC}"
                        echo -e "    ${YELLOW}$match_reason${NC}"
                        FOUND_IOCS+=("Known compromised package: $dep in $file")
                        WARNINGS=$((WARNINGS + 1))
                        break
                    fi
                done
                
                # Check against pattern matching (if not already flagged)
                if [ "$is_suspicious" = "false" ] && [ "$dep" != "postinstall" ]; then
                    if echo "$dep" | grep -qiE "($suspicious_package_patterns)"; then
                        is_suspicious=true
                        local matched_pattern=$(echo "$dep" | grep -oiE "($suspicious_package_patterns)" | head -1)
                        match_reason="Matched pattern: $matched_pattern"
                        suspicious_packages_found=$((suspicious_packages_found + 1))
                        echo -e "  ${YELLOW}[WARNING] Suspicious package name found: $dep in $file${NC}"
                        echo -e "    ${YELLOW}$match_reason${NC}"
                        FOUND_IOCS+=("Suspicious package: $dep in $file")
                        WARNINGS=$((WARNINGS + 1))
                    fi
                fi
            done
        fi
    done < <(find "$PROJECT_ROOT" -name "package.json" -type f -print0 2>/dev/null)
    
    if [ "$VERBOSE" = "true" ]; then
        echo -e "  ${GRAY}Found $package_json_count package.json file(s) to check${NC}"
    fi
    
    # Check package-lock.json files
    local package_lock_count=0
    
    while IFS= read -r -d '' file; do
        package_lock_count=$((package_lock_count + 1))
        
        if [ "$VERBOSE" = "true" ]; then
            echo -e "  ${GRAY}Checking: $file${NC}"
        fi
        
        if command -v jq >/dev/null 2>&1; then
            # Try package-lock.json v2+ format first (packages field)
            local lock_packages=$(jq -r '.packages // {} | keys[] | select(. != "")' "$file" 2>/dev/null)
            
            # If no packages field, try v1 format (dependencies)
            if [ -z "$lock_packages" ]; then
                # Extract all package names from nested dependencies structure
                lock_packages=$(jq -r '.dependencies // {} | keys[]' "$file" 2>/dev/null)
                # Also get nested dependencies recursively
                local nested_deps=$(jq -r '.dependencies[]?.dependencies // {} | keys[]?' "$file" 2>/dev/null)
                lock_packages=$(printf "%s\n%s" "$lock_packages" "$nested_deps" | sort -u)
            fi
            
            local lock_packages_count=0
            for pkg in $lock_packages; do
                lock_packages_count=$((lock_packages_count + 1))
            done
            
            if [ "$VERBOSE" = "true" ]; then
                echo -e "    ${GRAY}Found $lock_packages_count package(s) in lock file${NC}"
            fi
            
            total_packages_checked=$((total_packages_checked + lock_packages_count))
            
            for pkg in $lock_packages; do
                # Remove path prefix if present (e.g., "node_modules/package-name" -> "package-name")
                local pkg_name=$(echo "$pkg" | sed 's|^node_modules/||' | sed 's|.*node_modules/||')
                
                local is_suspicious=false
                local match_reason=""
                
                # Check against compromised packages list (exact match)
                for compromised_pkg in "${COMPROMISED_PACKAGES[@]}"; do
                    if [ "$pkg_name" = "$compromised_pkg" ]; then
                        is_suspicious=true
                        match_reason="Known compromised package (from Wiz Research CSV)"
                        suspicious_packages_found=$((suspicious_packages_found + 1))
                        echo -e "  ${RED}[WARNING] Known compromised package found in lock file: $pkg_name in $file${NC}"
                        echo -e "    ${YELLOW}$match_reason${NC}"
                        FOUND_IOCS+=("Known compromised package in lock file: $pkg_name in $file")
                        WARNINGS=$((WARNINGS + 1))
                        break
                    fi
                done
                
                # Check against pattern matching (if not already flagged)
                if [ "$is_suspicious" = "false" ] && [ "$pkg_name" != "postinstall" ]; then
                    if echo "$pkg_name" | grep -qiE "($suspicious_package_patterns)"; then
                        is_suspicious=true
                        local matched_pattern=$(echo "$pkg_name" | grep -oiE "($suspicious_package_patterns)" | head -1)
                        match_reason="Matched pattern: $matched_pattern"
                        suspicious_packages_found=$((suspicious_packages_found + 1))
                        echo -e "  ${YELLOW}[WARNING] Suspicious package name found in lock file: $pkg_name in $file${NC}"
                        echo -e "    ${YELLOW}$match_reason${NC}"
                        FOUND_IOCS+=("Suspicious package in lock file: $pkg_name in $file")
                        WARNINGS=$((WARNINGS + 1))
                    fi
                fi
            done
        fi
    done < <(find "$PROJECT_ROOT" -name "package-lock.json" -type f -print0 2>/dev/null)
    
    if [ "$VERBOSE" = "true" ]; then
        echo -e "  ${GRAY}Found $package_lock_count package-lock.json file(s) to check${NC}"
        echo -e "  ${GRAY}Total packages checked: $total_packages_checked${NC}"
        echo -e "  ${GRAY}Suspicious packages found: $suspicious_packages_found${NC}"
    fi
    
    if [ $bundle_js_count -eq 0 ]; then
        echo -e "  ${GREEN}No bundle.js files found${NC}"
    else
        if [ $suspicious_count -eq 0 ]; then
            echo -e "  ${GREEN}Found $bundle_js_count bundle.js file(s), none suspicious${NC}"
        else
            echo -e "  ${YELLOW}Found $bundle_js_count bundle.js file(s), $suspicious_count suspicious${NC}"
        fi
    fi
    echo ""
}

# Run all checks
check_postinstall_scripts
check_bundle_js_in_tarballs
check_suspicious_workflows
check_file_hashes
check_suspicious_packages

# Summary
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Scan Summary${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

if [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ No Shai-Hulud IOCs detected${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}⚠ Found $WARNINGS potential IOC(s):${NC}"
    echo ""
    
    for ioc in "${FOUND_IOCS[@]}"; do
        echo -e "  ${YELLOW}- $ioc${NC}"
    done
    
    echo ""
    echo -e "${CYAN}RECOMMENDED ACTIONS:${NC}"
    echo -e "  ${NC}1. Review all flagged files manually"
    echo -e "  ${NC}2. Check npm account for unauthorized package publications"
    echo -e "  ${NC}3. Review GitHub Actions workflows for unauthorized changes"
    echo -e "  ${NC}4. Rotate all potentially compromised credentials:"
    echo -e "     ${NC}- npm tokens"
    echo -e "     ${NC}- GitHub Personal Access Tokens"
    echo -e "     ${NC}- API keys for cloud services"
    echo -e "  ${NC}5. Check for unauthorized 'Shai-Hulud' repositories on GitHub"
    echo ""
    exit 1
fi
