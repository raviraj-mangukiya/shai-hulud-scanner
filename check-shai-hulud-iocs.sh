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
    
    local known_hashes
    if command -v jq >/dev/null 2>&1; then
        known_hashes=$(echo "$IOCS" | jq -r '.patterns.known_hashes[]? // empty')
    fi
    
    if [ -z "$known_hashes" ]; then
        echo -e "  ${GRAY}No known hashes configured${NC}"
        echo ""
        return
    fi
    
    local bundle_js_count=0
    local suspicious_count=0
    
    while IFS= read -r -d '' file; do
        bundle_js_count=$((bundle_js_count + 1))
        local file_hash=$(get_file_hash256 "$file")
        
        if [ -n "$file_hash" ]; then
            while IFS= read -r known_hash; do
                if [ -n "$known_hash" ] && [ "$file_hash" = "$known_hash" ]; then
                    suspicious_count=$((suspicious_count + 1))
                    echo -e "  ${RED}[WARNING] Known malicious file hash detected: $file${NC}"
                    echo -e "    ${YELLOW}Hash: $file_hash${NC}"
                    FOUND_IOCS+=("Known malicious hash in $file")
                    WARNINGS=$((WARNINGS + 1))
                    break
                fi
            done <<< "$known_hashes"
        fi
    done < <(find "$PROJECT_ROOT" -name "bundle.js" -type f ! -path "*/node_modules/.cache/*" -print0 2>/dev/null)
    
    echo -e "  Checked $bundle_js_count bundle.js file(s)" -ForegroundColor $(if [ $suspicious_count -gt 0 ]; then echo "$YELLOW"; else echo "$GREEN"; fi)
    echo ""
}

# Function to check for suspicious npm packages
check_suspicious_packages() {
    echo -e "${GREEN}[5/5] Checking for suspicious npm packages and bundle.js files...${NC}"
    
    local bundle_js_count=0
    local suspicious_count=0
    
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
    
    while IFS= read -r -d '' file; do
        if command -v jq >/dev/null 2>&1; then
            local deps=$(jq -r '.dependencies // {} | keys[]' "$file" 2>/dev/null)
            local dev_deps=$(jq -r '.devDependencies // {} | keys[]' "$file" 2>/dev/null)
            
            for dep in $deps $dev_deps; do
                if echo "$dep" | grep -qiE "($suspicious_package_patterns)" && [ "$dep" != "postinstall" ]; then
                    echo -e "  ${YELLOW}[WARNING] Suspicious package name found: $dep in $file${NC}"
                    FOUND_IOCS+=("Suspicious package: $dep in $file")
                    WARNINGS=$((WARNINGS + 1))
                fi
            done
        fi
    done < <(find "$PROJECT_ROOT" -name "package.json" -type f -print0 2>/dev/null)
    
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
