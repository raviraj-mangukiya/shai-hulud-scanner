#!/bin/bash

# Download Latest Shai-Hulud IOCs
# Fetches the latest IOC data from Wiz Research and other sources

set -euo pipefail

CONFIG_PATH="${1:-config.json}"
FORCE="${2:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Handle both absolute and relative paths for CONFIG_PATH
if [[ "$CONFIG_PATH" == /* ]]; then
    CONFIG_FILE="$CONFIG_PATH"
else
    CONFIG_FILE="$SCRIPT_DIR/$CONFIG_PATH"
fi
IOC_CACHE_DIR="$SCRIPT_DIR/ioc-cache"
IOC_CACHE_FILE="$IOC_CACHE_DIR/iocs.json"
LAST_UPDATE_FILE="$IOC_CACHE_DIR/last-update.txt"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Create cache directory if it doesn't exist
mkdir -p "$IOC_CACHE_DIR"

# Check if jq is available
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    echo ""
    echo "Installation options:"
    echo "  - Debian/Ubuntu: sudo apt-get install jq"
    echo "  - macOS: brew install jq"
    echo "  - Windows: Use the PowerShell script instead: download-iocs.ps1"
    echo ""
    echo "The bash script requires jq for JSON parsing. On Windows, PowerShell scripts"
    echo "are recommended as they don't require additional dependencies."
    exit 1
fi

# Check if curl or wget is available
if command -v curl >/dev/null 2>&1; then
    DOWNLOAD_CMD="curl -s -f -L --max-time 30"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOAD_CMD="wget -q -O- --timeout=30"
else
    echo -e "${RED}Error: curl or wget is required but not installed.${NC}"
    exit 1
fi

# Load configuration
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
    exit 1
fi

# Check if update is needed
NEEDS_UPDATE="$FORCE"
if [ "$NEEDS_UPDATE" != "true" ] && [ -f "$LAST_UPDATE_FILE" ]; then
    LAST_UPDATE=$(cat "$LAST_UPDATE_FILE")
    UPDATE_INTERVAL_HOURS=$(jq -r '.update_interval_hours // 24' "$CONFIG_FILE")
    
    if command -v date >/dev/null 2>&1; then
        LAST_UPDATE_EPOCH=$(date -d "$LAST_UPDATE" +%s 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$LAST_UPDATE" +%s 2>/dev/null || echo "0")
        CURRENT_EPOCH=$(date +%s)
        INTERVAL_SECONDS=$((UPDATE_INTERVAL_HOURS * 3600))
        
        if [ $((CURRENT_EPOCH - LAST_UPDATE_EPOCH)) -gt $INTERVAL_SECONDS ]; then
            NEEDS_UPDATE="true"
        fi
    fi
fi

if [ "$NEEDS_UPDATE" != "true" ] && [ -f "$IOC_CACHE_FILE" ]; then
    echo -e "${GREEN}IOC cache is up to date. Use 'true' as second argument to force update.${NC}"
    exit 0
fi

echo -e "${CYAN}Downloading latest Shai-Hulud IOCs...${NC}"
echo ""

# Initialize IOCs structure with local patterns
ALL_IOCS=$(jq '.' "$CONFIG_FILE")
ALL_IOCS=$(echo "$ALL_IOCS" | jq '. + {
    sources: [],
    last_updated: (now | strftime("%Y-%m-%d %H:%M:%S")),
    version: "1.0"
}')

SUCCESS_COUNT=0
FAIL_COUNT=0

# Get enabled sources
SOURCES=$(echo "$ALL_IOCS" | jq -c '.ioc_sources[] | select(.enabled == true)')

while IFS= read -r source; do
    # Skip empty lines
    if [ -z "$source" ]; then
        continue
    fi
    
    SOURCE_NAME=$(echo "$source" | jq -r '.name')
    SOURCE_URL=$(echo "$source" | jq -r '.url')
    FALLBACK_URL=$(echo "$source" | jq -r '.fallback_url // empty')
    
    # Skip if source name is empty or null
    if [ -z "$SOURCE_NAME" ] || [ "$SOURCE_NAME" = "null" ]; then
        continue
    fi
    
    echo -e "${YELLOW}Fetching from: $SOURCE_NAME${NC}"
    
    SUCCESS=false
    for url in "$SOURCE_URL" "$FALLBACK_URL"; do
        if [ -z "$url" ] || [ "$url" = "null" ]; then
            continue
        fi
        
        echo -e "  ${GRAY}Trying: $url${NC}"
        
        if REMOTE_IOCS=$($DOWNLOAD_CMD "$url" 2>/dev/null | jq '.' 2>/dev/null); then
            # Merge remote IOCs with local patterns
            if echo "$REMOTE_IOCS" | jq -e '.patterns' >/dev/null 2>&1; then
                # Merge patterns
                for pattern_type in $(echo "$REMOTE_IOCS" | jq -r '.patterns | keys[]'); do
                    REMOTE_PATTERNS=$(echo "$REMOTE_IOCS" | jq -c ".patterns.$pattern_type // []")
                    LOCAL_PATTERNS=$(echo "$ALL_IOCS" | jq -c ".ioc_patterns.$pattern_type // []")
                    
                    # Combine and deduplicate
                    COMBINED=$(echo "[$LOCAL_PATTERNS, $REMOTE_PATTERNS]" | jq -s 'add | unique')
                    ALL_IOCS=$(echo "$ALL_IOCS" | jq ".ioc_patterns.$pattern_type = $COMBINED")
                done
            fi
            
            # Add source info
            SOURCE_INFO=$(jq -n --arg name "$SOURCE_NAME" --arg url "$url" --arg fetched "$(date '+%Y-%m-%d %H:%M:%S')" '{
                name: $name,
                url: $url,
                fetched_at: $fetched
            }')
            ALL_IOCS=$(echo "$ALL_IOCS" | jq ".sources += [$SOURCE_INFO]")
            
            echo -e "  ${GREEN}✓ Successfully fetched from $SOURCE_NAME${NC}"
            SUCCESS=true
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            break
        else
            echo -e "  ${RED}✗ Failed${NC}"
        fi
    done
    
    if [ "$SUCCESS" != "true" ]; then
        echo -e "  ${RED}✗ Failed to fetch from $SOURCE_NAME${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done <<< "$SOURCES"

# If all sources failed, use local patterns from config
if [ $SUCCESS_COUNT -eq 0 ]; then
    echo ""
    echo -e "${YELLOW}Warning: Could not fetch remote IOCs. Using local patterns from config.${NC}"
    SOURCE_INFO=$(jq -n --arg fetched "$(date '+%Y-%m-%d %H:%M:%S')" '{
        name: "Local Config",
        url: "local",
        fetched_at: $fetched
    }')
    ALL_IOCS=$(echo "$ALL_IOCS" | jq ".sources += [$SOURCE_INFO]")
fi

# Save IOCs to cache
echo "$ALL_IOCS" | jq '.' > "$IOC_CACHE_FILE"
date '+%Y-%m-%d %H:%M:%S' > "$LAST_UPDATE_FILE"

echo ""
echo -e "${GREEN}IOC download complete!${NC}"
echo -e "  ${GREEN}Successfully fetched: $SUCCESS_COUNT source(s)${NC}"
if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "  ${YELLOW}Failed: $FAIL_COUNT source(s)${NC}"
fi
echo -e "  ${GRAY}Cache file: $IOC_CACHE_FILE${NC}"
echo ""
