#!/bin/bash

# Download Latest Shai-Hulud IOCs
# Fetches the latest IOC data from Wiz Research and other sources

set -euo pipefail

CONFIG_PATH="${1:-config.json}"
FORCE="${2:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/$CONFIG_PATH"
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

# JSON parsing helper functions (replacing jq)
json_get_value() {
    local json="$1"
    local key="$2"
    local default="${3:-}"
    local value=$(echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed "s/\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"/\1/" | head -1)
    if [ -z "$value" ]; then
        value=$(echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*[0-9]*" | sed "s/\"$key\"[[:space:]]*:[[:space:]]*\([0-9]*\)/\1/" | head -1)
    fi
    if [ -z "$value" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

json_get_object_value() {
    local obj="$1"
    local key="$2"
    local default="${3:-}"
    echo "$obj" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed "s/\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"/\1/" | head -1 || echo "$default"
}

json_extract_sources() {
    local json="$1"
    # Extract ioc_sources array objects where enabled=true
    echo "$json" | awk '
    BEGIN { in_sources=0; in_obj=0; brace_count=0; obj_lines="" }
    /"ioc_sources"[[:space:]]*:[[:space:]]*\[/ { in_sources=1; next }
    in_sources && /\{/ { 
        if (in_obj == 0) { in_obj=1; brace_count=1; obj_lines=$0; next }
        brace_count++; obj_lines=obj_lines "\n" $0; next
    }
    in_obj && /\}/ { 
        brace_count--; obj_lines=obj_lines "\n" $0
        if (brace_count == 0) {
            if (obj_lines ~ /"enabled"[[:space:]]*:[[:space:]]*true/) {
                print obj_lines
            }
            in_obj=0; obj_lines=""
        }
        next
    }
    in_obj { obj_lines=obj_lines "\n" $0; next }
    in_sources && /\]/ { in_sources=0; next }
    '
}

json_is_valid() {
    local json="$1"
    # Basic validation: check if it starts with { or [ and has balanced braces
    if echo "$json" | grep -qE '^[[:space:]]*[\{\[]'; then
        local open=$(echo "$json" | tr -cd '{[' | wc -c)
        local close=$(echo "$json" | tr -cd '}]' | wc -c)
        [ "$open" -eq "$close" ]
    else
        return 1
    fi
}

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
    CONFIG_CONTENT=$(cat "$CONFIG_FILE")
    UPDATE_INTERVAL_HOURS=$(json_get_value "$CONFIG_CONTENT" "update_interval_hours" "24")
    
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
ALL_IOCS=$(cat "$CONFIG_FILE")
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')
# Add sources array and metadata to the JSON
ALL_IOCS=$(echo "$ALL_IOCS" | sed 's/}$/,\n  "sources": [],\n  "last_updated": "'"$CURRENT_TIME"'",\n  "version": "1.0"\n}/')

SUCCESS_COUNT=0
FAIL_COUNT=0

# Get enabled sources - extract ioc_sources array and filter for enabled=true
CONFIG_CONTENT=$(cat "$CONFIG_FILE")
SOURCES=""
IFS=$'\n'
for source_obj in $(echo "$CONFIG_CONTENT" | awk '/"ioc_sources"[[:space:]]*:[[:space:]]*\[/,/\]/ { if (!/\[|\]/) print }' | awk '/\{/,/\}/ { print }'); do
    if echo "$source_obj" | grep -q '"enabled"[[:space:]]*:[[:space:]]*true'; then
        SOURCES="${SOURCES}${source_obj}"$'\n'
    fi
done

while IFS= read -r source; do
    SOURCE_NAME=$(echo "$source" | jq -r '.name')
    SOURCE_URL=$(echo "$source" | jq -r '.url')
    FALLBACK_URL=$(echo "$source" | jq -r '.fallback_url // empty')
    
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
