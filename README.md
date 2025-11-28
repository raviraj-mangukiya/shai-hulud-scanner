# Shai-Hulud IOC Scanner

A comprehensive scanner for detecting Indicators of Compromise (IOCs) associated with the Shai-Hulud npm supply chain attack, based on research from Wiz Research.

## Features

- **Automatic IOC Updates**: Downloads the latest IOCs from Wiz Research before scanning
- **Comprehensive Checks**: Scans for multiple types of IOCs including:
  - Malicious `postinstall` scripts in `package.json` files
  - `bundle.js` files in npm tarballs (`.tgz`)
  - Suspicious GitHub Actions workflows
  - Known malicious file hashes
  - Suspicious npm package names
- **Cross-Platform**: Works on Windows (PowerShell) and Linux/Mac (Bash)
- **Configurable**: Customize IOC sources and patterns via `config.json`

## Installation

No installation required. Just ensure you have:
- **PowerShell** (Windows) or **Bash** (Linux/Mac)
- **jq** (optional, for better JSON parsing on Linux/Mac)
- **curl** or **wget** (for downloading IOCs)

## Usage

### Windows (PowerShell)

```powershell
# Navigate to the scanner directory
cd shai-hulud-scanner

# Run a scan (automatically downloads latest IOCs)
.\check-shai-hulud-iocs.ps1

# Scan a specific directory
.\check-shai-hulud-iocs.ps1 -ProjectPath "C:\path\to\project"

# Skip IOC download (use cached IOCs)
.\check-shai-hulud-iocs.ps1 -SkipDownload

# Verbose output
.\check-shai-hulud-iocs.ps1 -Verbose
```

### Linux/Mac (Bash)

```bash
# Navigate to the scanner directory
cd shai-hulud-scanner

# Make scripts executable (first time only)
chmod +x *.sh

# Run a scan (automatically downloads latest IOCs)
./check-shai-hulud-iocs.sh

# Scan a specific directory
./check-shai-hulud-iocs.sh /path/to/project

# Skip IOC download (use cached IOCs)
./check-shai-hulud-iocs.sh . false true

# Verbose output
./check-shai-hulud-iocs.sh . true
```

### Manual IOC Update

You can manually update IOCs without running a scan:

**PowerShell:**
```powershell
.\download-iocs.ps1
.\download-iocs.ps1 -Force  # Force update even if cache is recent
```

**Bash:**
```bash
./download-iocs.sh
./download-iocs.sh config.json true  # Force update
```

## Configuration

Edit `config.json` to customize:

- **IOC Sources**: Add or modify sources for downloading IOCs
- **Update Interval**: How often to check for new IOCs (default: 24 hours)
- **Patterns**: Customize detection patterns for:
  - `postinstall_patterns`: Patterns to detect in postinstall scripts
  - `suspicious_packages`: Package names to flag
  - `suspicious_workflow_patterns`: Patterns in GitHub workflows
  - `known_hashes`: SHA-256 hashes of known malicious files
  - `exfiltration_endpoints`: Suspicious network endpoints
  - `suspicious_repositories`: Repository names to watch for
  - `suspicious_workflow_files`: Workflow filenames to flag

## What Gets Checked

1. **Postinstall Scripts**: Scans all `package.json` files for malicious postinstall scripts
2. **Tarball Contents**: Checks `.tgz` files for `bundle.js` payloads
3. **GitHub Workflows**: Scans `.github/workflows/*.yml` for suspicious patterns
4. **File Hashes**: Compares `bundle.js` files against known malicious hashes
5. **Package Names**: Flags suspicious package names in dependencies

## Output

The scanner provides:
- Real-time progress updates during scanning
- Detailed warnings for each IOC found
- Summary report with total IOC count
- Recommended remediation actions

Exit codes:
- `0`: No IOCs detected
- `1`: IOCs detected (requires investigation)

## IOC Cache

IOCs are cached in `ioc-cache/iocs.json` to avoid unnecessary downloads. The cache is automatically updated:
- When the update interval expires (default: 24 hours)
- When using `-Force` flag on download script
- On first run

## Troubleshooting

### "No IOC data available"
- Run `download-iocs.ps1` or `download-iocs.sh` manually
- Check internet connectivity
- Verify `config.json` exists and is valid JSON

### "jq not found" (Linux/Mac)
- Install jq: `apt-get install jq` (Debian/Ubuntu) or `brew install jq` (macOS)
- The script will still work but with limited functionality

### "Cannot check tarball contents"
- Install `tar` (usually pre-installed on Linux/Mac)
- Or install `7zip` (Windows: `choco install 7zip`)

## References

- [Wiz Research: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- Based on research and IOCs from Wiz Security Research Team

## License

This scanner is provided as-is for security research and incident response purposes.
